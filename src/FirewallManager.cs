using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
using NetTools;
using Newtonsoft.Json;
using PPMV4.Agent.Logging;
using PPMV4.Agent.ServerHandler;
using PPMV4.Agent.Structures;

namespace PPMV4.Agent.Firewall;

public class FirewallManager {
    private static FirewallManager? Instance;
    Dictionary<string, Server> Servers;
    private const string MasterUrl = "https://agent.api.purplemaze.net";
    public const int AgentPort = 6950;

    private FirewallManager(Dictionary<string, Server> servers){
        Servers = servers;
    }

    /// <summary>
    ///  Executes a command and captures its output
    /// </summary>
    /// <param name="command">Command to execute</param>
    /// <param name="arguments">Command arguments</param>
    /// <returns>Tuple containing success status and command output if successful</returns>
    private static (bool success, string? output) ExecuteCommand(string command, string arguments) {
        try {
            using var process = new Process {
                StartInfo = new ProcessStartInfo {
                    FileName = command,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                }
            };
            
            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            
            if (process.ExitCode != 0) {
                string error = process.StandardError.ReadToEnd();
                new Log($"Command failed: {command} {arguments}. Error: {error}", LogLevel.Error);
                return (false, null);
            }
            
            return (true, output);
        }
        catch (Exception ex) {
            new Log($"Failed to execute command {command} {arguments}: {ex.Message}", LogLevel.Error);
            return (false, null);
        }
    }

    /// <summary>
    ///  Called at startup. Will call the good linux/windows method to create the base rules / check if it can operate.
    /// </summary>
    public static bool InitFirewall(){
#if WINDOWS
        return InitFirewallWindows();
#elif LINUX
        return InitFirewallLinux();
#endif
        return false;
    }

    /// <summary>
    ///  Init the firewall for Windows.
    /// </summary>
    private static bool InitFirewallWindows() {
#pragma warning disable CA1416
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) {
            new Log("You need to be admin to use the Windows Firewall. Please re-run this software with the appropriate permissions.", LogLevel.Error);
            return false;
        }
#pragma warning restore CA1416

        // Init purge old rules
        ExecuteCommand("netsh", "advfirewall firewall delete rule name=\"PPMV4\"");
        return true;
    }

    /// <summary>
    ///  Init the firewall for Linux.
    /// </summary>
    private static bool InitFirewallLinux() {
        if (!ExecuteCommand("which", "iptables").success) {
            new Log("iptables is required on linux, but not installed. Please install it and try again.", LogLevel.Error);
            return false;
        }

        var (success, output) = ExecuteCommand("whoami", "");
        if (!success || output?.Trim() != "root") {
            new Log("You need to be root to use iptables. Please re-run this software with the appropriate permissions.", LogLevel.Error);
            return false;
        }

        // Check if the chain exists
        if (!ExecuteCommand("iptables", "-L PPMV4").success) {
            new Log("Chain PPMV4 not found. Creating it.", LogLevel.Info);
            if (!ExecuteCommand("iptables", "-N PPMV4").success) {
                new Log("Failed to create chain PPMV4. Exiting.", LogLevel.Error);
                return false;
            }
        }

        // Flush chain
        if (!ExecuteCommand("iptables", "-F PPMV4").success) {
            new Log("Failed to flush chain PPMV4. Exiting.", LogLevel.Error);
            return false;
        }

        // Insert ppmv4 chain at the begenning of the INPUT chain
        if (!ExecuteCommand("iptables", "-I INPUT -j PPMV4").success) {
            new Log("Failed to integrate PPMV4 chain into INPUT chain. Exiting.", LogLevel.Error);
            return false;
        }

        new Log("Successfully initialized iptables firewall with PPMV4 chain.", LogLevel.Info);
        return true;
    }

    /// <summary>
    ///  Block traffic for a server
    /// </summary>
    /// <param name="server"></param>
    /// <returns></returns>
    private bool DefaultBlockForServer(Server server){
#if WINDOWS
        return DefaultBlockForServerWindows(server.Port);
#elif LINUX
        return DefaultBlockForServerLinux(server.Port);
#endif
        return false;
    }

    /// <summary>
    ///  Block traffic for a server (Linux)
    /// </summary>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool DefaultBlockForServerLinux(ushort port){
        if (!ExecuteCommand("iptables", $"-A PPMV4 -p tcp --dport {port} -j DROP").success) {
            new Log($"Failed to add block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        if (!ExecuteCommand("iptables", $"-A PPMV4 -p udp --dport {port} -j DROP").success) {
            new Log($"Failed to add block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    ///  Block traffic for a server (Windows)
    /// </summary>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool DefaultBlockForServerWindows(ushort port){
        // tcp
        if (!ExecuteCommand("netsh", $"advfirewall firewall add rule name=\"PPMV4-Block-TCP-{port}\" dir=in action=block protocol=TCP localport={port}").success) {
            new Log($"Failed to add TCP block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // udp
        if (!ExecuteCommand("netsh", $"advfirewall firewall add rule name=\"PPMV4-Block-UDP-{port}\" dir=in action=block protocol=UDP localport={port}").success) {
            new Log($"Failed to add UDP block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        new Log($"Successfully added blocking rules for port {port}", LogLevel.Info);
        return true;
    }

    /// <summary>
    ///  Get an HttpClient bound to a specific IP address.
    /// </summary>
    /// <param name="address"></param>
    /// <returns></returns>
    public static HttpClient GetHttpClient(IPAddress address) {
        if (IPAddress.Any.Equals(address))
            return new HttpClient();

        SocketsHttpHandler handler = new SocketsHttpHandler();

        handler.ConnectCallback = async (context, cancellationToken) => {
            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Bind(new IPEndPoint(address, 0));
            socket.NoDelay = true;

            try {
                await socket.ConnectAsync(context.DnsEndPoint, cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, true);
            }
            catch {
                socket.Dispose();
                throw;
            }
        };

        return new HttpClient(handler);
    }

    /// <summary>
    ///  Initialize the whitelist: Fetch the IPs for each server, then add them to the firewall.
    /// </summary>
    public bool InitWhitelist(){
        new Log("Initializing whitelist", LogLevel.Info);
        bool systemDone = false;

        foreach (var server in Servers){
            if(!DefaultBlockForServer(server.Value)){
                new Log($"Failed to block traffic for server {server.Key}. Exiting.", LogLevel.Error);
                return false;
            }

            using (var httpClient = GetHttpClient(server.Value.IP)) {
                var response = httpClient.GetAsync($"{MasterUrl}/ranges/{server.Value.Slug}").GetAwaiter().GetResult();
                if (response.IsSuccessStatusCode) {
                    var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    try{
                        ApiResponse<InitialRequestData>? data = JsonConvert.DeserializeObject<ApiResponse<InitialRequestData>>(content);
                        if (data is null || data.Data is null) {
                            new Log($"Failed to deserialize IP ranges for server {server.Key}", LogLevel.Error);
                            return false;
                        }

                        if(!systemDone){
                            foreach (var range in data.Data.InfraRanges) {
                                Add(range, AgentPort, true);
                            }
                            systemDone = true;
                        }

                        foreach (var range in data.Data.ProxiesRanges) {
                            Add(range, server.Value.Port);
                        }
                    }
                    catch(Exception e){
                        new Log($"Error while getting initial ranges. HTTP response: {content}\n{e.Message}", LogLevel.Error);
                    }
                }
                else
                {
                    new Log($"Failed to fetch IP ranges for server {server.Key}. Status code: {response.StatusCode}", LogLevel.Error);
                }
            }
        }
        
        return true;
    }

    /// <summary>
    ///  Add a firewall rule for the range on the port.
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    public static bool Add(string range, ushort port, bool infra = false){
        if(!IPAddressRange.TryParse(range, out _)){
            new Log($"Invalid range: {range}", LogLevel.Warning);
            return false;
        }

#if WINDOWS
        return AddOnWindows(range, port, infra);
#elif LINUX
        return AddOnLinux(range, port, infra);
#endif
        return false;
    }

    /// <summary>
    ///  Remove the firewall rule for the range on the port.
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    public static bool Remove(string range, ushort port, bool infra = false){
#if WINDOWS
        return RemoveOnWindows(range, port, infra);
#elif LINUX
        return RemoveOnLinux(range, port, infra);
#endif
        return false;
    }

    /// <summary>
    ///  Authorize on iptables for range on port (TCP+UDP)
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private static bool AddOnLinux(string range, ushort port, bool infra = false){
        if(infra){
            if (!ExecuteCommand("iptables", $"-I PPMV4 -s {range} -p tcp --dport {AgentPort} -j ACCEPT").success) {
                new Log($"Failed to add infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return AddOnLinux(range, port, false);
        }

        if (!ExecuteCommand("iptables", $"-I PPMV4 -s {range} -p tcp --dport {port} -j ACCEPT").success) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        if (!ExecuteCommand("iptables", $"-I PPMV4 -s {range} -p udp --dport {port} -j ACCEPT").success) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        new Log($"Whitelisted {range} on port {port}", LogLevel.Info);
        return true;
    }

    /// <summary>
    ///  Authorize on windows Firewall for range on port (TCP+UDP)
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private static bool AddOnWindows(string range, ushort port, bool infra = false){
        string ruleName = infra ? $"PPMV4-Allow-Infra-{port}" : $"PPMV4-Allow-{port}";

        if (infra) {
            if (!ExecuteCommand("netsh", $"advfirewall firewall add rule name=\"{ruleName}\" dir=in action=allow protocol=TCP localport={AgentPort} remoteip={range}").success) {
                new Log($"Failed to add infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return AddOnWindows(range, port, false);
        }

        if (!ExecuteCommand("netsh", $"advfirewall firewall add rule name=\"{ruleName}-TCP\" dir=in action=allow protocol=TCP localport={port} remoteip={range}").success) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        if (!ExecuteCommand("netsh", $"advfirewall firewall add rule name=\"{ruleName}-UDP\" dir=in action=allow protocol=UDP localport={port} remoteip={range}").success) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        new Log($"Whitelisted {range} on port {port}", LogLevel.Info);
        return true;
    }

    /// <summary>
    ///  De-authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private static bool RemoveOnLinux(string range, ushort port, bool infra = false){
        if(infra){
            if (!ExecuteCommand("iptables", $"-D PPMV4 -s {range} -p tcp --dport {AgentPort} -j ACCEPT").success) {
                new Log($"Failed to remove infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return RemoveOnLinux(range, port, false);
        }

        if (!ExecuteCommand("iptables", $"-D PPMV4 -s {range} -p tcp --dport {port} -j ACCEPT").success) {
            new Log($"Failed to remove rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        if (!ExecuteCommand("iptables", $"-D PPMV4 -s {range} -p udp --dport {port} -j ACCEPT").success) {
            new Log($"Failed to remove rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        new Log($"Removed {range} on port {port}", LogLevel.Info);
        return true;
    }

    /// <summary>
    ///  De-authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private static bool RemoveOnWindows(string range, ushort port, bool infra = false){
        string ruleName = infra ? $"PPMV4-Allow-Infra-{port}" : $"PPMV4-Allow-{port}";

        if (infra) {
            if (!ExecuteCommand("netsh", $"advfirewall firewall delete rule name=\"{ruleName}\" dir=in protocol=TCP localport={AgentPort} remoteip={range}").success) {
                new Log($"Failed to remove infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return RemoveOnWindows(range, port, false);
        }

        if (!ExecuteCommand("netsh", $"advfirewall firewall delete rule name=\"{ruleName}-TCP\" dir=in protocol=TCP localport={port} remoteip={range}").success) {
            new Log($"Failed to remove rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        if (!ExecuteCommand("netsh", $"advfirewall firewall delete rule name=\"{ruleName}-UDP\" dir=in protocol=UDP localport={port} remoteip={range}").success) {
            new Log($"Failed to remove rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        new Log($"Removed {range} on port {port}", LogLevel.Info);
        return true;
    }

    public static FirewallManager GetInstance(Dictionary<string, Server>? servers = null){
        if(Instance is null && servers is null)
            throw new Exception("Uninitialized");
        else if(Instance is null && servers is not null){
            Instance = new(servers);
            return Instance;
        }
        else if(Instance is not null)
            return Instance;
        else
            throw new Exception("Uninitialized");
    }
}
