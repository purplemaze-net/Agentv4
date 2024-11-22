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
        // Check if the user is admin
#pragma warning disable CA1416 // Platform compatibility
        if (!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) {
            new Log($"You need to be admin to use the Windows Firewall. Please re-run this software with the appropriate permissions.", LogLevel.Error);
            return false;
        }
#pragma warning restore CA1416 // Platform compatibility

        // Check if the firewall is enabled
        if (!Process.Start("netsh", "advfirewall show allprofiles").StandardOutput.ReadToEnd().Contains("State ON")) {
            new Log($"The Windows Firewall is disabled. Please enable it and try again.", LogLevel.Error);
            return false;
        }

        // Purge any "PPMV4" rules
        if (Process.Start("netsh", "advfirewall firewall delete rule name=\"PPMV4\"").ExitCode != 0) {
            new Log($"Failed to delete existing PPMV4 rules. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Init the firewall for Linux.
    /// </summary>
    private static bool InitFirewallLinux() {
        // Check if iptables is installed
        if (Process.Start("which", "iptables").ExitCode != 0) {
            new Log($"iptables is required on linux, but not installed. Please install it and try again.", LogLevel.Error);
            return false;
        }

        // Check if the user is root
        if (Process.Start("whoami").StandardOutput.ReadToEnd().Trim() != "root") {
            new Log($"You need to be root to use iptables. Please re-run this software with the appropriate permissions.", LogLevel.Error);
            return false;
        }

        // Check if the chain "PPMV4" exists
        if (Process.Start("iptables", "-L PPMV4").ExitCode != 0) {
            new Log($"Chain PPMV4 not found. Creating it.", LogLevel.Info);
            if (Process.Start("iptables", "-N PPMV4").ExitCode != 0) {
                new Log($"Failed to create chain PPMV4. Exiting.", LogLevel.Error);
                return false;
            }
        }

        // If PPMV4 exists, flush it
        if (Process.Start("iptables", "-F PPMV4").ExitCode != 0) {
            new Log($"Failed to flush chain PPMV4. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, return true so we can continue 
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
        // Add block rules in the iptables chain (TCP)
        if (Process.Start("iptables", $"-A PPMV4 -p tcp --dport {port} -j DROP").ExitCode != 0) {
            new Log($"Failed to add block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, UDP
        if (Process.Start("iptables", $"-A PPMV4 -p udp --dport {port} -j DROP").ExitCode != 0) {
            new Log($"Failed to add block rule for port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    /// Block traffic for a server (Windows)
    /// </summary>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool DefaultBlockForServerWindows(ushort port){
        // Blocked by default, nothing to do (for the moment)
        return true;
    }

    /// <summary>
    ///  Get an HttpClient bound to a specific IP address.
    /// </summary>
    /// <param name="address"></param>
    /// <returns></returns>
    // Ref: https://stackoverflow.com/questions/65930192/how-to-bind-httpclient-to-a-specific-source-ip-address-in-net-5
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
        new Log($"Initializing whitelist", LogLevel.Info);
        bool systemDone = false;

        foreach (var server in Servers){
            // Init block
            if(!DefaultBlockForServer(server.Value)){
                new Log($"Failed to block traffic for server {server.Key}. Exiting.", LogLevel.Error);
                return false;
            }

            // HTTP request
            using (var httpClient = GetHttpClient(server.Value.IP)) {

                var response = httpClient.GetAsync($"{MasterUrl}/ranges/{server.Value.Slug}").GetAwaiter().GetResult();
                if (response.IsSuccessStatusCode) {
                    var content = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
                    ApiResponse<InitialRequestData>? data = JsonConvert.DeserializeObject<ApiResponse<InitialRequestData>>(content);
                    if (data is null || data.Data is null) {
                        new Log($"Failed to deserialize IP ranges for server {server.Key}", LogLevel.Error);
                        return false;
                    }

                    // Add infra ranges (used to ping this agent)
                    if(!systemDone){
                        foreach (var range in data.Data.InfraRanges) {
                            Add(range, AgentPort, true);
                        }
                        systemDone = true;
                    }

                    // Add proxies ranges
                    foreach (var range in data.Data.ProxiesRanges) {
                        Add(range, server.Value.Port);
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
        // Check range validity
        if(!IPAddressRange.TryParse(range, out _)){
            new Log($"Invalid range: {range}", LogLevel.Warning);
            return false;
        }

#if WINDOWS
        return AddOnWindows(address, port, infra);
#elif LINUX
        return AddOnLinux(address, port, infra);
#endif
        return false;
    }

    /// <summary>
    ///  Remove the firewall rule for the address on the port.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    public static bool Remove(string address, ushort port, bool infra = false){
#if WINDOWS
        return RemoveOnWindows(address, port, infra);
#elif LINUX
        return RemoveOnLinux(address, port, infra);
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
    private bool AddOnLinux(string range, ushort port, bool infra = false){
        // The range is already validated

        // Infra: Whitelist for *this agent* port + the server port)
        if(infra){
            // Only tcp for infra
            if (Process.Start("iptables", $"-I PPMV4 -s {range} -p tcp --dport {AgentPort} -j ACCEPT").ExitCode != 0) {
                new Log($"Failed to add infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return AddOnLinux(range, port, false); // WL on server port
        }

        // Add the tcp rule
        if (Process.Start("iptables", $"-I PPMV4 -s {range} -p tcp --dport {port} -j ACCEPT").ExitCode != 0) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, the UDP one
        if (Process.Start("iptables", $"-I PPMV4 -s {range} -p udp --dport {port} -j ACCEPT").ExitCode != 0) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    ///  Authorize on windows Firewall for range on port (TCP+UDP)
    /// </summary>
    /// <param name="range"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private bool AddOnWindows(string range, ushort port, bool infra = false){
        // The range is already validated

        // Infra: Whitelist for *this agent* port + the server port
        if(infra){
            // Only TCP for infra
            if (Process.Start("netsh", $"advfirewall firewall add rule name=\"PPMV4\" dir=in action=allow protocol=TCP localport={AgentPort} remoteip={range}").ExitCode != 0) {
                new Log($"Failed to add infra rule for range {range} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return AddOnWindows(range, port, false); // WL on server port
        }

        // Add the TCP rule
        if (Process.Start("netsh", $"advfirewall firewall add rule name=\"PPMV4\" dir=in action=allow protocol=TCP localport={port} remoteip={range}").ExitCode != 0) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, the UDP one
        if (Process.Start("netsh", $"advfirewall firewall add rule name=\"PPMV4\" dir=in action=allow protocol=UDP localport={port} remoteip={range}").ExitCode != 0) {
            new Log($"Failed to add rule for range {range} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    ///  De-authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private bool RemoveOnLinux(string address, ushort port, bool infra = false){
        // Range already validated

        // Infra: Remove the infra rule
        if(infra){
            if (Process.Start("iptables", $"-D PPMV4 -s {address} -p tcp --dport {AgentPort} -j ACCEPT").ExitCode != 0) {
                new Log($"Failed to remove infra rule for address {address} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return RemoveOnLinux(address, port, false); // Remove on server port aswell
        }

        // Remove the TCP rule
        if (Process.Start("iptables", $"-D PPMV4 -s {address} -p tcp --dport {port} -j ACCEPT").ExitCode != 0) {
            new Log($"Failed to remove rule for address {address} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, the UDP one
        if (Process.Start("iptables", $"-D PPMV4 -s {address} -p udp --dport {port} -j ACCEPT").ExitCode != 0) {
            new Log($"Failed to remove rule for address {address} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    /// <summary>
    ///  De-authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <param name="infra"></param>
    /// <returns></returns>
    private bool RemoveOnWindows(string address, ushort port, bool infra = false){
        // Range already validated

        // Infra: Remove the infra rule
        if(infra){
            if (Process.Start("netsh", $"advfirewall firewall delete rule name=\"PPMV4\" dir=in action=allow protocol=TCP localport={AgentPort} remoteip={address}").ExitCode != 0) {
                new Log($"Failed to remove infra rule for address {address} on port {port}. Exiting.", LogLevel.Error);
                return false;
            }

            return RemoveOnWindows(address, port, false); // Remove on server port aswell
        }

        // Remove the TCP rule
        if (Process.Start("netsh", $"advfirewall firewall delete rule name=\"PPMV4\" dir=in action=allow protocol=TCP localport={port} remoteip={address}").ExitCode != 0) {
            new Log($"Failed to remove rule for address {address} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        // Then, the UDP one
        if (Process.Start("netsh", $"advfirewall firewall delete rule name=\"PPMV4\" dir=in action=allow protocol=UDP localport={port} remoteip={address}").ExitCode != 0) {
            new Log($"Failed to remove rule for address {address} on port {port}. Exiting.", LogLevel.Error);
            return false;
        }

        return true;
    }

    public static FirewallManager GetInstance(Dictionary<string, Server>? servers){
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