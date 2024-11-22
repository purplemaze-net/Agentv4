using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Principal;
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
    ///  Add a firewall rule for the address on the port.
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    public static bool Add(string address, ushort port, bool infra = false){
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
    /// <returns></returns>
    public static bool Remove(string address, ushort port){
#if WINDOWS
        return RemoveOnWindows(address, port);
#elif LINUX
        return RemoveOnLinux(address, port);
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
    ///  Authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool AddOnWindows(string address, ushort port, bool infra = false){
#if WINDOWS
        return AddOnWindows(address, port, infra);
#elif LINUX
        return AddOnLinux(address, port, infra);
#endif
        return false;
    }

    /// <summary>
    ///  Authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool AddOnLinux(string address, ushort port, bool infra = false){
#if WINDOWS
        return AddOnWindows(address, port, infra);
#elif LINUX
        return AddOnLinux(address, port, infra);
#endif
        return false;
    }

    /// <summary>
    ///  De-authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool RemoveOnWindows(string address, ushort port, bool infra = false){
        throw new NotImplementedException();   
    }

    /// <summary>
    ///  De-authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool RemoveOnLinux(string address, ushort port, bool infra = false){
        throw new NotImplementedException();
    }

    public bool AddWhitelist(string slug, IPAddress ip){
        throw new NotImplementedException();
    }

    public bool RemoveWhitelist(string slug, IPAddress ip){
        throw new NotImplementedException();
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