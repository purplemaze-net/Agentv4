using System.Diagnostics;
using System.Net;
using System.Text;
using PPMV4.Agent.Logging;
using PPMV4.Agent.ServerHandler;

namespace PPMV4.Agent.Firewall;

public class FirewallManager {
    private static FirewallManager? Instance;
    Dictionary<string, Server> Servers;
    private const string MasterUrl = "https://agent.api.purplemaze.net";

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
    public static bool Add(string address, ushort port){
#if WINDOWS
        return AddOnWindows(address, port);
#elif LINUX
        return AddOnLinux(address, port);
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
        throw new NotImplementedException();
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
    ///  Initialize the whitelist: Fetch the IPs for each server, then add them to the firewall.
    /// </summary>
    public void InitWhitelist(){

    }

    /// <summary>
    ///  Authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool AddOnWindows(string address, ushort port){
        throw new NotImplementedException();   
    }

    /// <summary>
    ///  Authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool AddOnLinux(string address, ushort port){
        throw new NotImplementedException();
    }

    /// <summary>
    ///  De-authorize on windows Firewall for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool RemoveOnWindows(string address, ushort port){
        throw new NotImplementedException();   
    }

    /// <summary>
    ///  De-authorize on iptables for address on port (TCP+UDP)
    /// </summary>
    /// <param name="address"></param>
    /// <param name="port"></param>
    /// <returns></returns>
    private bool RemoveOnLinux(string address, ushort port){
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