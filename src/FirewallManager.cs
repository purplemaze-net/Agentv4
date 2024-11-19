using System.Net;
using PPMV4.Agent.ServerHandler;

namespace PPMV4.Agent.Firewall;

public class FirewallManager {
    private static FirewallManager? Instance;
    Dictionary<string, Server> Servers;

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
        throw new NotImplementedException();
    }

    /// <summary>
    /// Init the firewall for Linux.
    /// </summary>
    private static bool InitFirewallLinux() {
        throw new NotImplementedException();
    }

    // Make the initial IP requests & whitelist them
    public void Init(){

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