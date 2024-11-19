using System.Net;
using PPMV4.Agent.ServerHandler;

namespace PPMV4.Agent.Firewall;

public class FirewallManager {
    private static FirewallManager? Instance;
    Dictionary<string, Server> Servers;

    private FirewallManager(Dictionary<string, Server> servers){
        Servers = servers;
    }

    // Make the initial IP requests & whitelist them
    public void Init(){

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