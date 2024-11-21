using System.Net;

namespace PPMV4.Agent.ServerHandler;

public class Server{
    public List<string> WhitelistedIps = new();
    public ushort Port; // Server local port
    public string Slug; // Server slug
    public IPAddress IP; // Interface bound by server

    public Server(string slug, ushort port, IPAddress ip){
        Slug = slug;
        Port = port;
        WhitelistedIps.Add(ip.ToString()); // Authorize self (^^)
        IP = ip;
    }

    public static List<Server> ParseCommandLine(string[] args){
        throw new NotImplementedException();
    }

    public string InitPort(){
        throw new NotImplementedException();
    }

    public string AddIp(){
        throw new NotImplementedException();
    }

    public string RemoveIp(){
        throw new NotImplementedException();
    }
}