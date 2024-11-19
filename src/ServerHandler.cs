using System.Net;
using PPMV4.Agent.Logging;

namespace PPMV4.Agent.ServerHandler;

public class Server{
    public List<string> WhitelistedIps = new();
    public Server(string slug, ushort port, IPAddress ip){

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