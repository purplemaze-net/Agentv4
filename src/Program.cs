using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using PPMV4.Agent.Firewall;
using PPMV4.Agent.Logging;
using PPMV4.Agent.ServerHandler;
using PPMV4.Agent.WebServer;

class Agent {
    static void Main(string[] args) {
        Console.WriteLine("PurpleMaze Agent (V4)");
        Console.WriteLine("Copyright (©) 2022-" + DateTimeOffset.UtcNow.Date.Year.ToString());
        Console.WriteLine("MathiAs2Pique (@m2p_)");

#if WINDOWS
        new Log("Platform: Windows");
#elif LINUX
        new Log("Platform: Linux");
#endif

        byte[] publicCert = GetRessource("Purplemaze-Agent.keys.public.key");
        X509Certificate2 cert = new(publicCert);

        // Parse servers
        Dictionary<string, Server> servers = Server.ParseCommandLine(args);

        // Initialize firewall manager
        FirewallManager.GetInstance(servers);
        if(!FirewallManager.InitFirewall()){
            new Log("Firewall initialization failed", LogLevel.Error);
            Environment.Exit(1);
        }

        // Start web server
        WebServer webServer = new(cert, servers);
        Task.Run(webServer.startWebServer).Wait();
    }

    /// <summary>
    ///  Get content from an embedded resource
    /// </summary>
    /// <param name="name">Name of the resource</param>
    static byte[] GetRessource(string name) {
        var assembly = Assembly.GetExecutingAssembly();
        string[] ressources = assembly.GetManifestResourceNames();
        
        foreach (string ressource in ressources) {
            if (ressource == name) {
                using (Stream? stream = assembly.GetManifestResourceStream(ressource))
                if(stream != null){
                    using (StreamReader reader = new(stream)) {
                        return Encoding.UTF8.GetBytes(reader.ReadToEnd());
                    }
                }
            }
        }

        // If not found or null somewhere
        throw new Exception("Resource not found");
    }

}