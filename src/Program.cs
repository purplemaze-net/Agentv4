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

        byte[] publicCert = GetRessource("Purplemaze-Agent.keys.certificate.pem");
        X509Certificate2 cert = new(publicCert);

        // Parse servers
        Dictionary<string, Server> servers = Server.ParseCommandLine(args);

        // Initialize firewall manager
        FirewallManager fm = FirewallManager.GetInstance(servers);
        if(!FirewallManager.InitFirewall()){
            new Log("Firewall initialization failed", LogLevel.Error);
            Environment.Exit(1);
        }

        if(!fm.InitWhitelist()){
            new Log("Error while initializing IP whitelist", LogLevel.Error);
            Environment.Exit(1);
        }

        // Start web server
        WebServer webServer = new(cert, servers);
        webServer.StartWebServer();
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
                using (Stream? stream = assembly.GetManifestResourceStream(ressource)) {
                    if(stream != null) {
                        // Direct binary read instead of using StreamReader
                        using (MemoryStream ms = new MemoryStream()) {
                            stream.CopyTo(ms);
                            return ms.ToArray();
                        }
                    }
                }
            }
        }

        // If not found or null somewhere
        throw new Exception("Resource not found");
    }

}