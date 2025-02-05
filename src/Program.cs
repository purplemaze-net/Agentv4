using System.Reflection;
using System.Security.Cryptography.X509Certificates;
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

        byte[] publicCert = GetCertificate();
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
    ///  Get content from embedded certificate
    /// </summary>
    static byte[] GetCertificate() {
        var assembly = Assembly.GetExecutingAssembly();
        string[] ressources = assembly.GetManifestResourceNames();
        
        foreach (string ressource in ressources) {
            if (ressource == "Purplemaze-Agent.keys.certificate.pem") {
                using (Stream? stream = assembly.GetManifestResourceStream(ressource)) {
                    if(stream != null) {
                        using (StreamReader reader = new(stream)) {
                            string pemContent = reader.ReadToEnd();
                            // Remove PEM headers and decode base64
                            string base64 = pemContent
                                .Replace("-----BEGIN CERTIFICATE-----", "")
                                .Replace("-----END CERTIFICATE-----", "")
                                .Replace("\n", "")
                                .Replace("\r", "");
                            return Convert.FromBase64String(base64);
                        }
                    }
                }
            }
        }

        throw new Exception("Resource not found");
    }


}