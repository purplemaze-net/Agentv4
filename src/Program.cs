using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;

class Agent
{
    static void Main()
    {
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

        // Start web server
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