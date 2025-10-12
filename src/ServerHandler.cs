using System.Net;

namespace PPMV4.Agent.ServerHandler;

public class Server{
    public List<string> WhitelistedIps = new();
    public List<string> WhitelistedIps_tx = new();
    public ushort Port; // Server local port
    public string Slug; // Server slug
    public IPAddress IP; // Interface bound by server
    public ushort? TxPort; // txAdmin port, default null

    public Server(string slug, ushort port, IPAddress ip, ushort? txPort = null){
        Slug = slug;
        Port = port;
        WhitelistedIps.Add(ip.ToString()); // Authorize self (^^)
        WhitelistedIps_tx.Add(ip.ToString());
        IP = ip;
        TxPort = txPort;
    }

    /// <summary>
    ///  Exemple: ./software "slug:ip:port" "slug:ip:port[:txPort]"
    /// </summary>
    /// <param name="args"></param>
    /// <returns></returns>
    /// <exception cref="NotImplementedException"></exception>
    public static Dictionary<string, Server> ParseCommandLine(string[] args){
        try{
            Dictionary<string, Server> servers = new();
            foreach(string arg in args){
                string[] parts = arg.Split(':');
                if (parts.Count() == 3 || parts.Count() == 4)
                {
                    ushort tx_port = 0;
                    if (parts[0].Length != 8 || parts[0].LastIndexOfAny("abcdef0987654321".ToCharArray()) != parts[0].Length - 1)
                        throw new Exception($"Invalid slug: '{parts[0]}' in '{arg}");
                    if (!IPAddress.TryParse(parts[1], out var sv_ip))
                        throw new Exception($"Invalid IP: '{parts[1]}' in '{arg}");
                    if (!ushort.TryParse(parts[2], out ushort sv_port))
                        throw new Exception($"Invalid port: '{parts[2]}' in '{arg}");
                    if (parts.Count() == 4 && !ushort.TryParse(parts[3], out tx_port))
                        throw new Exception($"Invalid txAdmin port: '{parts[3]}' in '{arg}'");

                    if (!servers.ContainsKey(parts[0]))
                        servers.Add(parts[0], new(parts[0], sv_port, sv_ip, tx_port == 0 ? null : tx_port));
                    else
                        throw new Exception($"Duplicated server slug: '{parts[0]}'");

                }
                else
                    throw new Exception($"Unrecognized arg: '{arg}'");
            }

            if(servers.Count > 0)
                return servers;
            else
                throw new Exception($"No valid arguments");
        }
        catch(Exception e){
            string exeName = Path.GetFileName(Environment.ProcessPath ?? System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName ?? "program");
            Console.WriteLine($"{e.Message}. \nArgs must be in the format 'slug:ip:port'.\nExample1:  {exeName} \"abcdef12:10.11.12.13:80\"\nExample2:  {exeName} \"abcdef13:10.11.12.13:3011\" \"abcdff14:10.11.12.13:3012\"");
            Environment.Exit(1);
            throw new Exception("Error while parsing arguments");
        }
    }
}