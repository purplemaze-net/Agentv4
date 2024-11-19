using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Newtonsoft.Json;
using PPMV4.Agent.Logging;
using PPMV4.Agent.Structures;

namespace PPMV4.Agent.WebServer
{
    public class WebServer
    {
        public HttpListener Listener;
        X509Certificate2 PubCert;
        public const int Port = 6950;

        public WebServer(X509Certificate2 cert){
            PubCert = cert;

            // Start web server
            Listener = new();
            Listener.Prefixes.Add($"http://+:{Port}/");
        }

        private bool CheckTimestamp(long timestamp, int ttl){
            return Math.Abs(DateTimeOffset.UtcNow.ToUnixTimeSeconds() - timestamp) > ttl;
        }

        private bool CheckSignature(string signature, string body){
            byte[] data = Encoding.UTF8.GetBytes(body);
            byte[] signatureBytes = Convert.FromBase64String(signature);

            using (RSA? rsa = PubCert.GetRSAPublicKey())
            {
                if(rsa is null)
                    return false;

                // Check with rsa
                return rsa.VerifyData(
                    data,
                    signatureBytes,
                    HashAlgorithmName.SHA512,
                    RSASignaturePadding.Pss);
            }
        }

        public static async void SendResponse(HttpListenerResponse resp, ApiResponse apiResp, int httpCode){
            if(!resp.OutputStream.CanWrite)
                return;

            resp.StatusCode = httpCode;
            resp.ContentType = "application/json";

            byte[] buffer = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(apiResp));
            resp.ContentLength64 = buffer.Length;
            await resp.OutputStream.WriteAsync(buffer, 0, buffer.Length);

            resp.Close();
        }

        public (ApiResponse, int) WhitelistHandler(HttpListenerRequest req, WhitelistAction action){
            // Read body
            ApiResponse resp = new(false, "Generic Error");
            
            string body = "";

            using(var reader = new StreamReader(req.InputStream, req.ContentEncoding)){
                body = reader.ReadToEnd();
            }

            string? signature = req.Headers.Get("signature");
            if(signature is null){ // prevent missing header
                resp.Error = "Missing signature header";
                return (resp, 400);
            }

            if(!CheckSignature(signature, body)){
                resp.Error = "Request authenticity check failure";
                return (resp, 400);
            }

            // Parse body
            ApiRequest? apiReq = JsonConvert.DeserializeObject<ApiRequest>(body);
            if(apiReq is null){
                resp.Error = "Wrong body json format";
                return (resp, 400);
            }

            // Check TTL
            if(!CheckTimestamp(apiReq.Timestamp, apiReq.TTL)){
                resp.Error = "Request expired";
                return (resp, 400);
            }

            // TODO: Whitelist job
            throw new NotImplementedException();
        }

        public async Task HandleIncomingConnections()
        {
            bool run = true;
            while (run)
            {
                try
                {
                    HttpListenerContext ctx = await Listener.GetContextAsync();
                    HttpListenerRequest req = ctx.Request;
                    HttpListenerResponse resp = ctx.Response;

                    ApiResponse apiResp = new(false, "Generic error");

                    string? path = req?.Url?.AbsolutePath;

                    if(path is null){
                        throw new Exception("empty path");
                    }

                    // Log
                    new Log($"(WS) {req?.RemoteEndPoint}: {req?.HttpMethod} {path}");

                    // Check the path
                    if (path.Contains("/alive")) {
                        apiResp = new(true, "alive !");
                    }
                    else if (path.Contains("/whitelist")) {
                        // check method
                        if (req?.HttpMethod == "POST") {
                            // handle request
                            (apiResp, int respCode) = WhitelistHandler(req, WhitelistAction.Remove);
                            SendResponse(resp, apiResp, respCode);
                            
                        }
                        else if (req?.HttpMethod == "DELETE") {
                            // handle request
                            (apiResp, int respCode) = WhitelistHandler(req, WhitelistAction.Remove);
                            SendResponse(resp, apiResp, respCode);
                        }
                        else {
                            apiResp = new(false, "Unknown method");
                            SendResponse(resp, apiResp, 405);
                        }
                    }
                    else {
                        apiResp = new(false, "Unknown route");
                        SendResponse(resp, apiResp, 404);
                    }
                }
                catch(Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }

        public Task startWebServer()
        {
            while (true)
            {
                try
                {
                    Listener.Start();
                    new Log($"Web Server started");
                    Task listenTask = HandleIncomingConnections();
                    listenTask.GetAwaiter().GetResult();
                }
                catch (Exception e)
                {
                    new Log($"Error in web server: {e.Message}");;
                    Environment.Exit(1);
                }
                // Close then re-run on error
                finally
                {
                    if (Listener.IsListening)
                        Listener.Stop();
                }
                Listener.Close();
            }
        }
    }
}