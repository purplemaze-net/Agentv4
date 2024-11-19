using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PPMV4.Agent.Structures;

public class ApiResponse {
    [JsonProperty("success", Required = Required.Always)]
    public bool Success { get; set; }

    [JsonProperty("error", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public string? Error { get; set; }

    [JsonProperty("message", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public string? Message { get; set; }

    [JsonProperty("data", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public JObject? Data { get; set; }

    public ApiResponse(bool success, string description){
        Success = success;
        if(success){
            Message = description;
        }
        else{
            Error = description;
        }
    }
}

public enum WhitelistAction{
    Add,
    Remove
}

#pragma warning disable CS8618 // Don't warn as it will throw an error if the serialization fails.
public class ApiRequest {

    [JsonProperty("ip", Required = Required.Always)]
    public List<string> IP { get; set; }

    [JsonProperty("timestamp", Required = Required.Always)]
    public long Timestamp { get; set; }

    [JsonProperty("seed", Required = Required.Always)]
    public string Seed { get; set; }

    [JsonProperty("ttl", Required = Required.Always)]
    public int TTL { get; set; }
}
#pragma warning restore CS8618