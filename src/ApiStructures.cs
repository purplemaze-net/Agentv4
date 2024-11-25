using Newtonsoft.Json;

namespace PPMV4.Agent.Structures;

#pragma warning disable CS8618 // Don't warn possible-null-values as it will throw an error if the serialization fails.
public class InitialRequestData {
    [JsonProperty("infra", Required = Required.Always)]
    public List<string> InfraRanges { get; set; }

    [JsonProperty("proxies", Required = Required.Always)]
    public List<string> ProxiesRanges { get; set; }
}

public class ApiResponse<T> {
    [JsonProperty("success", Required = Required.Always)]
    public bool Success { get; set; }

    [JsonProperty("error", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public string? Error { get; set; }

    [JsonProperty("message", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public string? Message { get; set; }

    [JsonProperty("data", Required = Required.AllowNull, NullValueHandling = NullValueHandling.Ignore)]
    public T? Data { get; set; }

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

public class ApiRequest {

    [JsonProperty("ranges", Required = Required.Always)]
    public List<string> Ranges { get; set; }

    [JsonProperty("timestamp", Required = Required.Always)]
    public long Timestamp { get; set; }

    [JsonProperty("seed", Required = Required.Always)]
    public string Seed { get; set; }

    [JsonProperty("ttl", Required = Required.Always)]
    public int TTL { get; set; }
}
#pragma warning restore CS8618