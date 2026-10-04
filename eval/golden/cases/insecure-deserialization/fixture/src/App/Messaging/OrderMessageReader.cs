using Newtonsoft.Json;

namespace App.Messaging;

public sealed class OrderMessage
{
    public int Id { get; set; }
    public string Customer { get; set; } = "";
}

public sealed class OrderMessageReader
{
    public OrderMessage? Load(string json)
    {
        var settings = new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All };
        return JsonConvert.DeserializeObject<OrderMessage>(json, settings);
    }
}
