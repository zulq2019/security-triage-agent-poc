using Newtonsoft.Json;

namespace App;

public sealed record Order(int Id, string Customer, decimal Total);

public sealed class OrderSerializer
{
    public string Write(Order order)
    {
        return JsonConvert.SerializeObject(order);
    }

    public Order? Read(string json)
    {
        return JsonConvert.DeserializeObject<Order>(json);
    }
}
