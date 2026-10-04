using App;
using Xunit;

namespace App.Tests;

public class OrderSerializerTests
{
    [Fact]
    public void Round_trips_an_order()
    {
        var s = new OrderSerializer();
        var back = s.Read(s.Write(new Order(7, "alice", 12.5m)));
        Assert.Equal(new Order(7, "alice", 12.5m), back);
    }
}
