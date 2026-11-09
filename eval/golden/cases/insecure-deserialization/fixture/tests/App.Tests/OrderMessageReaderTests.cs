using App.Messaging;
using Xunit;

namespace App.Tests;

public class OrderMessageReaderTests
{
    [Fact]
    public void Reads_a_plain_message()
    {
        var m = new OrderMessageReader().Load("{\"Id\":5,\"Customer\":\"carol\"}");
        Assert.Equal(5, m!.Id);
    }
}
