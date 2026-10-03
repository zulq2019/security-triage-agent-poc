using App;
using Xunit;

namespace App.Tests;

public class OrderMappingTests
{
    [Fact]
    public void Maps_entity_to_dto()
    {
        var dto = OrderMapping.ToDto(new OrderEntity { Id = 3, Customer = "bob" });
        Assert.Equal(3, dto.Id);
        Assert.Equal("bob", dto.Customer);
    }
}
