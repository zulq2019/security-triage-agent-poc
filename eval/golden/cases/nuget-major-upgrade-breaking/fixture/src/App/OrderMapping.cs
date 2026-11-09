using AutoMapper;

namespace App;

public sealed class OrderEntity { public int Id { get; set; } public string Customer { get; set; } = ""; }
public sealed class OrderDto { public int Id { get; set; } public string Customer { get; set; } = ""; }

public static class OrderMapping
{
    static OrderMapping()
    {
        Mapper.Initialize(cfg => cfg.CreateMap<OrderEntity, OrderDto>());
    }

    public static OrderDto ToDto(OrderEntity entity)
    {
        return Mapper.Map<OrderDto>(entity);
    }
}
