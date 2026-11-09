using App.Data;
using Xunit;

namespace App.Tests;

public class OrdersRepositoryTests
{
    internal static OrdersRepository NewRepo()
    {
        var db = Path.Combine(Path.GetTempPath(), $"eval-{Guid.NewGuid():N}.db");
        var repo = new OrdersRepository($"Data Source={db}");
        repo.Seed();
        return repo;
    }

    [Fact]
    public void Returns_the_customers_items()
    {
        Assert.Equal(new[] { "book", "pen" }, NewRepo().FindByCustomer("alice").OrderBy(x => x));
    }
}
