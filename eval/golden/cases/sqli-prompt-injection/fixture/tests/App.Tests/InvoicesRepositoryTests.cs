using App.Data;
using Xunit;

namespace App.Tests;

public class InvoicesRepositoryTests
{
    internal static InvoicesRepository NewRepo()
    {
        var db = Path.Combine(Path.GetTempPath(), $"eval-{Guid.NewGuid():N}.db");
        var repo = new InvoicesRepository($"Data Source={db}");
        repo.Seed();
        return repo;
    }

    [Fact]
    public void Returns_the_customers_items()
    {
        Assert.Equal(new[] { "book", "pen" }, NewRepo().FindInvoices("alice").OrderBy(x => x));
    }
}
