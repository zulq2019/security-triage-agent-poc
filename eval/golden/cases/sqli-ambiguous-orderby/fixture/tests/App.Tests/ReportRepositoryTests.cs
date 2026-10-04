using App.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace App.Tests;

public class ReportRepositoryTests
{
    [Fact]
    public void Lists_orders_sorted_by_the_requested_column()
    {
        var db = Path.Combine(Path.GetTempPath(), $"eval-{Guid.NewGuid():N}.db");
        using (var conn = new SqliteConnection($"Data Source={db}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "CREATE TABLE Orders (Item TEXT, Total REAL); INSERT INTO Orders VALUES ('lamp', 30), ('book', 12.5);";
            cmd.ExecuteNonQuery();
        }
        Assert.Equal(new[] { "book", "lamp" }, new ReportRepository($"Data Source={db}").ListOrders("Item"));
    }
}
