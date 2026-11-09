using App.Data;
using Microsoft.Data.Sqlite;
using Xunit;

namespace App.Tests;

public class CatalogRepositoryTests
{
    [Fact]
    public void Counts_active_products()
    {
        var db = Path.Combine(Path.GetTempPath(), $"eval-{Guid.NewGuid():N}.db");
        using (var conn = new SqliteConnection($"Data Source={db}"))
        {
            conn.Open();
            using var cmd = conn.CreateCommand();
            cmd.CommandText = "CREATE TABLE Products (Name TEXT, Active INTEGER); INSERT INTO Products VALUES ('a', 1), ('b', 0), ('c', 1);";
            cmd.ExecuteNonQuery();
        }
        Assert.Equal(2, new CatalogRepository($"Data Source={db}").CountActive());
    }
}
