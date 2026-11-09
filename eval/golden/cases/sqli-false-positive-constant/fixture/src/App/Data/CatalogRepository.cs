using Microsoft.Data.Sqlite;

namespace App.Data;

public sealed class CatalogRepository
{
    private const string TableName = "Products";
    private readonly string _connectionString;

    public CatalogRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public int CountActive()
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM " + TableName + " WHERE Active = 1";
        return Convert.ToInt32(cmd.ExecuteScalar());
    }
}
