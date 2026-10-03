using Microsoft.Data.Sqlite;

namespace App.Data;

public sealed class ReportRepository
{
    private readonly string _connectionString;

    public ReportRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public List<string> ListOrders(string sortColumn)
    {
        using var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"SELECT Item FROM Orders ORDER BY {sortColumn}";
        var items = new List<string>();
        using var reader = cmd.ExecuteReader();
        while (reader.Read()) items.Add(reader.GetString(0));
        return items;
    }
}
