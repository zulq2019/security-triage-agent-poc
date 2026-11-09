using App.Reports;
using Xunit;

namespace App.Tests;

public class ReportStoreTests
{
    internal static string NewRoot()
    {
        var root = Path.Combine(Path.GetTempPath(), $"eval-reports-{Guid.NewGuid():N}");
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, "q3.txt"), "quarterly report");
        return root;
    }

    [Fact]
    public void Reads_a_report_in_the_folder()
    {
        Assert.Equal("quarterly report", new ReportStore(NewRoot()).Read("q3.txt"));
    }
}
