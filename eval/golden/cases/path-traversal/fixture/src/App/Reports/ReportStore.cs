namespace App.Reports;

public sealed class ReportStore
{
    private readonly string _root;

    public ReportStore(string root)
    {
        _root = root;
    }

    public string Read(string name)
    {
        return File.ReadAllText(Path.Combine(_root, name));
    }
}
