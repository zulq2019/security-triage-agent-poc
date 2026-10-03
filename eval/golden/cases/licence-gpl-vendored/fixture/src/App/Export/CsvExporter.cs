using App.ThirdParty.CsvEscaper;

namespace App.Export;

public sealed class CsvExporter
{
    public string Row(IEnumerable<string> cells)
    {
        return string.Join(',', cells.Select(CsvEscaper.Escape));
    }
}
