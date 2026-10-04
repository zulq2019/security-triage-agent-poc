// SPDX-License-Identifier: GPL-3.0-only
// Synthetic vendored snippet for the evaluation fixture (not real third-party code).
namespace App.ThirdParty.CsvEscaper;

public static class CsvEscaper
{
    public static string Escape(string value)
    {
        return value.Contains(',') || value.Contains('"') ? "\"" + value.Replace("\"", "\"\"") + "\"" : value;
    }
}
