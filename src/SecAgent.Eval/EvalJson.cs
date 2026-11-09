using System.Text.Encodings.Web;
using System.Text.Json;
using SecAgent.Core;

namespace SecAgent.Eval;

/// <summary>JSON options for files people read and edit (recordings, baseline, report): snake_case like every other schema, indented,
/// and without escaping &lt;, &gt;, quotes and apostrophes so code inside recordings stays readable.</summary>
public static class EvalJson
{
    public static readonly JsonSerializerOptions Files = new(Schema.JsonIndented) { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };
}
