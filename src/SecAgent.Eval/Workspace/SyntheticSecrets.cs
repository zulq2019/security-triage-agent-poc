using System.Security.Cryptography;
using System.Text;

namespace SecAgent.Eval.Workspace;

/// <summary>Generates synthetic secret values at run time so no secret-looking literal is ever committed with the fixtures.</summary>
public interface ISyntheticSecretGenerator
{
    string Generate(string caseId, string name, string kind);
}

/// <summary>Deterministic per (case, name, kind): the same run twice produces the same prompts (replay prompt hashes stay stable).
/// Values have the right shape for detectors and the masker but are not real credentials.</summary>
public sealed class DeterministicSecretGenerator : ISyntheticSecretGenerator
{
    const string Base32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    const string Alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    public string Generate(string caseId, string name, string kind)
    {
        var seed = SHA256.HashData(Encoding.UTF8.GetBytes($"secagent-eval|{caseId}|{name}|{kind}"));
        return kind switch
        {
            "aws_access_key_id" => "AKIA" + Pick(seed, Base32, 16),
            "stripe_test_key" => "sk_test_" + Pick(seed, Alnum, 24),
            "stripe_live_key" => "sk_live_" + Pick(seed, Alnum, 24),
            "github_pat" => "ghp_" + Pick(seed, Alnum, 36),
            "password" => "Pw-" + Pick(seed, Alnum, 18),
            _ => throw new InvalidOperationException($"unknown synthetic secret kind '{kind}'"),
        };
    }

    static string Pick(byte[] seed, string alphabet, int n)
    {
        var sb = new StringBuilder(n);
        var block = seed;
        for (int i = 0; i < n; i++)
        {
            if (i > 0 && i % block.Length == 0) block = SHA256.HashData(block);
            sb.Append(alphabet[block[i % block.Length] % alphabet.Length]);
        }
        return sb.ToString();
    }
}
