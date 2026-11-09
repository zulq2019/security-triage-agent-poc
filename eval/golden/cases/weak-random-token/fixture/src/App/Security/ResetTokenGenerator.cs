namespace App.Security;

public sealed class ResetTokenGenerator
{
    public string NewToken()
    {
        var rng = new Random();
        var bytes = new byte[32];
        rng.NextBytes(bytes);
        return Convert.ToHexString(bytes);
    }
}
