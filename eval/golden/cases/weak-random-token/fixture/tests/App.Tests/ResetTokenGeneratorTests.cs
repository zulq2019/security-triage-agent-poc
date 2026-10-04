using App.Security;
using Xunit;

namespace App.Tests;

public class ResetTokenGeneratorTests
{
    [Fact]
    public void Token_is_64_hex_characters()
    {
        Assert.Matches("^[0-9A-F]{64}$", new ResetTokenGenerator().NewToken());
    }
}
