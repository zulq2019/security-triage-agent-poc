using App.Security;
using Xunit;

namespace App.Tests;

public class DocumentHasherTests
{
    [Fact]
    public void Same_content_gives_the_same_hash()
    {
        var h = new DocumentHasher();
        Assert.Equal(h.Hash("invoice-42"), h.Hash("invoice-42"));
    }
}
