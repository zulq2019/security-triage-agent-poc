using App.Models;
using Xunit;

namespace App.Tests;

public class ProfileViewModelTests
{
    [Fact]
    public void Defaults_are_empty()
    {
        Assert.Equal("", new ProfileViewModel().Bio);
    }
}
