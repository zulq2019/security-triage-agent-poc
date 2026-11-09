using App.Controllers;
using Xunit;

namespace App.Tests;

public class GreetingControllerTests
{
    [Fact]
    public void Greets_by_name()
    {
        Assert.Contains("Hello ada", new GreetingController().Greet("ada").Content);
    }
}
