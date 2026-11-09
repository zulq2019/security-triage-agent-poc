using System.Reflection;
using App.Controllers;
using Microsoft.AspNetCore.Authorization;
using Xunit;

namespace App.Tests;

public class AdminControllerTests
{
    [Fact]
    public void Health_is_anonymous()
    {
        Assert.NotNull(typeof(AdminController).GetMethod(nameof(AdminController.Health))!.GetCustomAttribute<AllowAnonymousAttribute>());
    }
}
