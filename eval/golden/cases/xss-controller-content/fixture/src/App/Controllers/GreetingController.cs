using Microsoft.AspNetCore.Mvc;

namespace App.Controllers;

[ApiController]
[Route("greet")]
public sealed class GreetingController : ControllerBase
{
    [HttpGet]
    public ContentResult Greet(string name)
    {
        return Content("<p>Hello " + name + "</p>", "text/html");
    }
}
