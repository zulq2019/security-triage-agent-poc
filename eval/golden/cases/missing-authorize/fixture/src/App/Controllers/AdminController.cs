using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace App.Controllers;

[ApiController]
[Route("api/admin")]
public sealed class AdminController : ControllerBase
{
    [HttpGet("health")]
    [AllowAnonymous]
    public IActionResult Health()
    {
        return Ok("ok");
    }

    [HttpDelete("users/{id}")]
    public IActionResult DeleteUser(int id)
    {
        return NoContent();
    }
}
