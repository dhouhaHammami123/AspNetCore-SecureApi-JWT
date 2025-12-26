using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using SecureAPI_JWT.Models;
using SecureAPI_JWT.Services;

namespace SecureAPI_JWT.Controllers
{
    // Controllers/AuthController.cs
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            var result = await _authService.RegisterAsync(model);
            return Ok(result);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetToken(TokenRequestModel model)
        {
            var token = await _authService.GetTokenAsync(model);
            if (token == null)
                return Unauthorized();
            return Ok(new { token });
        }

        [HttpPost("addrole")]
        public async Task<IActionResult> AddRole(AddRoleModel model)
        {
            var result = await _authService.AddRoleAsync(model);
            return Ok(result);
        }
    }
}
