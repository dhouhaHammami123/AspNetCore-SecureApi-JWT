// Services/IAuthService.cs
using SecureAPI_JWT.Models;

namespace SecureAPI_JWT.Services
{
    public interface IAuthService
    {
        Task<string> RegisterAsync(RegisterModel model);
        Task<string> GetTokenAsync(TokenRequestModel model);
        Task<string> AddRoleAsync(AddRoleModel model);
    }
}