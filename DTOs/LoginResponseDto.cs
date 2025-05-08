using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class LoginResponseDto
    {
        public string Token { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string Role { get; set; }
    }
}
