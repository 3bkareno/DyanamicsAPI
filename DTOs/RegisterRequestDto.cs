using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class RegisterRequestDto
    {
        public string Username { get; set; } = null!;
        public string Password { get; set; } = null!;
        public string Email { get; set; } = null!;
        public UserRole Role { get; set; }
    }
}
