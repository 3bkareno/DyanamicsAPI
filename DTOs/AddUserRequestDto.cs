using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class AddUserRequestDto
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public UserRole Role { get; set; } = UserRole.User;
    }
}
