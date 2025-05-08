using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class UpdateUserRequestDto
    {
        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Email { get; set; }
        public UserRole? Role { get; set; }
    }
}
