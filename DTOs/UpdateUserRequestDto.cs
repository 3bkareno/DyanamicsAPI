using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class UpdateUserRequestDto
    {
        public Guid Id { get; set; } // Changed from int

        public string? Username { get; set; }
        public string? Password { get; set; }
        public string? Email { get; set; }
        public UserRole? Role { get; set; }
    }
}
