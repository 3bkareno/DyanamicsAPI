using DyanamicsAPI.Models;

namespace DyanamicsAPI.DTOs
{
    public class LoginResponseDto
    {
        public Guid Id { get; set; }  // Added user GUID
        public string Username { get; set; }
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; } // Will no longer be null
        public string Role { get; set; }
        public int ExpiresIn { get; set; } = 900; // 15 minutes in seconds
        public DateTime? LastSuccessfulLogin { get; set; }

    }
}
