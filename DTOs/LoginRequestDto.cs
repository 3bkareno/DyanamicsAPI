
using System.ComponentModel.DataAnnotations;

namespace DyanamicsAPI.DTOs
{
    public class LoginRequestDto
    {
        [Required]
        
        public string Username { get; set; } = string.Empty;
        [Required]
        public string Password { get; set; } = string.Empty;
        

    }
}
