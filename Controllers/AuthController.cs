using DyanamicsAPI.DTOs;
using DyanamicsAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.JsonWebTokens;
using System.Security.Claims;

namespace DyanamicsAPI.Controllers
{
    [EnableRateLimiting("api")]
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly IWebHostEnvironment _env;
        private readonly ILogger<AuthController> _logger;

        public AuthController(
       AuthService authService,
       IWebHostEnvironment env,
       ILogger<AuthController> logger)
        {
            _authService = authService;
            _env = env;
            _logger = logger;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginDto)
        {
            // 1. Validate input
            // tuple deconstruction
            var (accessToken, refreshToken, user) = await _authService.AuthenticateAsync(loginDto);

            if (accessToken == null)
                return Unauthorized("Invalid credentials");

            // Set refresh token as HTTP-only cookie
            Response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            return Ok(new LoginResponseDto
            {
                Id = user.Id, // Include user GUID
                Username = user.Username,
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token, // Will now have value
                Role = user.Role.ToString(),
                ExpiresIn = (int)TimeSpan.FromMinutes(15).TotalSeconds
            });
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            // 1. More descriptive error message
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Refresh token missing. Please login again.");

            try
            {
                // 2. Add token validation
                if (!IsValidRefreshTokenFormat(refreshToken))
                    return BadRequest("Malformed refresh token");

                // 3. Null check for newRefreshToken
                var (accessToken, newRefreshToken) = await _authService.RefreshTokenAsync(refreshToken);

                if (accessToken == null || newRefreshToken == null)
                    return Unauthorized(new
                    {
                        Message = "Invalid or expired refresh token",
                        Action = "require_login"
                    });

                // 4. Additional cookie security
                Response.Cookies.Append("refreshToken", newRefreshToken.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Expires = newRefreshToken.Expires,
                    Secure = !_env.IsDevelopment(), // Allow non-HTTPS in dev
                    SameSite = SameSiteMode.Strict,
                    Path = "/api/auth" // Restrict cookie path
                });

                // 5. Return token expiry time
                return Ok(new
                {
                    AccessToken = accessToken,
                    ExpiresIn = 900 // 15 minutes in seconds
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Refresh token failure");
                return StatusCode(500, "Internal server error");
            }
        }

        // Helper method
        private bool IsValidRefreshTokenFormat(string token)
        {
            try
            {
                return !string.IsNullOrEmpty(token) &&
                       Convert.FromBase64String(token).Length >= 64;
            }
            catch
            {
                return false;
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            var refreshToken = Request.Cookies["refreshToken"];

            if (jti == null || refreshToken == null)
                return BadRequest("Invalid token data");

            await _authService.LogoutAsync(jti, refreshToken);

            // Clear the refresh token cookie
            Response.Cookies.Delete("refreshToken");

            return Ok("Logged out successfully");
        }


        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("AddUser")]
        public async Task<IActionResult> AddUser([FromBody] AddUserRequestDto addUserDto)
        {
            var user = await _authService.AddUserAsync(addUserDto);
            return Ok("User Added successfully.");
        }

        // Get all users (SuperAdmin, Admin)
        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpGet("Getallusers")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _authService.GetAllUsersAsync();
            return Ok(users);
        }

        // Delete a user (only SuperAdmin)
        [Authorize(Roles = "SuperAdmin")]
        [HttpPost("Deleteuser/id")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var success = await _authService.DeleteUserAsync(id);
            if (!success)
                return NotFound("User not found.");

            return Ok("User deleted successfully.");
        }

        // Update a user (SuperAdmin, Admin)
        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("Edituser/id")]
        public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserRequestDto updateDto)
        {
            var updatedUser = await _authService.UpdateUserAsync(id, updateDto);
            if (updatedUser == null)
                return NotFound("User not found.");

            return Ok(updatedUser);
        }
    }
}
