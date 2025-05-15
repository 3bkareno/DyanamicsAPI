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
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

            var (accessToken, refreshToken, user) = await _authService.AuthenticateAsync(loginDto, ip);

            if (accessToken == null)
                return Unauthorized("Invalid credentials or IP blocked");

            Response.Cookies.Append("refreshToken", refreshToken.Token, new CookieOptions
            {
                HttpOnly = true,
                Expires = refreshToken.Expires,
                Secure = true,
                SameSite = SameSiteMode.Strict
            });

            return Ok(new LoginResponseDto
            {
                Id = user.Id,
                Username = user.Username,
                AccessToken = accessToken,
                RefreshToken = refreshToken.Token,
                Role = user.Role.ToString(),
                ExpiresIn = (int)TimeSpan.FromMinutes(15).TotalSeconds,
                LastSuccessfulLogin = user.LastSuccessfulLogin
            });
        }


        
        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken()
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrEmpty(refreshToken))
                return BadRequest("Refresh token missing");

            try
            {
                var (accessToken, newRefreshToken) = await _authService.RefreshTokenAsync(refreshToken);
                if (accessToken == null || newRefreshToken == null)
                    return Unauthorized("Invalid refresh token");

                Response.Cookies.Append("refreshToken", newRefreshToken.Token, new CookieOptions
                {
                    HttpOnly = true,
                    Expires = newRefreshToken.Expires,
                    Secure = !_env.IsDevelopment(),
                    SameSite = SameSiteMode.Strict,
                    Path = "/api/auth"
                });

                return Ok(new
                {
                    AccessToken = accessToken,
                    ExpiresIn = 900
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Refresh token failure");
                return StatusCode(500, "Internal server error");
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
            Response.Cookies.Delete("refreshToken");

            return Ok("تم تسجيل الخروج بنجاح");
        }

        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("AddUser")]
        public async Task<IActionResult> AddUser([FromBody] AddUserRequestDto addUserDto)
        {
            var (user, error) = await _authService.AddUserAsync(addUserDto);
            if (error != null)
                return BadRequest(new { Error = error });

            return Ok(new
            {
                Message = "تمت إضافة المستخدم بنجاح",
                User = new { user.Id, user.Username, user.Email, user.Role }
            });
        }

        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpGet("GetAllUsers")]
        public async Task<IActionResult> GetAllUsers()
        {
            var users = await _authService.GetAllUsersAsync();
            return Ok(users);
        }

        [Authorize(Roles = "SuperAdmin")]
        [HttpDelete("DeleteUser/{id}")]
        public async Task<IActionResult> DeleteUser(Guid id)
        {
            var success = await _authService.DeleteUserAsync(id);
            return success ? Ok("تم حذف المستخدم") : NotFound("لم يتم العثور على المستخدم");
        }

        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPut("UpdateUser/{id}")]
        public async Task<IActionResult> UpdateUser(Guid id, [FromBody] UpdateUserRequestDto updateDto)
        {
            var (updatedUser, error) = await _authService.UpdateUserAsync(id, updateDto);
            if (error != null)
                return BadRequest(new { Error = error });

            return Ok(new
            {
                Message = "تم تحديث المستخدم بنجاح",
                User = updatedUser
            });
        }

        [Authorize]
        [HttpPost("ChangePassword")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordDto dto)
        {
            var userIdClaim = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userIdClaim, out var userId))
                return BadRequest("تنسيق معرف المستخدم غير صالح");

            var currentJti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

            var (success, error) = await _authService.ChangePasswordAsync(
                userId,
                dto,
                currentJti
            );

            if (!success) return BadRequest(new { Error = error });

            // Clear current session's refresh token cookie
            Response.Cookies.Delete("refreshToken");

            return Ok(new
            {
                Message = "تم نغير كلمة المرور برجاء تسجيل الدخول مرة اخري"
            });
        }
    }
}