using DyanamicsAPI.DTOs;
using DyanamicsAPI.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace DyanamicsAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;

        public AuthController(AuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto loginDto)
        {
            var (token, user) = await _authService.AuthenticateAsync(loginDto);

            if (token == null)
                return Unauthorized("Invalid username or password.");

            var response = new LoginResponseDto
            {
                Username = user.Username,
                Token = token,
                Role = user.Role.ToString()
            };

            return Ok(response);
        }

        [Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("Add User")]
        public async Task<IActionResult> AddUser([FromBody] AddUserRequestDto addUserDto)
        {
            var user = await _authService.AddUserAsync(addUserDto);
            return Ok("User Added successfully.");
        }

        // Get all users (SuperAdmin, Admin)
        [Authorize(Roles = "SuperAdmin,Admin,User")]
        [HttpGet("Getallusers")]
        public async Task<IActionResult> GetUsers()
        {
            var users = await _authService.GetAllUsersAsync();
            return Ok(users);
        }

        // Delete a user (only SuperAdmin)
        //[Authorize(Roles = "SuperAdmin")]
        [HttpPost("Delete user/id")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            var success = await _authService.DeleteUserAsync(id);
            if (!success)
                return NotFound("User not found.");

            return Ok("User deleted successfully.");
        }

        // Update a user (SuperAdmin, Admin)
        //[Authorize(Roles = "SuperAdmin,Admin")]
        [HttpPost("Edit user/id")]
        public async Task<IActionResult> UpdateUser(int id, [FromBody] UpdateUserRequestDto updateDto)
        {
            var updatedUser = await _authService.UpdateUserAsync(id, updateDto);
            if (updatedUser == null)
                return NotFound("User not found.");

            return Ok(updatedUser);
        }
    }
}
