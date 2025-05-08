using DyanamicsAPI.Data;
using DyanamicsAPI.DTOs;
using DyanamicsAPI.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace DyanamicsAPI.Services
{
    public class AuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // AuthService.AuthenticateAsync
        public async Task<(string Token, User user)> AuthenticateAsync(LoginRequestDto loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loginDto.Username);

            if (user == null)
                return (null, null);

            var passwordHash = ComputeSha256Hash(loginDto.Password);

            if (user.PasswordHash != passwordHash)
                return (null, null);

            var token = GenerateJwtToken(user);
            return (token, user);
        }

        public async Task<UserDto> AddUserAsync(AddUserRequestDto dto)
        {
            var newUser = new User
            {
                Username = dto.Username,
                Email = dto.Email,
                PasswordHash = ComputeSha256Hash(dto.Password),
                Role = dto.Role
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            return new UserDto
            {
                Id = newUser.Id,
                Username = newUser.Username,
                Email = newUser.Email
            };
        }
        public async Task<List<UserDto>> GetAllUsersAsync()
        {
            return await _context.Users
                .Select(u => new UserDto
                {
                    Id = u.Id,
                    Username = u.Username,
                    Email = u.Email,
                    Role = u.Role.ToString()
                })
                .ToListAsync();
        }

        public async Task<bool> DeleteUserAsync(int id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
                return false;

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }

        public async Task<UserDto?> UpdateUserAsync(int id, UpdateUserRequestDto dto)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
                return null;

            user.Email = dto.Email ?? user.Email;
            user.Username = dto.Username ?? user.Username;
            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                user.PasswordHash = ComputeSha256Hash(dto.Password);
            }
            user.Role = dto.Role ?? user.Role;

            await _context.SaveChangesAsync();

            return new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Role = user.Role.ToString()
            };
        }


        public static string ComputeSha256Hash(string rawData)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }

        private string GenerateJwtToken(User user)
        {
             var claims = new List<Claim>
    {
                 new(JwtRegisteredClaimNames.Sub, user.Username),
                 new(JwtRegisteredClaimNames.Email, user.Email),
                 new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                 new Claim("http://schemas.microsoft.com/ws/2008/06/identity/claims/role", user.Role.ToString())

    };

            // Decode base64 key
            var secretKey = _configuration["JwtSettings:SecretKey"]!;
            var keyBytes = Encoding.UTF8.GetBytes(secretKey); // Match validation approach
            var key = new SymmetricSecurityKey(keyBytes);

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],      // "DyamicsAPI"
                audience: _configuration["JwtSettings:Audience"],  // "DyamicsAPIUser"
                claims: claims,
                expires: DateTime.UtcNow.AddHours(24),
                signingCredentials: creds
            );

            // Return the JWT token as a string (the compact serialization format)
            return new JwtSecurityTokenHandler().WriteToken(token);
        }




    }
}
