using DyanamicsAPI.Data;
using DyanamicsAPI.DTOs;
using DyanamicsAPI.Models;
using DyanamicsAPI.Validators;
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

        public async Task<(string AccessToken, RefreshToken RefreshToken, User User)> AuthenticateAsync(LoginRequestDto loginDto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loginDto.Username);

            if (user == null || ComputeSha256Hash(loginDto.Password) != user.PasswordHash)
                return (null, null, null);

            var (accessToken, jti) = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken(user.Id, jti);

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            return (accessToken, refreshToken, user);
        }

        public async Task<(string AccessToken, RefreshToken RefreshToken)> RefreshTokenAsync(string refreshToken)
        {
            var storedToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == refreshToken && rt.Expires > DateTime.UtcNow);

            if (storedToken == null)
                return (null, null);

            // Check blacklist using stored JTI
            var isBlacklisted = await _context.BlacklistedTokens
                .AnyAsync(bt => bt.Jti == storedToken.Jti && bt.Expiry > DateTime.UtcNow);

            if (isBlacklisted)
                return (null, null);

            var (newAccessToken, newJti) = GenerateJwtToken(storedToken.User);
            var newRefreshToken = GenerateRefreshToken(storedToken.User.Id, newJti);

            _context.RefreshTokens.Remove(storedToken);
            _context.RefreshTokens.Add(newRefreshToken);
            await _context.SaveChangesAsync();

            return (newAccessToken, newRefreshToken);
        }

        public async Task<bool> LogoutAsync(string accessTokenJti, string refreshToken)
        {
            // Blacklist the access token
            _context.BlacklistedTokens.Add(new BlacklistedToken
            {
                Jti = accessTokenJti,
                Expiry = DateTime.UtcNow.AddHours(24)
            });

            // Delete the refresh token
            var storedRefreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == refreshToken);

            if (storedRefreshToken != null)
                _context.RefreshTokens.Remove(storedRefreshToken);

            await _context.SaveChangesAsync();
            return true;
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
        public async Task<(UserDto User, string Error)> AddUserAsync(AddUserRequestDto dto)
        {
            var (isValid, errorMessage) = PasswordValidator.Validate(dto.Password);
            if (!isValid)
                return (null, errorMessage);

            if (await _context.Users.AnyAsync(u => u.Username == dto.Username))
                return (null, "Username already exists");

            if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return (null, "Email already in use");

            var newUser = new User
            {
                Username = dto.Username,
                Email = dto.Email,
                PasswordHash = ComputeSha256Hash(dto.Password),
                Role = dto.Role
            };

            _context.Users.Add(newUser);
            await _context.SaveChangesAsync();

            return (new UserDto
            {
                Id = newUser.Id,
                Username = newUser.Username,
                Email = newUser.Email,
                Role = newUser.Role.ToString()
            }, null);
        }

        public async Task<bool> DeleteUserAsync(Guid id)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null) return false;

            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }
        public async Task<(UserDto? User, string? Error)> UpdateUserAsync(Guid id, UpdateUserRequestDto dto)
        {
            var user = await _context.Users.FindAsync(id);
            if (user == null)
                return (null, "User not found");

            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                var (isValid, errorMessage) = PasswordValidator.Validate(dto.Password);
                if (!isValid)
                    return (null, errorMessage);
            }

            if (dto.Username != null && dto.Username != user.Username)
            {
                if (await _context.Users.AnyAsync(u => u.Username == dto.Username))
                    return (null, "Username already exists");
            }

            if (dto.Email != null && dto.Email != user.Email)
            {
                if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                    return (null, "Email already in use");
            }

            user.Email = dto.Email ?? user.Email;
            user.Username = dto.Username ?? user.Username;
            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                user.PasswordHash = ComputeSha256Hash(dto.Password);
            }
            user.Role = dto.Role ?? user.Role;

            await _context.SaveChangesAsync();

            return (new UserDto
            {
                Id = user.Id,
                Username = user.Username,
                Email = user.Email,
                Role = user.Role.ToString()
            }, null);
        }

        public async Task<(bool Success, string Error)> ChangePasswordAsync(Guid userId, ChangePasswordDto dto, string currentJti)
        {
            var user = await _context.Users.FindAsync(userId);
            if (user == null) return (false, "User not found");

            // Verify current password
            if (ComputeSha256Hash(dto.CurrentPassword) != user.PasswordHash)
                return (false, "Current password is incorrect");

            // Validate new password
            var (isValid, errorMessage) = PasswordValidator.Validate(dto.NewPassword);
            if (!isValid) return (false, errorMessage);

            // Update password
            user.PasswordHash = ComputeSha256Hash(dto.NewPassword);

            // Get all refresh tokens and their JTIs
            var refreshTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId)
                .ToListAsync();

            // Blacklist all related JTIs
            var jtisToBlacklist = refreshTokens.Select(rt => rt.Jti).ToList();
            jtisToBlacklist.Add(currentJti); // Also blacklist current token

            foreach (var jti in jtisToBlacklist.Distinct())
            {
                _context.BlacklistedTokens.Add(new BlacklistedToken
                {
                    Jti = jti,
                    Expiry = DateTime.UtcNow.AddHours(24)
                });
            }

            // Remove all refresh tokens
            _context.RefreshTokens.RemoveRange(refreshTokens);

            await _context.SaveChangesAsync();
            return (true, null);
        }

        private RefreshToken GenerateRefreshToken(Guid userId, string jti)
        {
            if (!_context.Users.Any(u => u.Id == userId))
                throw new ArgumentException("Invalid user ID");
            return new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                Expires = DateTime.UtcNow.AddDays(7),
                UserId = userId,
                Created = DateTime.UtcNow,
                Jti = jti
            };
        }

        private (string Token, string Jti) GenerateJwtToken(User user)
        {
            var jti = Guid.NewGuid().ToString();
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new(JwtRegisteredClaimNames.Email, user.Email),
                new(JwtRegisteredClaimNames.Jti, jti),
                new(ClaimTypes.Role, user.Role.ToString()),
                new(ClaimTypes.NameIdentifier, user.Id.ToString())
            };

            var key = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(_configuration["JwtSettings:SecretKey"]!));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _configuration["JwtSettings:Issuer"],
                audience: _configuration["JwtSettings:Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(15),
                signingCredentials: creds
            );

            return (new JwtSecurityTokenHandler().WriteToken(token), jti);
        }

        public static string ComputeSha256Hash(string rawData)
        {
            using var sha256 = SHA256.Create();
            var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return BitConverter.ToString(bytes).Replace("-", "").ToLower();
        }
    }
}