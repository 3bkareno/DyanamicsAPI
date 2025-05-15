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
        private readonly ILogger<AuthService> _logger;


        public AuthService(AppDbContext context, IConfiguration configuration, ILogger<AuthService> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task<(string AccessToken, RefreshToken RefreshToken, User User)> AuthenticateAsync(LoginRequestDto loginDto, string ipAddress)
        {
            var ipAttempt = await _context.IpLoginAttempts.FirstOrDefaultAsync(x => x.IpAddress == ipAddress);
            if (ipAttempt != null && ipAttempt.BlockedUntil.HasValue && ipAttempt.BlockedUntil > DateTime.UtcNow)
            {
                _logger.LogWarning("Login attempt from blocked IP: {IP}. Blocked until {Time}", ipAddress, ipAttempt.BlockedUntil);
                return (null, null, null);
            }

            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == loginDto.Username);

            if (user == null)
            {
                _logger.LogWarning("Failed login attempt with unknown username: {Username} from IP: {IP}", loginDto.Username, ipAddress);
                await TrackFailedIpLogin(ipAddress);
                return (null, null, null);
            }

            if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
            {
                _logger.LogWarning("Login attempt on locked out user: {Username} from IP: {IP}", user.Username, ipAddress);
                return (null, null, null);
            }

            if (ComputeSha256Hash(loginDto.Password) != user.PasswordHash)
            {
                user.FailedLoginAttempts++;
                _logger.LogWarning("Failed login for user: {Username} from IP: {IP} (Attempt #{Count})", user.Username, ipAddress, user.FailedLoginAttempts);

                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockoutEnd = DateTime.UtcNow.AddMinutes(15);
                    _logger.LogWarning("User {Username} locked out until {Time}", user.Username, user.LockoutEnd);
                }

                await TrackFailedIpLogin(ipAddress);

                _context.Users.Update(user);
                await _context.SaveChangesAsync();
                return (null, null, null);
            }

            // Successful login
            _logger.LogInformation("Successful login for user: {Username} from IP: {IP}", user.Username, ipAddress);

            user.FailedLoginAttempts = 0;
            user.LockoutEnd = null;
            user.LastSuccessfulLogin = DateTime.UtcNow;

            if (ipAttempt != null)
            {
                ipAttempt.FailedAttempts = 0;
                ipAttempt.BlockedUntil = null;
                _context.IpLoginAttempts.Update(ipAttempt);
            }

            var (accessToken, jti) = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken(user.Id, jti);

            _context.RefreshTokens.Add(refreshToken);
            _context.Users.Update(user);
            await _context.SaveChangesAsync();

            return (accessToken, refreshToken, user);
        }


        private async Task TrackFailedIpLogin(string ipAddress)
        {
            var ipAttempt = await _context.IpLoginAttempts.FirstOrDefaultAsync(x => x.IpAddress == ipAddress);
            if (ipAttempt == null)
            {
                ipAttempt = new IpLoginAttempt
                {
                    IpAddress = ipAddress,
                    FailedAttempts = 1
                };
                _logger.LogWarning("Tracking new failed IP login from {IP} (Attempt #1)", ipAddress);
                _context.IpLoginAttempts.Add(ipAttempt);
            }
            else
            {
                ipAttempt.FailedAttempts++;
                _logger.LogWarning("Failed login attempt #{Count} from IP: {IP}", ipAttempt.FailedAttempts, ipAddress);

                if (ipAttempt.FailedAttempts >= 10)
                {
                    ipAttempt.BlockedUntil = DateTime.UtcNow.AddMinutes(30);
                    _logger.LogWarning("IP {IP} blocked until {Time}", ipAddress, ipAttempt.BlockedUntil);
                }

                _context.IpLoginAttempts.Update(ipAttempt);
            }

            await _context.SaveChangesAsync();
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
                return (null, "اسم المستخدم موجود بالفعل");

            if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return (null, "البريد الإلكتروني قيد الاستخدام بالفعل");

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
                return (null, "لم يتم العثور على المستخدم");

            if (!string.IsNullOrWhiteSpace(dto.Password))
            {
                var (isValid, errorMessage) = PasswordValidator.Validate(dto.Password);
                if (!isValid)
                    return (null, errorMessage);
            }

            if (dto.Username != null && dto.Username != user.Username)
            {
                if (await _context.Users.AnyAsync(u => u.Username == dto.Username))
                    return (null, "اسم المستخدم موجود بالفعل");
            }

            if (dto.Email != null && dto.Email != user.Email)
            {
                if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                    return (null, "البريد الإلكتروني قيد الاستخدام بالفعل");
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
            if (user == null) return (false, "لم يتم العثور على المستخدم");

            // Verify current password
            if (ComputeSha256Hash(dto.CurrentPassword) != user.PasswordHash)
                return (false, "كلمة المرور الحالية غير صحيحة");

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
                throw new ArgumentException("معرف المستخدم غير صالح");
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