using DyanamicsAPI.Data;
using DyanamicsAPI.Models;

namespace DyanamicsAPI.Services
{
    public class DbSeeder
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly ILogger<DbSeeder> _logger;

        public DbSeeder(AppDbContext context, IConfiguration configuration, ILogger<DbSeeder> logger)
        {
            _context = context;
            _configuration = configuration;
            _logger = logger;
        }

        public async Task SeedSuperAdminAsync()
        {
            if (_context.Users.Any())
            {
                _logger.LogInformation("Database already has users. Skipping seeding...");
                return;
            }

            var superAdminUsername = _configuration["SuperAdmin:Username"];
            var superAdminPassword = _configuration["SuperAdmin:Password"];
            var superAdminEmail = _configuration["SuperAdmin:Email"];

            if (string.IsNullOrWhiteSpace(superAdminUsername) ||
                string.IsNullOrWhiteSpace(superAdminPassword) ||
                string.IsNullOrWhiteSpace(superAdminEmail))
            {
                _logger.LogError("SuperAdmin settings are missing in configuration.");
                return;
            }

            var hashedPassword = AuthService.ComputeSha256Hash(superAdminPassword);

            var superAdmin = new User
            {
                Username = superAdminUsername,
                PasswordHash = hashedPassword,
                Email = superAdminEmail,
                Role = UserRole.SuperAdmin,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(superAdmin);
            await _context.SaveChangesAsync();

            _logger.LogInformation("SuperAdmin user seeded successfully.");
        }
    }
}
