using DyanamicsAPI.Models;
using DyanamicsAPI.Services;
using Microsoft.EntityFrameworkCore;

namespace DyanamicsAPI.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
        public DbSet<BlacklistedToken> BlacklistedTokens { get; set; }
        public DbSet<IpLoginAttempt> IpLoginAttempts { get; set; }
        public DbSet<UserFile> UserFiles { get; set; }



        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>(entity =>
            {
                entity.HasKey(u => u.Id);
                entity.Property(u => u.Id).ValueGeneratedOnAdd();

                entity.HasIndex(u => u.Username).IsUnique();
                entity.HasIndex(u => u.Email).IsUnique();

                entity.Property(u => u.Username)
                    .IsRequired()
                    .HasMaxLength(50);

                entity.Property(u => u.PasswordHash)
                    .IsRequired()
                    .HasMaxLength(256);

                entity.Property(u => u.Role)
                    .IsRequired()
                    .HasConversion<string>();
            });

            // Refresh Token Configuration
            modelBuilder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(rt => rt.Id);
                entity.Property(rt => rt.Id).ValueGeneratedOnAdd();

                entity.Property(rt => rt.Token)
                    .IsRequired()
                    .HasMaxLength(88); // Base64 encoded 64-byte token

                entity.Property(rt => rt.Created)
                    .IsRequired()
                    .HasDefaultValueSql("GETUTCDATE()");

                entity.Property(rt => rt.Expires)
                    .IsRequired();

                // Relationship with User
                entity.HasOne(rt => rt.User)
                    .WithMany(u => u.RefreshTokens)
                    .HasForeignKey(rt => rt.UserId)
                    .OnDelete(DeleteBehavior.Cascade);

                entity.HasIndex(rt => rt.Token).IsUnique();
            });

            // Blacklisted Token Configuration
            modelBuilder.Entity<BlacklistedToken>(entity =>
            {
                entity.HasKey(bt => bt.Id);
                entity.Property(bt => bt.Id).ValueGeneratedOnAdd();

                entity.Property(bt => bt.Jti)
                    .IsRequired()
                    .HasMaxLength(36); // GUID length

                entity.Property(bt => bt.Expiry)
                    .IsRequired();

                entity.HasIndex(bt => bt.Jti).IsUnique();
                entity.HasIndex(bt => bt.Expiry);
            });


            modelBuilder.Entity<UserFile>(entity =>
            {
                entity.HasKey(f => f.Id);
                entity.Property(f => f.FilePath).IsRequired();
                entity.Property(f => f.UploadedAt).HasDefaultValueSql("GETUTCDATE()");
                entity.HasOne(f => f.User)
                      .WithMany(u => u.UserFiles)
                      .HasForeignKey(f => f.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });


        }
    }
}