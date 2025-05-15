namespace DyanamicsAPI.Models
{
    public class RefreshToken
    {
        public Guid Id { get; set; } = Guid.NewGuid();
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public DateTime Created { get; set; }

        public string Jti { get; set; }  // Stores associated JWT ID

        // Foreign key property
        public Guid UserId { get; set; }

        // Navigation property
        public virtual User User { get; set; }
    }
}
