namespace DyanamicsAPI.Models
{
    public class BlacklistedToken
    {
        public int Id { get; set; }
        public string Jti { get; set; }  // JWT ID claim
        public DateTime Expiry { get; set; }
    }
}
