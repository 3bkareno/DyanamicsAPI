namespace DyanamicsAPI.DTOs
{
    public class RefreshTokenDto
    {
        public Guid Id { get; set; }
        public string Token { get; set; }
        public DateTime Expires { get; set; }
        public string UserId { get; set; }
    }
}
