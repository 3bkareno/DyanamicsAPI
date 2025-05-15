namespace DyanamicsAPI.Models
{
    public class IpLoginAttempt
    {
        public int Id { get; set; }
        public string IpAddress { get; set; }
        public int FailedAttempts { get; set; }
        public DateTime? BlockedUntil { get; set; }
    }
}
