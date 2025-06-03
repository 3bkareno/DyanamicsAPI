using System;

namespace DyanamicsAPI.Models
{
    public class UserFile
    {
        public Guid Id { get; set; }
        public string FilePath { get; set; }
        public DateTime UploadedAt { get; set; }

        // Foreign Key
        public Guid UserId { get; set; }
        public User User { get; set; }
    }
}
