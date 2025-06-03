using Microsoft.AspNetCore.Mvc;

namespace DyanamicsAPI.DTOs
{
    public class FileUploadDto
    {
        [FromForm]
        public IFormFile File { get; set; }
    }
}
