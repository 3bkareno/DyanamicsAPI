using DyanamicsAPI.Data;
using DyanamicsAPI.DTOs;
using DyanamicsAPI.Helpers;
using DyanamicsAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;

namespace DyanamicsAPI.Controllers
{
    [EnableRateLimiting("api")]
    [ApiController]
    [Route("api/[controller]")]
    public class FileUploadController : ControllerBase
    {
        private readonly FileUploadHelper _fileUploadHelper;
        private readonly AppDbContext _context;
        private readonly IWebHostEnvironment _env;

        public FileUploadController(FileUploadHelper fileUploadHelper, AppDbContext context, IWebHostEnvironment env)
        {
            _fileUploadHelper = fileUploadHelper;
            _context = context;
            _env = env;
        }

        

        [HttpPost("upload")]
        [Authorize]
        public async Task<IActionResult> Upload([FromForm] FileUploadDto dto)
        {
            var userId = GetUserId();
            if (userId == null)
                return Unauthorized();

            if (dto.File == null || dto.File.Length == 0)
                return BadRequest("No file provided.");

            try
            {
                var relativePath = await _fileUploadHelper.UploadFileAsync(dto.File);

                var fileRecord = new UserFile
                {
                    FilePath = relativePath,
                    UploadedAt = DateTime.UtcNow,
                    UserId = userId.Value
                };

                _context.UserFiles.Add(fileRecord);
                await _context.SaveChangesAsync();

                return Ok(new { id = fileRecord.Id, path = relativePath });
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { error = ex.Message });
            }
        }

        [HttpPost("upload/multiple")]
        [Authorize]
        public async Task<IActionResult> UploadMultiple([FromForm] List<IFormFile> files)
        {
            var userId = GetUserId();
            if (userId == null)
                return Unauthorized();

            if (files == null || !files.Any())
                return BadRequest("No files provided.");

            var results = new List<object>();

            foreach (var file in files)
            {
                try
                {
                    var relativePath = await _fileUploadHelper.UploadFileAsync(file);

                    var fileRecord = new UserFile
                    {
                        FilePath = relativePath,
                        UploadedAt = DateTime.UtcNow,
                        UserId = userId.Value
                    };

                    _context.UserFiles.Add(fileRecord);
                    results.Add(new { file = file.FileName, path = relativePath });
                }
                catch (ArgumentException ex)
                {
                    results.Add(new { file = file.FileName, error = ex.Message });
                }
            }

            await _context.SaveChangesAsync();
            return Ok(results);
        }

        [HttpGet("AllFiles")]
        [Authorize(Roles = "SuperAdmin")]
        public async Task<IActionResult> GetAllFiles(
             [FromQuery] int page = 1,
             [FromQuery] int pageSize = 10,
             [FromQuery] string? username = null,
             [FromQuery] DateTime? date = null,
             [FromQuery] string? extension = null)
        {
            var query = _context.UserFiles
                .Include(f => f.User)
                .AsQueryable();

            
            if (!string.IsNullOrWhiteSpace(username))
            {
                query = query.Where(f => f.User.Username.Contains(username));
            }

            if (date.HasValue)
            {
                var startDate = date.Value.Date;
                var endDate = startDate.AddDays(1);
                query = query.Where(f => f.UploadedAt >= startDate && f.UploadedAt < endDate);
            }

            if (!string.IsNullOrWhiteSpace(extension))
            {
                var ext = extension.StartsWith(".") ? extension.ToLower() : "." + extension.ToLower();
                query = query.Where(f => f.FilePath.EndsWith(ext));
            }

            var totalCount = await query.CountAsync();

            var files = await query
                .OrderByDescending(f => f.UploadedAt)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(f => new
                {
                    f.Id,
                    f.FilePath,
                    f.UploadedAt,
                    f.UserId,
                    Username = f.User.Username
                })
                .ToListAsync();

            return Ok(new
            {
                currentPage = page,
                pageSize,
                totalCount,
                totalPages = (int)Math.Ceiling(totalCount / (double)pageSize),
                files
            });
        }


        [HttpGet("user/{userId}/files")]
        [Authorize]
        public async Task<IActionResult> GetUserFiles(Guid userId)
        {
            var files = await _context.UserFiles
                .Where(f => f.UserId == userId)
                .Select(f => new {
                    f.Id,
                    f.FilePath,
                    f.UploadedAt
                })
                .ToListAsync();

            return Ok(files);
        }

        [HttpGet("download/{id}")]
        [Authorize]
        public async Task<IActionResult> Download(Guid id)
        {
            var file = await _context.UserFiles.FindAsync(id);
            if (file == null)
                return NotFound();

            var fullPath = Path.Combine(_env.WebRootPath ?? Path.Combine(_env.ContentRootPath, "wwwroot"), file.FilePath);
            if (!System.IO.File.Exists(fullPath))
                return NotFound("File not found on disk.");

            var mime = GetMimeType(fullPath);
            var bytes = await System.IO.File.ReadAllBytesAsync(fullPath);
            return File(bytes, mime, Path.GetFileName(fullPath));
        }

        [HttpDelete("delete/{id}")]
        [Authorize]
        public async Task<IActionResult> Delete(Guid id)
        {
            var userId = GetUserId();
            if (userId == null)
                return Unauthorized();

            var file = await _context.UserFiles.FirstOrDefaultAsync(f => f.Id == id && f.UserId == userId);
            if (file == null)
                return NotFound("File not found or not owned by user.");

            var fullPath = Path.Combine(_env.WebRootPath ?? Path.Combine(_env.ContentRootPath, "wwwroot"), file.FilePath);
            if (System.IO.File.Exists(fullPath))
                System.IO.File.Delete(fullPath);

            _context.UserFiles.Remove(file);
            await _context.SaveChangesAsync();

            return NoContent();
        }



        private string GetMimeType(string filePath)
        {
            var provider = new Microsoft.AspNetCore.StaticFiles.FileExtensionContentTypeProvider();
            if (!provider.TryGetContentType(filePath, out string contentType))
            {
                contentType = "application/octet-stream";
            }
            return contentType;
        }
        private Guid? GetUserId()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            return Guid.TryParse(userId, out var parsed) ? parsed : null;
        }


    }
}
