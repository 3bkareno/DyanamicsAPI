using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace DyanamicsAPI.Helpers
{
    public class FileUploadHelper
    {
        private readonly long _maxFileSize;
        private readonly string[] _permittedExtensions;
        private readonly string _targetFilePath;

        public FileUploadHelper(long maxFileSize, string[] permittedExtensions, string targetFilePath)
        {
            _maxFileSize = maxFileSize;
            _permittedExtensions = permittedExtensions;
            _targetFilePath = targetFilePath;
        }

        public async Task<string> UploadFileAsync(IFormFile formFile)
        {
            string reason;
            if (!ValidateFile(formFile, out reason))
                throw new ArgumentException(reason);

            var dateFolder = DateTime.UtcNow.ToString("yyyy-MM-dd");
            var subfolder = Path.Combine(_targetFilePath, dateFolder);
            Directory.CreateDirectory(subfolder);

            var fileExt = Path.GetExtension(formFile.FileName).ToLowerInvariant();
            var uniqueName = $"{dateFolder}_{Guid.NewGuid()}{fileExt}";
            var fullPath = Path.Combine(subfolder, uniqueName);

            using (var stream = new FileStream(fullPath, FileMode.Create))
            {
                await formFile.CopyToAsync(stream);
            }

            return Path.Combine("Uploads", dateFolder, uniqueName).Replace("\\", "/");
        }

        public bool ValidateFile(IFormFile formFile, out string reason)
        {
            var ext = Path.GetExtension(formFile.FileName).ToLowerInvariant();
            reason = "";

            if (!_permittedExtensions.Contains(ext))
            {
                reason = "File type not permitted.";
                return false;
            }

            if (formFile.Length > _maxFileSize)
            {
                reason = "File size exceeds the allowed limit.";
                return false;
            }

            if (!IsValidSignature(formFile))
            {
                reason = "File signature is invalid or doesn't match its extension.";
                return false;
            }

            if (ContainsMaliciousContent(formFile))
            {
                reason = "File contains potentially malicious content.";
                return false;
            }

            if (IsEncryptedPdf(formFile))
            {
                reason = "Encrypted or password-protected PDFs are not allowed.";
                return false;
            }

            if (IsEncryptedZip(formFile))
            {
                reason = "Encrypted ZIP files are not allowed.";
                return false;
            }

            if (IsSignedExe(formFile))
            {
                reason = "Signed executable files are not allowed.";
                return false;
            }

            return true;
        }

        private bool IsValidSignature(IFormFile file)
        {
            using (var stream = file.OpenReadStream())
            {
                byte[] buffer = new byte[8];
                stream.Seek(0, SeekOrigin.Begin);
                stream.Read(buffer, 0, buffer.Length);

                string hex = BitConverter.ToString(buffer).Replace("-", "").ToLowerInvariant();

                var knownSignatures = new Dictionary<string, string[]>
                {
                    { ".jpg", new[] { "ffd8ff" } },
                    { ".jpeg", new[] { "ffd8ff" } },
                    { ".png", new[] { "89504e47" } },
                    { ".pdf", new[] { "25504446" } },
                    { ".zip", new[] { "504b0304", "504b0506", "504b0708" } },
                    { ".exe", new[] { "4d5a" } } // MZ
                };

                var ext = Path.GetExtension(file.FileName).ToLowerInvariant();
                if (!knownSignatures.ContainsKey(ext)) return false;

                return knownSignatures[ext].Any(sig => hex.StartsWith(sig));
            }
        }

        private bool ContainsMaliciousContent(IFormFile file)
        {
            var pattern = @"<script|<\?|eval\(|exec\(";
            using (var stream = file.OpenReadStream())
            using (var reader = new StreamReader(stream))
            {
                var content = reader.ReadToEnd();
                return Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase);
            }
        }

        private bool IsEncryptedPdf(IFormFile file)
        {
            if (!file.FileName.EndsWith(".pdf", StringComparison.OrdinalIgnoreCase))
                return false;

            using (var stream = file.OpenReadStream())
            using (var reader = new StreamReader(stream))
            {
                var content = reader.ReadToEnd();
                return content.Contains("/Encrypt");
            }
        }

        private bool IsEncryptedZip(IFormFile file)
        {
            if (!file.FileName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                return false;

            using (var stream = file.OpenReadStream())
            {
                byte[] buffer = new byte[30];
                stream.Read(buffer, 0, buffer.Length);

                int flag = buffer[6] | (buffer[7] << 8);
                return (flag & 0x0001) != 0;
            }
        }

        private bool IsSignedExe(IFormFile file)
        {
            if (!file.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                return false;

            try
            {
                using (var ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    var cert = X509Certificate.CreateFromSignedFile(file.FileName);
                    return cert != null;
                }
            }
            catch
            {
                // No certificate or not a signed exe
                return false;
            }
        }
    }
}
