using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;

namespace DyanamicsAPI.Middleware
{
    public class RequestResponseLoggingMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<RequestResponseLoggingMiddleware> _logger;
        private const int MaxLoggableBodyLength = 4096; // 4KB

        public RequestResponseLoggingMiddleware(
            RequestDelegate next,
            ILogger<RequestResponseLoggingMiddleware> logger)
        {
            _next = next;
            _logger = logger;
        }

        public async Task Invoke(HttpContext context)
        {
            // Skip logging for specific paths
            if (ShouldSkipLogging(context))
            {
                await _next(context);
                return;
            }

            // Log request
            var requestLog = await FormatRequest(context.Request);
            _logger.LogInformation($"Request: {requestLog}");

            // Capture original response body stream
            var originalBodyStream = context.Response.Body;

            try
            {
                using var memoryStream = new MemoryStream();
                context.Response.Body = memoryStream;

                await _next(context);

                // Log response
                var responseLog = await FormatResponse(context.Response, memoryStream);
                _logger.LogInformation($"Response: {responseLog}");

                // Copy memory stream to original stream
                memoryStream.Seek(0, SeekOrigin.Begin);
                await memoryStream.CopyToAsync(originalBodyStream);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error processing request");
                throw;
            }
            finally
            {
                context.Response.Body = originalBodyStream;
            }
        }

        private bool ShouldSkipLogging(HttpContext context)
        {
            var path = context.Request.Path.Value ?? string.Empty;
            return path.StartsWith("/swagger", StringComparison.OrdinalIgnoreCase) ||
                   path.StartsWith("/health", StringComparison.OrdinalIgnoreCase);
        }

        private async Task<string> FormatRequest(HttpRequest request)
        {
            var body = await GetRequestBody(request);
            return $"{request.Method} {request.Path}{request.QueryString} | " +
                   $"Headers: {FormatHeaders(request.Headers)} | " +
                   $"Body: {Truncate(body, MaxLoggableBodyLength)}";
        }

        private async Task<string> FormatResponse(HttpResponse response, MemoryStream memoryStream)
        {
            var body = await GetResponseBody(response, memoryStream);
            return $"{response.StatusCode} | " +
                   $"Headers: {FormatHeaders(response.Headers)} | " +
                   $"Body: {Truncate(body, MaxLoggableBodyLength)}";
        }

        private async Task<string> GetRequestBody(HttpRequest request)
        {
            if (!request.Body.CanSeek)
                return "[non-readable-stream]";

            try
            {
                request.EnableBuffering();
                var buffer = new byte[Convert.ToInt32(request.ContentLength ?? 0)];
                await request.Body.ReadAsync(buffer);
                request.Body.Seek(0, SeekOrigin.Begin);
                return Encoding.UTF8.GetString(buffer);
            }
            catch
            {
                return "[error-reading-body]";
            }
        }

        private async Task<string> GetResponseBody(HttpResponse response, MemoryStream memoryStream)
        {
            try
            {
                memoryStream.Seek(0, SeekOrigin.Begin);
                var body = await new StreamReader(memoryStream).ReadToEndAsync();
                return body;
            }
            catch
            {
                return "[error-reading-body]";
            }
        }

        private static string FormatHeaders(IHeaderDictionary headers)
        {
            var sb = new StringBuilder();
            foreach (var (key, value) in headers)
            {
                sb.Append($"{key}: {string.Join(",", value)}; ");
            }
            return sb.ToString();
        }

        private static string Truncate(string value, int maxLength)
        {
            return value?.Length > maxLength
                ? value[..maxLength] + "...[TRUNCATED]"
                : value ?? "[null]";
        }
    }
}