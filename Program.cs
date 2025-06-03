using DyanamicsAPI.Data;
using DyanamicsAPI.DTOs;
using DyanamicsAPI.Helpers;
using DyanamicsAPI.Middleware;
using DyanamicsAPI.Services;
using FluentValidation;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Serilog;
using System.Security.Claims;
using System.Text;
using System.Threading.RateLimiting;


var logger = new LoggerConfiguration()
    .WriteTo.File("Logs/log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();
Log.Logger = logger;

var builder = WebApplication.CreateBuilder(args);

// new call 
builder.Services.AddControllers();
builder.Services.AddFluentValidationAutoValidation();
builder.Services.AddFluentValidationClientsideAdapters();
builder.Services.AddValidatorsFromAssemblyContaining<Program>();

// DB Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// DI
builder.Services.AddScoped<DbSeeder>();
builder.Services.AddScoped<AuthService>();
builder.Services.AddScoped<IValidator<AddUserRequestDto>, AddUserRequestValidator>();
builder.Services.AddScoped<IValidator<UpdateUserRequestDto>, UpdateUserRequestValidator>();
builder.Services.AddScoped<IValidator<ChangePasswordDto>, ChangePasswordValidator>();

    builder.Services.AddSingleton(new FileUploadHelper(
    maxFileSize: 10*1024 * 1024,
    permittedExtensions: new[] { ".jpg", ".png", ".pdf", ".zip" },
    targetFilePath: Path.Combine(builder.Environment.ContentRootPath, "wwwroot/Uploads")
));


builder.Services.AddEndpointsApiExplorer();
builder.Services.AddAuthorization();
builder.Host.UseSerilog(logger);





// Configure Kestrel for HTTP/2 and HTTPS => docker 

//builder.WebHost.ConfigureKestrel(options =>
//{
//    options.ListenAnyIP(8080);
//    options.ListenAnyIP(8081, listenOptions =>
//    {
//        listenOptions.UseHttps("/https/devcert.pfx", "P@ssw0rd");
//    });
//});

//// bypass docker proxy
//builder.Services.Configure<ForwardedHeadersOptions>(options =>
//{
//    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto;
//});



// Swagger Auth
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Dyanamics API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter your token",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Id = "Bearer",
                    Type = ReferenceType.SecurityScheme
                }
            },
            Array.Empty<string>()
        }
    });
    c.AddSecurityDefinition("cookieAuth", new OpenApiSecurityScheme
    {
        Type = SecuritySchemeType.ApiKey,
        In = ParameterLocation.Cookie,
        Name = "refreshToken",
        Description = "Refresh token in cookie"
    });
});


// JWT Auth
var secretKey = builder.Configuration["JwtSettings:SecretKey"]!;
var keyBytes = Encoding.UTF8.GetBytes(secretKey); // Changed from Base64 decode

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            ValidateLifetime = true,
            IssuerSigningKey = new SymmetricSecurityKey(keyBytes), // Use UTF8 bytes directly
            ValidateIssuerSigningKey = true
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = async context =>
            {
                var jti = context.Principal.FindFirstValue(JwtRegisteredClaimNames.Jti);
                var dbContext = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();

                var isBlacklisted = await dbContext.BlacklistedTokens
                    .AnyAsync(t => t.Jti == jti && t.Expiry > DateTime.UtcNow);

                if (isBlacklisted)
                    context.Fail("Token revoked");
            }
        };
    });


builder.Services.AddCors(options =>
{
    options.AddPolicy("TrustedLocalOrigins", policy =>
    {
        policy
            .WithOrigins("http://localhost:4200", "https://localhost:4200")
            .AllowAnyHeader()
            .AllowAnyMethod()
            .AllowCredentials(); 
    });
});


builder.Services.AddRateLimiter(options =>
{
    options.AddSlidingWindowLimiter("api", limiter =>
    {
        limiter.Window = TimeSpan.FromSeconds(10);
        limiter.PermitLimit = 5;
        limiter.SegmentsPerWindow = 2;
        limiter.QueueProcessingOrder = QueueProcessingOrder.OldestFirst; 
        limiter.QueueLimit = 2;
    });
});

var app = builder.Build();

// Seed data
using (var scope = app.Services.CreateScope())
{
    var seeder = scope.ServiceProvider.GetRequiredService<DbSeeder>();
    await seeder.SeedSuperAdminAsync();
}

// Middleware
app.UseSwagger();
app.UseSwaggerUI();
app.UseHttpsRedirection();
app.UseCors("TrustedLocalOrigins");

app.MapGet("/", () => "CORS with credentials for localhost only");
app.UseAuthentication();
app.UseAuthorization();
app.UseMiddleware<RequestResponseLoggingMiddleware>();
app.UseForwardedHeaders();

app.UseRateLimiter();
app.MapControllers();
app.Run();
