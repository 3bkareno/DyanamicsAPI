using DyanamicsAPI.Data;
using DyanamicsAPI.Services;
using FluentValidation.AspNetCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// DB Context
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// DI
builder.Services.AddScoped<DbSeeder>();
builder.Services.AddScoped<AuthService>();

builder.Services.AddControllers()
    .AddFluentValidation(fv => fv.RegisterValidatorsFromAssemblyContaining<Program>());

builder.Services.AddEndpointsApiExplorer();

// Swagger Auth
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Dyanamics API", Version = "v1" });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Enter 'Bearer' followed by your token",
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
});


// JWT Auth
var secretKey = builder.Configuration["JwtSettings:SecretKey"] ?? "1MK9x9sezBwBTWc+c2iqme5Ult/WZMSE2XoWfRJLrWA=";
var keyBytes = Convert.FromBase64String(secretKey);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        var key = Convert.FromBase64String(builder.Configuration["JwtSettings:SecretKey"]!);

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["JwtSettings:Issuer"],
            ValidAudience = builder.Configuration["JwtSettings:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(key),
            RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
            // 🔧 Increase clock skew to avoid time sync issues
            ClockSkew = TimeSpan.FromMinutes(5),
        };

        // 🔍 Log token validation results
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                Console.WriteLine("📥 Token received:");
                Console.WriteLine(context.Request.Headers["Authorization"]);
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine("❌ Authentication failed!");
                Console.WriteLine($"Exception: {context.Exception.GetType().Name}");
                Console.WriteLine($"Message: {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("✅ Token successfully validated!");
                Console.WriteLine("Claims:");
                foreach (var claim in context.Principal!.Claims)
                {
                    Console.WriteLine($" - {claim.Type}: {claim.Value}");
                }
                return Task.CompletedTask;
            },
            OnChallenge = context =>
            {
                Console.WriteLine("⚠️ JWT Challenge triggered.");
                Console.WriteLine($"Error: {context.Error}");
                Console.WriteLine($"Description: {context.ErrorDescription}");
                if (context.AuthenticateFailure != null)
                {
                    Console.WriteLine($"Failure: {context.AuthenticateFailure.Message}");
                }
                return Task.CompletedTask;
            }
        };
    });


builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.AllowAnyHeader().AllowAnyMethod().SetIsOriginAllowed(_ => true);
        // Do NOT use AllowCredentials with wildcard origin
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
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();
app.Run();
