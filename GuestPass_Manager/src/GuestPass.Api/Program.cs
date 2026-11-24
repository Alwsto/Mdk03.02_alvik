using System.Security.Claims;
using System.Threading.RateLimiting;
using FluentValidation;
using GuestPass.Api;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = 16 * 1024);
builder.Logging.ClearProviders().AddJsonConsole();
builder.Services.AddSingleton(services => SecuritySettings.Read(services.GetRequiredService<IConfiguration>()));
builder.Services.AddSingleton(TimeProvider.System);
builder.Services.AddControllers();
builder.Services.AddDbContext<PassDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("GuestPass")));
builder.Services.AddValidatorsFromAssemblyContaining<CreatePassValidator>();
builder.Services.AddScoped<PassService>();
builder.Services.AddScoped<IAuditWriter, AuditWriter>();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer();
builder.Services.AddOptions<JwtBearerOptions>(JwtBearerDefaults.AuthenticationScheme).Configure<SecuritySettings>((options, secrets) =>
{
    options.MapInboundClaims = false;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true, ValidIssuer = secrets.Issuer,
        ValidateAudience = true, ValidAudience = secrets.Audience,
        ValidateLifetime = true, RequireExpirationTime = true,
        ValidateIssuerSigningKey = true, RequireSignedTokens = true,
        IssuerSigningKey = new SymmetricSecurityKey(secrets.JwtKey),
        ValidAlgorithms = [SecurityAlgorithms.HmacSha256],
        ClockSkew = TimeSpan.Zero, NameClaimType = "sub", RoleClaimType = "role"
    };
});
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("PassRead", policy => policy.RequireAuthenticatedUser()
        .RequireAssertion(context => !string.IsNullOrWhiteSpace(context.User.FindFirstValue("sub"))));
    options.AddPolicy("PassCreate", policy => policy.RequireAuthenticatedUser()
        .RequireAssertion(context => !string.IsNullOrWhiteSpace(context.User.FindFirstValue("sub")))
        .RequireRole("Employee", "Guard"));
});
builder.Services.AddRateLimiter(options =>
{
    int permitLimit = builder.Configuration.GetValue<int?>("RateLimit:PermitLimit") ?? 60;
    int windowSeconds = builder.Configuration.GetValue<int?>("RateLimit:WindowSeconds") ?? 60;
    if (permitLimit < 1 || windowSeconds < 1) throw new InvalidOperationException("Invalid rate limit.");
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    options.GlobalLimiter = PartitionedRateLimiter.Create<HttpContext, string>(context =>
        RateLimitPartition.GetFixedWindowLimiter(
            context.User.FindFirstValue("sub") ?? context.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permitLimit, Window = TimeSpan.FromSeconds(windowSeconds),
                QueueLimit = 0, AutoReplenishment = true
            }));
});
var app = builder.Build();
_ = app.Services.GetRequiredService<SecuritySettings>();
using (var scope = app.Services.CreateScope())
    scope.ServiceProvider.GetRequiredService<PassDbContext>().Database.EnsureCreated();
// Аудит оборачивает аутентификацию, ограничения и авторизацию: видны также 401/403/429.
app.UseMiddleware<AuditMiddleware>();
app.UseAuthentication();
app.UseRateLimiter();
app.UseAuthorization();
app.MapControllers();
app.Run();

/// <summary>Точка входа для WebApplicationFactory; тестовая аутентификация здесь отсутствует.</summary>
public partial class Program { }
