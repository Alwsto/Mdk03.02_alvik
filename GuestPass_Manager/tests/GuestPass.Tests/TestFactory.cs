using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text.Encodings.Web;
using GuestPass.Api;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace GuestPass.Tests;

public sealed class FrozenClock : TimeProvider
{
    public static readonly DateTimeOffset Now = new(2030, 1, 1, 12, 0, 0, TimeSpan.Zero);
    public override DateTimeOffset GetUtcNow() => Now;
}

public sealed class TestFactory(bool testAuthentication = true, bool failAudit = false, int rateLimit = 60)
    : WebApplicationFactory<Program>
{
    private readonly string databasePath = Path.Combine(Path.GetTempPath(), $"guestpass-tests-{Guid.NewGuid():N}.db");
    public byte[] JwtKey { get; } = RandomNumberGenerator.GetBytes(32);
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.ConfigureAppConfiguration((_, configuration) => configuration.AddInMemoryCollection(
            new Dictionary<string, string?>
            {
                ["ConnectionStrings:GuestPass"] = $"Data Source={databasePath};Pooling=False",
                ["Jwt:Issuer"] = "test-issuer", ["Jwt:Audience"] = "test-audience",
                ["Jwt:SigningKeyBase64"] = Convert.ToBase64String(JwtKey),
                ["Audit:HashKeyBase64"] = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
                ["RateLimit:PermitLimit"] = rateLimit.ToString(), ["RateLimit:WindowSeconds"] = "60"
            }));
        builder.ConfigureTestServices(services =>
        {
            services.RemoveAll<TimeProvider>();
            services.AddSingleton<TimeProvider, FrozenClock>();
            if (failAudit) { services.RemoveAll<IAuditWriter>(); services.AddScoped<IAuditWriter, FailingAuditWriter>(); }
            if (testAuthentication)
                services.AddAuthentication(options =>
                {
                    options.DefaultAuthenticateScheme = "Test";
                    options.DefaultChallengeScheme = "Test";
                    options.DefaultForbidScheme = "Test";
                }).AddScheme<AuthenticationSchemeOptions, TestAuthHandler>("Test", _ => { });
        });
    }

    public HttpClient Client(string? user = "owner", string role = "Employee")
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
        if (user is not null) { client.DefaultRequestHeaders.Add("X-Test-User", user); client.DefaultRequestHeaders.Add("X-Test-Role", role); }
        return client;
    }

    public async Task<int> SeedAsync(string owner = "owner")
    {
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<PassDbContext>();
        var pass = new GuestPass.Api.GuestPass
        {
            OwnerId = owner, GuestName = "Тестовый гость", ValidFromUtc = FrozenClock.Now,
            ValidUntilUtc = FrozenClock.Now.AddDays(1)
        };
        db.Passes.Add(pass);
        await db.SaveChangesAsync();
        return pass.Id;
    }

    public async Task<List<AuditEvent>> AuditAsync()
    {
        using var scope = Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<PassDbContext>().AuditEvents.AsNoTracking().ToListAsync();
    }

    public async Task<int> PassCountAsync()
    {
        using var scope = Services.CreateScope();
        return await scope.ServiceProvider.GetRequiredService<PassDbContext>().Passes.CountAsync();
    }

    public string Token(string? subject = "owner", string role = "Employee", string issuer = "test-issuer",
        string audience = "test-audience", bool expired = false, bool wrongKey = false)
    {
        var claims = new List<Claim> { new("role", role) };
        if (subject is not null) claims.Add(new Claim("sub", subject));
        var key = wrongKey ? RandomNumberGenerator.GetBytes(32) : JwtKey;
        return new JwtSecurityTokenHandler().WriteToken(new JwtSecurityToken(issuer, audience, claims,
            DateTime.UtcNow.AddHours(-2), expired ? DateTime.UtcNow.AddHours(-1) : DateTime.UtcNow.AddMinutes(10),
            new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)));
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && File.Exists(databasePath)) File.Delete(databasePath);
    }
}

public sealed class FailingAuditWriter : IAuditWriter
{
    public Task AppendAsync(AuditEvent entry) => throw new IOException("Injected audit failure");
}

public sealed class TestAuthHandler(IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory logger, UrlEncoder encoder) : AuthenticationHandler<AuthenticationSchemeOptions>(options, logger, encoder)
{
    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        if (!Request.Headers.TryGetValue("X-Test-User", out var user)) return Task.FromResult(AuthenticateResult.NoResult());
        var claims = new[] { new Claim("sub", user.ToString()), new Claim("role", Request.Headers["X-Test-Role"].ToString()) };
        var identity = new ClaimsIdentity(claims, Scheme.Name, "sub", "role");
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity), Scheme.Name)));
    }
}
