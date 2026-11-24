using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using FluentAssertions;
using GuestPass.Api;
using Xunit;

namespace GuestPass.Tests;

public sealed class IntegrationTests
{
    private static CreatePassRequest Valid(string name = "Гость") =>
        new(name, FrozenClock.Now.AddMinutes(1), FrozenClock.Now.AddDays(1));

    [Fact]
    public async Task I01_OwnerReadsOwnPassAndAuditIsDurable()
    {
        using var factory = new TestFactory();
        using var client = factory.Client();
        int id = await factory.SeedAsync();
        (await client.GetAsync($"/api/passes/{id}")).StatusCode.Should().Be(HttpStatusCode.OK);
        var audit = (await factory.AuditAsync()).Should().ContainSingle().Subject;
        audit.Outcome.Should().Be("allowed");
        audit.ActorRef.Should().HaveLength(64).And.NotContain("owner");
        audit.PassId.Should().Be(id);
    }

    [Fact]
    public async Task I02_IdorReturns403AndRecordsDenied()
    {
        using var factory = new TestFactory();
        using var client = factory.Client("attacker");
        int id = await factory.SeedAsync();
        var response = await client.GetAsync($"/api/passes/{id}");
        response.StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await response.Content.ReadAsStringAsync()).Should().NotContain("Тестовый гость");
        (await factory.AuditAsync()).Should().ContainSingle(x => x.StatusCode == 403 && x.Outcome == "denied");
    }

    [Fact]
    public async Task I03_GuardReadsOtherPass()
    {
        using var factory = new TestFactory();
        using var client = factory.Client("guard", "Guard");
        int id = await factory.SeedAsync();
        (await client.GetAsync($"/api/passes/{id}")).StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task I04_AnonymousRequest401IsAudited()
    {
        using var factory = new TestFactory();
        using var client = factory.Client(null);
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await factory.AuditAsync()).Should().ContainSingle(x => x.ActorRef == "anonymous" && x.StatusCode == 401);
    }

    [Fact]
    public async Task I05_MissingPass404()
    {
        using var factory = new TestFactory();
        using var client = factory.Client();
        (await client.GetAsync("/api/passes/999")).StatusCode.Should().Be(HttpStatusCode.NotFound);
    }

    [Fact]
    public async Task I06_Create201AndReadRoundtrip()
    {
        using var factory = new TestFactory();
        using var client = factory.Client();
        var response = await client.PostAsJsonAsync("/api/passes", Valid());
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        response.Headers.Location.Should().NotBeNull();
        (await client.GetAsync(response.Headers.Location)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await factory.AuditAsync()).Should().HaveCount(2);
    }

    [Fact]
    public async Task I07_VisitorCannotCreate()
    {
        using var factory = new TestFactory();
        using var client = factory.Client("visitor", "Visitor");
        (await client.PostAsJsonAsync("/api/passes", Valid())).StatusCode.Should().Be(HttpStatusCode.Forbidden);
        (await factory.PassCountAsync()).Should().Be(0);
    }

    [Fact]
    public async Task I08_InvalidInput400AndNoRow()
    {
        using var factory = new TestFactory();
        using var client = factory.Client();
        (await client.PostAsJsonAsync("/api/passes", Valid(" "))).StatusCode.Should().Be(HttpStatusCode.BadRequest);
        (await factory.PassCountAsync()).Should().Be(0);
        (await factory.AuditAsync()).Should().ContainSingle(x => x.StatusCode == 400);
    }

    [Fact]
    public async Task I09_RateLimit429IsAudited()
    {
        using var factory = new TestFactory(rateLimit: 2);
        using var client = factory.Client();
        await client.GetAsync("/api/passes/1");
        await client.GetAsync("/api/passes/1");
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await factory.AuditAsync()).Should().HaveCount(3).And.Contain(x => x.StatusCode == 429);
    }

    [Fact]
    public async Task I10_AuditFailure503RollsBackCreation()
    {
        using var factory = new TestFactory(failAudit: true);
        using var client = factory.Client();
        var response = await client.PostAsJsonAsync("/api/passes", Valid());
        response.StatusCode.Should().Be(HttpStatusCode.ServiceUnavailable);
        (await factory.PassCountAsync()).Should().Be(0);
        (await response.Content.ReadAsStringAsync()).Should().NotContain("Гость");
    }

    [Fact]
    public async Task I11_OwnerSpoofingInJsonHasNoEffect()
    {
        using var factory = new TestFactory();
        using var owner = factory.Client();
        var valid = Valid();
        var response = await owner.PostAsJsonAsync("/api/passes", new
        { valid.GuestName, valid.ValidFromUtc, valid.ValidUntilUtc, OwnerId = "attacker", Role = "Guard" });
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        using var attacker = factory.Client("attacker");
        (await attacker.GetAsync(response.Headers.Location)).StatusCode.Should().Be(HttpStatusCode.Forbidden);
    }

    [Fact]
    public async Task I12_SqlLookingNameIsLiteralData()
    {
        using var factory = new TestFactory();
        using var client = factory.Client();
        const string name = "Гость'; DROP TABLE Passes; --";
        var response = await client.PostAsJsonAsync("/api/passes", Valid(name));
        response.StatusCode.Should().Be(HttpStatusCode.Created);
        var pass = await client.GetFromJsonAsync<PassResponse>(response.Headers.Location);
        pass!.GuestName.Should().Be(name);
        (await factory.PassCountAsync()).Should().Be(1);
    }

    [Theory]
    [InlineData("valid", 200)]
    [InlineData("expired", 401)]
    [InlineData("issuer", 401)]
    [InlineData("audience", 401)]
    [InlineData("signature", 401)]
    [InlineData("subject", 403)]
    [InlineData("empty-subject", 403)]
    public async Task I13_RealBearerValidation(string scenario, int expectedStatus)
    {
        using var factory = new TestFactory(testAuthentication: false);
        using var client = factory.Client(null);
        int id = await factory.SeedAsync();
        string token = factory.Token(subject: scenario == "subject" ? null : scenario == "empty-subject" ? "" : "owner",
            issuer: scenario == "issuer" ? "wrong" : "test-issuer",
            audience: scenario == "audience" ? "wrong" : "test-audience",
            expired: scenario == "expired", wrongKey: scenario == "signature");
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        ((int)(await client.GetAsync($"/api/passes/{id}")).StatusCode).Should().Be(expectedStatus);
        (await factory.AuditAsync()).Should().ContainSingle(x => x.StatusCode == expectedStatus);
    }

    [Fact]
    public async Task I14_TestHeadersCannotBypassRealAuthentication()
    {
        using var factory = new TestFactory(testAuthentication: false);
        using var client = factory.Client("owner", "Guard");
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task I15_AnonymousRateLimitAndAudit()
    {
        using var factory = new TestFactory(rateLimit: 2);
        using var client = factory.Client(null);
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        (await client.GetAsync("/api/passes/1")).StatusCode.Should().Be(HttpStatusCode.TooManyRequests);
        (await factory.AuditAsync()).Should().HaveCount(3).And.OnlyContain(x => x.ActorRef == "anonymous");
    }
}
