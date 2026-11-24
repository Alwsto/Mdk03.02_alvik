using System.Security.Claims;
using FluentAssertions;
using GuestPass.Api;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace GuestPass.Tests;

public sealed class UnitTests
{
    private static CreatePassRequest Valid() => new("Гость", FrozenClock.Now.AddMinutes(1), FrozenClock.Now.AddDays(1));

    [Theory]
    [InlineData(1, true)]
    [InlineData(100, true)]
    [InlineData(101, false)]
    [InlineData(0, false)]
    public void U01_NameLengthBoundary(int length, bool expected)
    {
        var request = Valid() with { GuestName = new string('А', length) };
        new CreatePassValidator(new FrozenClock()).Validate(request).IsValid.Should().Be(expected);
    }

    [Theory]
    [InlineData("   ")]
    [InlineData("Имя\nподдельный аудит")]
    [InlineData(null)]
    public void U02_InvalidNames(string? name) =>
        new CreatePassValidator(new FrozenClock()).Validate(Valid() with { GuestName = name! }).IsValid.Should().BeFalse();

    [Theory]
    [InlineData(0, false)]
    [InlineData(1, true)]
    [InlineData(604800, true)]
    [InlineData(604801, false)]
    public void U03_DurationBoundary(int seconds, bool expected)
    {
        var start = FrozenClock.Now.AddMinutes(1);
        var request = Valid() with { ValidFromUtc = start, ValidUntilUtc = start.AddSeconds(seconds) };
        new CreatePassValidator(new FrozenClock()).Validate(request).IsValid.Should().Be(expected);
    }

    [Fact]
    public void U04_PastAndNonUtcRejected()
    {
        var validator = new CreatePassValidator(new FrozenClock());
        validator.Validate(Valid() with { ValidFromUtc = FrozenClock.Now.AddSeconds(-1) }).IsValid.Should().BeFalse();
        validator.Validate(Valid() with { ValidFromUtc = FrozenClock.Now.ToOffset(TimeSpan.FromHours(3)) }).IsValid.Should().BeFalse();
    }

    [Theory]
    [InlineData("owner", "Employee", true)]
    [InlineData("other", "Employee", false)]
    [InlineData("other", "Guard", true)]
    public void U05_ObjectAuthorization(string subject, string role, bool allowed)
    {
        var principal = new ClaimsPrincipal(new ClaimsIdentity([new("sub", subject), new("role", role)], "test", "sub", "role"));
        var pass = new GuestPass.Api.GuestPass { OwnerId = "owner", GuestName = "Гость" };
        PassAccess.CanRead(principal, pass).Should().Be(allowed);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("not-base64")]
    [InlineData("YWJj")]
    public void U06_MissingInvalidOrShortKeyRejected(string? key)
    {
        var config = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            { ["Jwt:SigningKeyBase64"] = key }).Build();
        Action action = () => SecuritySettings.Read(config);
        action.Should().Throw<InvalidOperationException>();
    }
}
