using FluentValidation;
using Microsoft.EntityFrameworkCore;

namespace GuestPass.Api;

/// <summary>Гостевой пропуск; владельца назначает сервер из проверенного JWT.</summary>
public sealed class GuestPass
{
    public int Id { get; set; }
    public required string OwnerId { get; set; }
    public required string GuestName { get; set; }
    public DateTimeOffset ValidFromUtc { get; set; }
    public DateTimeOffset ValidUntilUtc { get; set; }
}

/// <summary>Входные поля; OwnerId и роли намеренно не принимаются от клиента.</summary>
public sealed record CreatePassRequest(string GuestName, DateTimeOffset ValidFromUtc, DateTimeOffset ValidUntilUtc);
/// <summary>Разрешенное представление пропуска без внутреннего идентификатора владельца.</summary>
public sealed record PassResponse(int Id, string GuestName, DateTimeOffset ValidFromUtc, DateTimeOffset ValidUntilUtc);

/// <summary>Проверяет имя, UTC и срок пропуска от текущего момента до семи суток.</summary>
public sealed class CreatePassValidator : AbstractValidator<CreatePassRequest>
{
    public CreatePassValidator(TimeProvider clock)
    {
        RuleFor(x => x.GuestName).NotEmpty().MaximumLength(100)
            .Must(name => name is not null && !name.Any(char.IsControl))
            .WithMessage("Имя не должно содержать управляющие символы.");
        RuleFor(x => x.ValidFromUtc).Must(value => value.Offset == TimeSpan.Zero)
            .WithMessage("Начало срока должно быть указано в UTC.")
            .Must(value => value >= clock.GetUtcNow())
            .WithMessage("Начало срока не может быть в прошлом.");
        RuleFor(x => x.ValidUntilUtc).Must(value => value.Offset == TimeSpan.Zero)
            .WithMessage("Конец срока должен быть указан в UTC.")
            .GreaterThan(x => x.ValidFromUtc)
            .Must((request, value) => value - request.ValidFromUtc <= TimeSpan.FromDays(7))
            .WithMessage("Максимальный срок пропуска — 7 суток.");
    }
}

/// <summary>Техническое событие без имени гостя, JWT, IP и тела запроса.</summary>
public sealed class AuditEvent
{
    public long Id { get; set; }
    public DateTimeOffset OccurredAtUtc { get; set; }
    public required string ActorRef { get; set; }
    public required string Action { get; set; }
    public int? PassId { get; set; }
    public int StatusCode { get; set; }
    public required string Outcome { get; set; }
    public required string TraceId { get; set; }
}

/// <summary>Одна SQLite БД для атомарной записи пропуска и аудита.</summary>
public sealed class PassDbContext(DbContextOptions<PassDbContext> options) : DbContext(options)
{
    public DbSet<GuestPass> Passes => Set<GuestPass>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    protected override void OnModelCreating(ModelBuilder model)
    {
        model.Entity<GuestPass>().Property(x => x.GuestName).HasMaxLength(100);
        model.Entity<GuestPass>().HasIndex(x => x.OwnerId);
        model.Entity<AuditEvent>().HasIndex(x => x.OccurredAtUtc);
    }
}
