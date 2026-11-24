using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace GuestPass.Api;

/// <summary>Решение объектной авторизации после загрузки конкретного пропуска.</summary>
public static class PassAccess
{
    /// <summary>Разрешает чтение только аутентифицированному владельцу либо охраннику.</summary>
    public static bool CanRead(ClaimsPrincipal user, GuestPass pass) =>
        user.Identity?.IsAuthenticated == true &&
        (user.IsInRole("Guard") || user.FindFirstValue("sub") == pass.OwnerId);
}

/// <summary>Результат чтения без зависимости сервиса от HTTP.</summary>
public enum ReadOutcome { Found, NotFound, Forbidden }
/// <summary>Содержит данные только при успешной объектной авторизации.</summary>
public sealed record ReadPassResult(ReadOutcome Outcome, PassResponse? Pass = null);

/// <summary>Хранение и объектная авторизация; строковой конкатенации SQL нет.</summary>
public sealed class PassService(PassDbContext db)
{
    /// <summary>Загружает пропуск параметризованным LINQ-запросом и проверяет доступ к объекту.</summary>
    public async Task<ReadPassResult> ReadAsync(int id, ClaimsPrincipal user, CancellationToken token)
    {
        var pass = await db.Passes.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id, token);
        if (pass is null) return new(ReadOutcome.NotFound);
        if (!PassAccess.CanRead(user, pass)) return new(ReadOutcome.Forbidden);
        return new(ReadOutcome.Found, Map(pass));
    }

    /// <summary>Сохраняет проверенный запрос с владельцем из доверенного контекста пользователя.</summary>
    public async Task<PassResponse> CreateAsync(CreatePassRequest request, string ownerId, CancellationToken token)
    {
        var pass = new GuestPass
        {
            OwnerId = ownerId, GuestName = request.GuestName.Trim(),
            ValidFromUtc = request.ValidFromUtc, ValidUntilUtc = request.ValidUntilUtc
        };
        db.Passes.Add(pass);
        await db.SaveChangesAsync(token);
        return Map(pass);
    }

    private static PassResponse Map(GuestPass pass) =>
        new(pass.Id, pass.GuestName, pass.ValidFromUtc, pass.ValidUntilUtc);
}
