using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace GuestPass.Api;

/// <summary>Контракт постоянного хранилища технических событий.</summary>
public interface IAuditWriter
{
    /// <summary>Добавляет событие в текущую транзакцию запроса.</summary>
    Task AppendAsync(AuditEvent entry);
}

/// <summary>Запись сохраняется внутри транзакции запроса и не зависит от отключения клиента.</summary>
public sealed class AuditWriter(PassDbContext db) : IAuditWriter
{
    /// <summary>Сохраняет событие без использования токена отключившегося клиента.</summary>
    public async Task AppendAsync(AuditEvent entry)
    {
        db.AuditEvents.Add(entry);
        await db.SaveChangesAsync(CancellationToken.None);
    }
}

/// <summary>Не выпускает ответ до записи аудита; сбой приводит к откату и 503.</summary>
public sealed class AuditMiddleware(RequestDelegate next, ILogger<AuditMiddleware> logger)
{
    /// <summary>Атомарно фиксирует бизнес-операцию и аудит до выдачи HTTP-ответа.</summary>
    public async Task InvokeAsync(HttpContext context, PassDbContext db, IAuditWriter writer,
        SecuritySettings settings, TimeProvider clock)
    {
        var originalBody = context.Response.Body;
        await using var buffer = new MemoryStream();
        context.Response.Body = buffer;
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(CancellationToken.None);
            try
            {
                await next(context);
                await writer.AppendAsync(CreateEntry(context, settings, clock));
                await transaction.CommitAsync(CancellationToken.None);
            }
            catch
            {
                await transaction.RollbackAsync(CancellationToken.None);
                throw;
            }
        }
        catch
        {
            // Аварийный канал содержит только технический TraceId. В production нужен внешний сборщик.
            logger.LogCritical("RequestOrAuditFailure TraceId={TraceId} StatusCode={StatusCode}",
                context.TraceIdentifier, StatusCodes.Status503ServiceUnavailable);
            buffer.SetLength(0);
            context.Response.Clear();
            context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
            context.Response.ContentType = "application/problem+json";
            await context.Response.WriteAsync("{\"title\":\"Service temporarily unavailable\",\"status\":503}");
        }
        finally { context.Response.Body = originalBody; }
        buffer.Position = 0;
        await buffer.CopyToAsync(originalBody, CancellationToken.None);
    }

    private static AuditEvent CreateEntry(HttpContext context, SecuritySettings settings, TimeProvider clock)
    {
        var subject = context.User.Identity?.IsAuthenticated == true ? context.User.FindFirstValue("sub") : null;
        var actor = subject is null ? "anonymous" : Convert.ToHexString(
            HMACSHA256.HashData(settings.AuditKey, Encoding.UTF8.GetBytes(subject)));
        int? passId = context.Items["CreatedPassId"] as int?;
        if (passId is null && int.TryParse(context.Request.RouteValues["id"]?.ToString(), out var id)) passId = id;
        int status = context.Response.StatusCode;
        return new AuditEvent
        {
            OccurredAtUtc = clock.GetUtcNow(), ActorRef = actor,
            Action = context.GetEndpoint()?.DisplayName is null ? "unmatched" : context.Request.Method,
            PassId = passId, StatusCode = status,
            Outcome = status < 400 ? "allowed" : status < 500 ? "denied" : "error",
            TraceId = context.TraceIdentifier
        };
    }
}
