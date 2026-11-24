using System.Security.Claims;
using FluentValidation;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace GuestPass.Api;

/// <summary>HTTP-контракт выдачи и чтения гостевых пропусков.</summary>
[ApiController]
[Route("api/passes")]
public sealed class PassesController(PassService service, IValidator<CreatePassRequest> validator) : ControllerBase
{
    /// <summary>Чтение доступно владельцу пропуска и сотруднику охраны.</summary>
    [HttpGet("{id:int:min(1)}")]
    [Authorize(Policy = "PassRead")]
    public async Task<ActionResult<PassResponse>> Get(int id, CancellationToken token)
    {
        var result = await service.ReadAsync(id, User, token);
        return result.Outcome switch
        {
            ReadOutcome.NotFound => NotFound(),
            ReadOutcome.Forbidden => Forbid(),
            _ => Ok(result.Pass)
        };
    }

    /// <summary>Создает пропуск от имени аутентифицированного сотрудника.</summary>
    [HttpPost]
    [Authorize(Policy = "PassCreate")]
    public async Task<ActionResult<PassResponse>> Create(CreatePassRequest request, CancellationToken token)
    {
        var validation = await validator.ValidateAsync(request, token);
        if (!validation.IsValid) return BadRequest(new ValidationProblemDetails(validation.ToDictionary()));
        var pass = await service.CreateAsync(request, User.FindFirstValue("sub")!, token);
        HttpContext.Items["CreatedPassId"] = pass.Id;
        return CreatedAtAction(nameof(Get), new { id = pass.Id }, pass);
    }
}
