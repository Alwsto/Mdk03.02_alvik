namespace GuestPass.Api;

/// <summary>Секреты читаются из конфигурации, в репозитории отсутствуют.</summary>
public sealed record SecuritySettings(string Issuer, string Audience, byte[] JwtKey, byte[] AuditKey)
{
    /// <summary>Проверяет наличие издателя, аудитории и двух различных ключей минимум 256 бит.</summary>
    public static SecuritySettings Read(IConfiguration configuration)
    {
        string Required(string key) => string.IsNullOrWhiteSpace(configuration[key])
            ? throw new InvalidOperationException($"Missing setting: {key}") : configuration[key]!;
        byte[] Key(string name)
        {
            byte[] bytes;
            try { bytes = Convert.FromBase64String(Required(name)); }
            catch (FormatException) { throw new InvalidOperationException($"Invalid Base64 key: {name}"); }
            if (bytes.Length < 32) throw new InvalidOperationException($"Key must contain at least 32 bytes: {name}");
            return bytes;
        }
        var jwtKey = Key("Jwt:SigningKeyBase64");
        var auditKey = Key("Audit:HashKeyBase64");
        if (jwtKey.SequenceEqual(auditKey)) throw new InvalidOperationException("JWT and audit keys must differ.");
        return new(Required("Jwt:Issuer"), Required("Jwt:Audience"), jwtKey, auditKey);
    }
}
