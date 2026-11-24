param([string]$Subject = 'employee-001', [ValidateSet('Employee','Guard','Visitor')][string]$Role = 'Employee')
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($env:Jwt__SigningKeyBase64)) { throw 'Set Jwt__SigningKeyBase64 first.' }
function ConvertTo-Base64Url([byte[]]$Bytes) {
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+','-').Replace('/','_')
}
$now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$header = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes('{"alg":"HS256","typ":"JWT"}'))
$payloadJson = @{sub=$Subject;role=$Role;iss='GuestPass.Local';aud='GuestPass.Api';iat=$now;nbf=$now;exp=$now+900} | ConvertTo-Json -Compress
$payload = ConvertTo-Base64Url ([Text.Encoding]::UTF8.GetBytes($payloadJson))
$hmac = [Security.Cryptography.HMACSHA256]::new([Convert]::FromBase64String($env:Jwt__SigningKeyBase64))
try { $signature = ConvertTo-Base64Url ($hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes("$header.$payload"))) }
finally { $hmac.Dispose() }
"$header.$payload.$signature"
