# Запустите через dot-sourcing: . ./scripts/Set-DemoEnvironment.ps1
# Ключи существуют только в окружении текущего процесса PowerShell.
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $jwtBytes = New-Object byte[] 32
    $auditBytes = New-Object byte[] 32
    $rng.GetBytes($jwtBytes)
    $rng.GetBytes($auditBytes)
    $env:Jwt__SigningKeyBase64 = [Convert]::ToBase64String($jwtBytes)
    $env:Audit__HashKeyBase64 = [Convert]::ToBase64String($auditBytes)
} finally { $rng.Dispose() }
$env:ASPNETCORE_URLS = 'http://127.0.0.1:5080'
$env:ASPNETCORE_ENVIRONMENT = 'Development'
Write-Host 'Локальное окружение подготовлено. Ключи не выведены и не сохранены.'
