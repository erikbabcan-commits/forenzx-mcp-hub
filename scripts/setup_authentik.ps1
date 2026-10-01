# ForenZX MCP Hub - Authentik Automated Setup (PowerShell)
# Generates high-entropy secrets and initializes Authentik environment

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  ForenZX MCP Hub - Authentik IdP Provisioning Assistant  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$EnvFile = ".env.authentik"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = Split-Path -Parent $ScriptDir

Set-Location $ProjectDir

# Ensure directories exist
$Dirs = @("authentik/media", "authentik/custom-templates", "authentik/blueprints")
foreach ($dir in $Dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "[+] Created directory: $dir" -ForegroundColor Green
    }
}

if (-not (Test-Path $EnvFile)) {
    Write-Host "[*] Generating high-entropy cryptographic secrets..." -ForegroundColor Yellow
    
    $SecretKey = python -c "import secrets; print(secrets.token_urlsafe(50))"
    $DbPassword = python -c "import secrets; print(secrets.token_urlsafe(32))"
    $ClientSecret = python -c "import secrets; print(secrets.token_urlsafe(48))"

    $EnvContent = @"
# ForenZX MCP Hub - Auto-generated Authentik Configuration
AUTHENTIK_SECRET_KEY=$SecretKey
AUTHENTIK_POSTGRESQL_USER=authentik
AUTHENTIK_POSTGRESQL_NAME=authentik
AUTHENTIK_POSTGRESQL_PASSWORD=$DbPassword
AUTHENTIK_FORENZX_CLIENT_SECRET=$ClientSecret
AUTHENTIK_PORT_HTTP=9000
AUTHENTIK_PORT_HTTPS=9443
"@

    Set-Content -Path $EnvFile -Value $EnvContent -Encoding UTF8
    Write-Host "[+] Generated $EnvFile successfully with strong secrets!" -ForegroundColor Green
} else {
    Write-Host "[i] Existing $EnvFile found. Skipping secret generation." -ForegroundColor Gray
}

Write-Host "`n[+] Setup completed successfully!" -ForegroundColor Green
Write-Host "`nTo start ForenZX MCP Hub with Authentik Identity Provider, run:" -ForegroundColor White
Write-Host "  docker compose -f docker-compose.yml -f docker-compose.authentik.yml --env-file .env --env-file .env.authentik up -d" -ForegroundColor Yellow
Write-Host "`nInitial Authentik Admin Setup URL:" -ForegroundColor White
Write-Host "  http://localhost:9000/if/flow/initial-setup/" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
