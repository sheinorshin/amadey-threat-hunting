# setup-misp.ps1 - start MISP (official misp-docker) for the Amadey threat-hunting project
# Run from PowerShell:
#   powershell -ExecutionPolicy Bypass -File "$HOME\Desktop\amadey-misp\setup-misp.ps1"
# Needs Docker Desktop running. Web UI: https://localhost:8443  (first login: admin@admin.test / admin, then set a new password)
# Windows fixes included (see 01-misp-deployment.md, section 1.5):
#   - docker-compose.override.yml: 15 min healthcheck grace period for misp-core (slow first start on Windows bind mounts)
#   - self-signed certificate in .\ssl (misp-nginx refuses to start without cert.pem/key.pem when BASE_URL is https)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Write-Host "== MISP setup (Amadey threat-hunting project) ==" -ForegroundColor Cyan

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host "Docker is not installed. Install Docker Desktop first:" -ForegroundColor Yellow
    Write-Host "    winget install -e --id Docker.DockerDesktop"
    Write-Host "Then start Docker Desktop, wait for 'Engine running', and run this script again."
    exit 1
}

docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker Desktop is installed but the engine is not running." -ForegroundColor Yellow
    Write-Host "Start Docker Desktop, wait for 'Engine running', then run this script again."
    exit 1
}

$dir = Join-Path $here 'misp-docker'
if (-not (Test-Path (Join-Path $dir 'docker-compose.yml'))) {
    Write-Host "Unpacking misp-docker.zip ..."
    Expand-Archive -Path (Join-Path $here 'misp-docker.zip') -DestinationPath $here -Force
}
Set-Location $dir

# Fix 1: longer healthcheck grace period for misp-core (first start copies the MISP data files
# into the bind-mounted .\files folder, which takes several minutes on Windows)
$override = Join-Path $dir 'docker-compose.override.yml'
if (-not (Test-Path $override)) {
    Write-Host "Writing docker-compose.override.yml (misp-core start_period 900s) ..."
    @(
        'services:',
        '  misp-core:',
        '    healthcheck:',
        "      test: bash -c 'echo > /dev/tcp/127.0.0.1/9002' || exit 1",
        '      interval: 2s',
        '      timeout: 1s',
        '      retries: 3',
        '      start_period: 900s',
        '      start_interval: 5s'
    ) | Set-Content -Path $override -Encoding ascii
}

Write-Host "Pulling images (about 2-3 GB on first run) ..." -ForegroundColor Cyan
docker compose pull
if ($LASTEXITCODE -ne 0) { Write-Host "docker compose pull failed - check your internet connection and run again." -ForegroundColor Red; exit 1 }

# Fix 2: self-signed certificate for https://localhost:8443 (openssl from the misp-core image)
$ssl = Join-Path $dir 'ssl'
if (-not ((Test-Path (Join-Path $ssl 'cert.pem')) -and (Test-Path (Join-Path $ssl 'key.pem')))) {
    New-Item -ItemType Directory -Force -Path $ssl | Out-Null
    Write-Host "Creating a self-signed certificate in .\ssl ..." -ForegroundColor Cyan
    docker run --rm -v "${ssl}:/ssl" --entrypoint openssl ghcr.io/misp/misp-docker/misp-core:latest req -x509 -subj '/CN=localhost' -nodes -newkey rsa:4096 -keyout /ssl/key.pem -out /ssl/cert.pem -days 365 -addext 'subjectAltName = DNS:localhost, IP:127.0.0.1, IP:::1'
    if ($LASTEXITCODE -ne 0) { Write-Host "Certificate creation failed - misp-nginx will not start without .\ssl\cert.pem and key.pem" -ForegroundColor Red; exit 1 }
}

Write-Host "Starting containers (first start takes 5-15 minutes) ..." -ForegroundColor Cyan
docker compose up -d
if ($LASTEXITCODE -ne 0) {
    Write-Host "docker compose up reported an error - checking misp-core status ..." -ForegroundColor Yellow
}

Write-Host "Waiting for misp-core to become healthy " -NoNewline
$deadline = (Get-Date).AddMinutes(20)
$status = ''
do {
    Start-Sleep -Seconds 15
    $id = docker compose ps -q misp-core
    if ($id) { $status = (docker inspect --format '{{.State.Health.Status}}' $id) 2>$null }
    Write-Host "." -NoNewline
} until ($status -eq 'healthy' -or (Get-Date) -gt $deadline)
Write-Host ""

if ($status -eq 'healthy') {
    # starts misp-nginx if it was skipped because misp-core was not healthy yet
    docker compose up -d
}
docker compose ps
if ($status -eq 'healthy') {
    Write-Host ""
    Write-Host "MISP is ready:  https://localhost:8443" -ForegroundColor Green
    Write-Host "Open it in CHROME, accept the self-signed certificate warning,"
    Write-Host "log in with admin@admin.test / admin and set your own new password."
} else {
    Write-Host "MISP is not healthy yet. Wait a few minutes and check with:  docker compose ps" -ForegroundColor Yellow
    Write-Host "Logs:  docker compose logs --tail 50 misp-core"
}
