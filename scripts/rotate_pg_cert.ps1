# IronVault PostgreSQL TLS Certificate Rotation Script
#
# Regenerates the self-signed server certificate used by PostgreSQL, with a
# short validity period, and re-applies locked-down file permissions on the
# private key. Run this on a recurring schedule (recommended: every 90-180
# days) rather than letting a cert sit unrotated for years.
#
# MUST be run as Administrator, on the PostgreSQL server machine, in the
# PostgreSQL data directory.
#
# After running this script:
#   1. Restart the PostgreSQL service for the new cert to take effect.
#   2. Copy the new root.crt to every IronVault client machine's
#      IRONVAULT_DB_SSL_ROOT_CERT path (or your deployment share).
#   3. Confirm certutil -addstore is re-run if you rely on OS-level trust
#      for anything else touching this cert (the IronVault Rust client does
#      NOT need this step — it reads root.crt directly via
#      IRONVAULT_DB_SSL_ROOT_CERT).

param(
    [string]$PgDataDir = "C:\Program Files\PostgreSQL\18\data",
    [string]$ServerIp = "10.47.240.169",
    [int]$ValidityDays = 180,
    [string]$PgServiceAccount = "NETWORK SERVICE"
)

$ErrorActionPreference = "Stop"

Write-Host "=== IronVault Postgres Cert Rotation ===" -ForegroundColor Cyan
Write-Host "Target directory: $PgDataDir"
Write-Host "Validity: $ValidityDays days"
Write-Host ""

if (-not (Test-Path $PgDataDir)) {
    throw "PostgreSQL data directory not found: $PgDataDir"
}

Set-Location $PgDataDir

# --- Back up the existing cert/key before overwriting, timestamped ---
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupDir = Join-Path $PgDataDir "cert_backup_$timestamp"
New-Item -ItemType Directory -Path $backupDir -Force | Out-Null

foreach ($f in @("server.crt", "server.key", "root.crt")) {
    if (Test-Path $f) {
        Copy-Item $f -Destination $backupDir
        Write-Host "Backed up existing $f -> $backupDir"
    }
}

# --- Generate the SAN config ---
$sanConfigPath = Join-Path $PgDataDir "cert_san.cnf"
@"
[req]
prompt=no
distinguished_name=req_dn
req_extensions=v3_req
[req_dn]
CN=$ServerIp
[v3_req]
subjectAltName=@alt_names
[alt_names]
DNS.1=localhost
IP.1=127.0.0.1
IP.2=$ServerIp
"@ | Out-File -FilePath $sanConfigPath -Encoding ascii -NoNewline

# --- Generate the new cert/key ---
Write-Host "Generating new certificate (valid $ValidityDays days)..."
& openssl req -new -x509 -days $ValidityDays -nodes `
    -out server.crt -keyout server.key `
    -config $sanConfigPath -extensions v3_req

if ($LASTEXITCODE -ne 0) {
    throw "openssl certificate generation failed. Check that openssl is on PATH."
}

Copy-Item server.crt root.crt -Force
Remove-Item $sanConfigPath -Force

# --- Lock down the private key ---
Write-Host "Applying restricted permissions to server.key..."
icacls server.key /reset | Out-Null
icacls server.key /inheritance:r | Out-Null
icacls server.key /grant "Administrators:F" | Out-Null
icacls server.key /grant "$PgServiceAccount`:F" | Out-Null
# NOTE: deliberately NOT granting the interactive %USERNAME% read access
# here — the PostgreSQL service account needs the key; an interactively
# logged-in operator running this script does not need standing read
# access to the private key afterward. If you need to inspect it
# immediately after rotation, do so in this same elevated session rather
# than granting a persistent ACL entry.

Write-Host ""
Write-Host "=== Rotation complete ===" -ForegroundColor Green
Write-Host "Old cert/key backed up to: $backupDir"
Write-Host ""
Write-Host "REMAINING MANUAL STEPS:" -ForegroundColor Yellow
Write-Host "  1. Restart the PostgreSQL service now."
Write-Host "  2. Distribute the new root.crt ($PgDataDir\root.crt) to every"
Write-Host "     IronVault client's IRONVAULT_DB_SSL_ROOT_CERT path."
Write-Host "  3. Confirm a test IronVault client connects successfully."
Write-Host "  4. Once confirmed, the backup in $backupDir can be archived/removed."
# Restart the Postgres service
Restart-Service postgresql-x64-18