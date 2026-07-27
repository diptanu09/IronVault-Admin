# IronVault Node/Command-Center mTLS Certificate Setup
#
# Generates:
#   - A local Certificate Authority (ca.crt / ca.key)
#   - A server certificate for the Command Center, signed by the CA
#   - A client certificate for each Edge Node, signed by the CA
#
# Both sides verify the peer's certificate against ca.crt — this is what
# gives each side genuine peer identity, unlike the old shared-AES-key
# scheme where "having the key" was the only proof of identity.
#
# Run as Administrator. Requires openssl on PATH.

param(
    [string]$OutDir = ".\certs\generated",
    [string]$CommandCenterCn = "ironvault-command-center",
    [string[]]$NodeNames = @("node-01"),
    [int]$ValidityDays = 180
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
Set-Location $OutDir

Write-Host "=== Generating IronVault mTLS Certificate Authority ===" -ForegroundColor Cyan

# --- CA ---
if (-not (Test-Path "ca.key")) {
    openssl genrsa -out ca.key 4096
    openssl req -new -x509 -days ($ValidityDays * 4) -key ca.key -out ca.crt `
        -subj "/CN=IronVault-Internal-CA"
    Write-Host "Generated new CA (ca.crt / ca.key)"
} else {
    Write-Host "Existing CA found, reusing it. Delete ca.key/ca.crt to force regeneration." -ForegroundColor Yellow
}

# --- Command Center server cert ---
Write-Host "Generating Command Center server certificate..."
openssl genrsa -out command_center.key 2048
openssl req -new -key command_center.key -out command_center.csr -subj "/CN=$CommandCenterCn"
openssl x509 -req -in command_center.csr -CA ca.crt -CAkey ca.key -CAcreateserial `
    -out command_center.crt -days $ValidityDays
Remove-Item command_center.csr

# --- One client cert per node ---
foreach ($node in $NodeNames) {
    Write-Host "Generating client certificate for node: $node"
    openssl genrsa -out "$node.key" 2048
    openssl req -new -key "$node.key" -out "$node.csr" -subj "/CN=$node"
    openssl x509 -req -in "$node.csr" -CA ca.crt -CAkey ca.key -CAcreateserial `
        -out "$node.crt" -days $ValidityDays
    Remove-Item "$node.csr"
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Green
Write-Host "Command Center needs: ca.crt, command_center.crt, command_center.key"
Write-Host "Each Node needs: ca.crt, <node_name>.crt, <node_name>.key"
Write-Host "Distribute each node's key ONLY to that node — never share one node cert/key across machines."