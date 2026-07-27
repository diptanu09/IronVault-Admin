# IronVault mTLS Certificate Generator
#
# Generates:
#   certs/generated/
#       ca.crt
#       ca.key
#       command_center.crt
#       command_center.key
#       node-01.crt
#       node-01.key
#
# Requires:
#   OpenSSL installed and available on PATH
#
# Run:
#   powershell -ExecutionPolicy Bypass -File generate-certs.ps1

param(
    [string]$OutDir = ".\certs\generated",

    # Hostname of your Command Center
    [string]$CommandCenterCn = "ironvault-command-center",

    # Command Center IP
    [string]$CommandCenterIP = "10.47.240.169",

    # Edge Nodes
    [string[]]$NodeNames = @("node-01"),

    [int]$ValidityDays = 365
)

$ErrorActionPreference = "Stop"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Set-Location $OutDir

Write-Host ""
Write-Host "======================================" -ForegroundColor Cyan
Write-Host " IronVault Certificate Generator"
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

##########################################################
# Generate CA
##########################################################

if (!(Test-Path "ca.key")) {
    Write-Host "Generating Certificate Authority..."

    openssl genrsa -out ca.key 4096

    openssl req `
        -new `
        -x509 `
        -days ($ValidityDays * 5) `
        -key ca.key `
        -out ca.crt `
        -subj "/CN=IronVault Internal CA"

    Write-Host "CA generated."
}
else {
    Write-Host "Existing CA found."
}

##########################################################
# Server Certificate Extension
##########################################################

@"
authorityKeyIdentifier=keyid,issuer

basicConstraints=CA:FALSE

keyUsage=digitalSignature,keyEncipherment

extendedKeyUsage=serverAuth

subjectAltName=@alt_names

[alt_names]
DNS.1=$CommandCenterCn
DNS.2=localhost
IP.1=127.0.0.1
IP.2=$CommandCenterIP
"@ | Set-Content server.ext

##########################################################
# Generate Command Center Certificate
##########################################################

Write-Host ""
Write-Host "Generating Command Center Certificate..."

openssl genrsa `
    -out command_center.key `
    2048

openssl req `
    -new `
    -key command_center.key `
    -out command_center.csr `
    -subj "/CN=$CommandCenterCn"

openssl x509 `
    -req `
    -in command_center.csr `
    -CA ca.crt `
    -CAkey ca.key `
    -CAcreateserial `
    -out command_center.crt `
    -days $ValidityDays `
    -sha256 `
    -extfile server.ext

Remove-Item command_center.csr

##########################################################
# Client Certificate Extension
##########################################################

@"
authorityKeyIdentifier=keyid,issuer

basicConstraints=CA:FALSE

keyUsage=digitalSignature,keyEncipherment

extendedKeyUsage=clientAuth
"@ | Set-Content client.ext

##########################################################
# Generate Node Certificates
##########################################################

foreach ($node in $NodeNames) {
    Write-Host ""
    Write-Host "Generating certificate for $node"

    openssl genrsa `
        -out "$node.key" `
        2048

    openssl req `
        -new `
        -key "$node.key" `
        -out "$node.csr" `
        -subj "/CN=$node"

    openssl x509 `
        -req `
        -in "$node.csr" `
        -CA ca.crt `
        -CAkey ca.key `
        -CAcreateserial `
        -out "$node.crt" `
        -days $ValidityDays `
        -sha256 `
        -extfile client.ext

    Remove-Item "$node.csr"
}

##########################################################
# Cleanup
##########################################################

Remove-Item server.ext
Remove-Item client.ext

Write-Host ""
Write-Host "======================================" -ForegroundColor Green
Write-Host "Certificates Generated Successfully"
Write-Host "======================================" -ForegroundColor Green
Write-Host ""

Write-Host "Server:"
Write-Host "  command_center.crt"
Write-Host "  command_center.key"

Write-Host ""

Write-Host "Certificate Authority:"
Write-Host "  ca.crt"
Write-Host "  ca.key"

Write-Host ""

Write-Host "Nodes:"
foreach ($node in $NodeNames) {
    Write-Host "  $node.crt"
    Write-Host "  $node.key"
}

Write-Host ""

Write-Host "Server SAN entries:"
Write-Host "  DNS : $CommandCenterCn"
Write-Host "  DNS : localhost"
Write-Host "  IP  : 127.0.0.1"
Write-Host "  IP  : $CommandCenterIP"

Write-Host ""
Write-Host "Done."