# Build-time check: compiles the NightSend v2 crypto exactly as the app does and runs a full
# handshake + encrypted transfer over loopback. Prints OK or FAIL and sets the exit code.
$src = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot "NightSend.ps1")
$m = [regex]::Match($src, "(?s)//CS-BEGIN\r?\n(.*?)//CS-END")
if (-not $m.Success) { Write-Host "FAIL: crypto source not found"; exit 1 }
Add-Type -AssemblyName System.Security
Add-Type -ReferencedAssemblies System.Core -TypeDefinition $m.Groups[1].Value
$r = [NsCrypto]::SelfTest()
Write-Host $r
if ($r -ne "OK") { exit 1 }
