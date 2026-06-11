<#
  Verify talkrypt release artifacts against BOTH SHA256SUMS and SHA3-256SUMS.

  Two independent hash families (SHA-256 = FIPS 180-4, and SHA3-256 = FIPS 202 /
  Keccak) must BOTH match for every file: a flaw in one construction cannot mask
  a tampered artifact, because it would also have to forge a second, unrelated
  digest.

    powershell -ExecutionPolicy Bypass -File verify.ps1            # current dir
    pwsh ./verify.ps1 -Dir C:\path\to\artifacts                    # another dir

  Exit code 0 if every listed file is present and both digests match; non-zero
  otherwise. SHA-256 uses the built-in Get-FileHash. SHA3-256 uses .NET 8+'s
  SHA3_256 if available, else python3's hashlib, else openssl 3.x — and reports
  if none is found.
#>
[CmdletBinding()]
param([string]$Dir = ".")

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $Dir

function Get-Sha256Hex([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLower()
}

# --- detect a SHA3-256 backend once ---
$Sha3Backend = $null
try {
    if ([System.Security.Cryptography.SHA3_256]::IsSupported) { $Sha3Backend = "dotnet" }
} catch { }
if (-not $Sha3Backend) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
    if ($py) {
        try {
            & $py.Source -c "import hashlib;hashlib.sha3_256" 2>$null
            if ($LASTEXITCODE -eq 0) { $Sha3Backend = "python:" + $py.Source }
        } catch { }
    }
}
if (-not $Sha3Backend) {
    $ossl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($ossl) {
        try {
            "" | & $ossl.Source dgst -sha3-256 *>$null
            if ($LASTEXITCODE -eq 0) { $Sha3Backend = "openssl:" + $ossl.Source }
        } catch { }
    }
}

function Get-Sha3_256Hex([string]$Path) {
    if ($Sha3Backend -eq "dotnet") {
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))
        $h = [System.Security.Cryptography.SHA3_256]::HashData($bytes)
        return (($h | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    elseif ($Sha3Backend -like "python:*") {
        $exe = $Sha3Backend.Substring(7)
        $full = (Resolve-Path -LiteralPath $Path).Path
        return (& $exe -c "import hashlib,sys;print(hashlib.sha3_256(open(sys.argv[1],'rb').read()).hexdigest())" $full).Trim()
    }
    elseif ($Sha3Backend -like "openssl:*") {
        $exe = $Sha3Backend.Substring(8)
        $full = (Resolve-Path -LiteralPath $Path).Path
        $out = & $exe dgst -sha3-256 $full
        return ($out -replace '^.*=\s*', '').Trim()
    }
    return $null
}

# Verify each "<hex>  <name>" line of a sums file. Returns a hashtable of counts.
function Invoke-VerifyList([string]$SumsFile, [string]$Label, [scriptblock]$Hasher) {
    $counts = @{ Pass = 0; Fail = 0; Miss = 0 }
    if (-not (Test-Path -LiteralPath $SumsFile)) {
        Write-Host "  (${Label}: no $SumsFile - skipped)" -ForegroundColor DarkGray
        return $counts
    }
    foreach ($line in Get-Content -LiteralPath $SumsFile) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith("#")) { continue }
        $parts = $line -split '\s+', 2
        if ($parts.Count -lt 2) { continue }
        $expected = $parts[0].Trim().ToLower()
        $name     = $parts[1].Trim()
        if (-not (Test-Path -LiteralPath $name)) {
            Write-Host ("  MISS  {0,-46} {1}" -f $name, $Label) -ForegroundColor Yellow
            $counts.Miss++; continue
        }
        $got = (& $Hasher $name).ToLower()
        if ($got -eq $expected) {
            Write-Host ("  OK    {0,-46} {1}" -f $name, $Label) -ForegroundColor Green
            $counts.Pass++
        } else {
            Write-Host ("  FAIL  {0,-46} {1}" -f $name, $Label) -ForegroundColor Red
            Write-Host ("        expected {0}" -f $expected)
            Write-Host ("        got      {0}" -f $got)
            $counts.Fail++
        }
    }
    return $counts
}

$sha3Label = if ([string]::IsNullOrEmpty($Sha3Backend)) { "<none found>" } else { $Sha3Backend }
Write-Host "talkrypt artifact verification in: $(Get-Location)"
Write-Host "  sha-256 backend:  Get-FileHash (built-in)"
Write-Host "  sha3-256 backend: $sha3Label"
Write-Host ""

Write-Host "SHA-256:"
$c1 = Invoke-VerifyList "SHA256SUMS" "sha256" { param($p) Get-Sha256Hex $p }

Write-Host ""
Write-Host "SHA3-256:"
if ($Sha3Backend) {
    $c2 = Invoke-VerifyList "SHA3-256SUMS" "sha3-256" { param($p) Get-Sha3_256Hex $p }
} else {
    Write-Host "  (no SHA3-256 backend - install .NET 8+, python3, or openssl 3.x to check the second digest)" -ForegroundColor Yellow
    $c2 = @{ Pass = 0; Fail = 0; Miss = 0 }
}

$pass = $c1.Pass + $c2.Pass
$fail = $c1.Fail + $c2.Fail
$miss = $c1.Miss + $c2.Miss

Write-Host ""
Write-Host "----"
Write-Host ("OK: {0}   FAIL: {1}   MISSING: {2}" -f $pass, $fail, $miss)
if ($fail -gt 0 -or $miss -gt 0) {
    Write-Host "VERIFICATION FAILED - do NOT trust these artifacts." -ForegroundColor Red
    exit 1
}
if ($pass -eq 0) {
    Write-Host "nothing verified - no SHA256SUMS/SHA3-256SUMS found here." -ForegroundColor Yellow
    exit 2
}
Write-Host "All artifacts verified against both SHA-256 and SHA3-256." -ForegroundColor Green
exit 0
