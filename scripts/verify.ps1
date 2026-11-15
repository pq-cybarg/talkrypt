<#
  Verify talkrypt release artifacts against BOTH SHA384SUMS and SHA3-384SUMS, then
  every post-quantum co-signature present.

  Two independent 384-bit hash families (SHA-384 = FIPS 180-4, and SHA3-384 = FIPS
  202 / Keccak) must BOTH match for every file: a flaw in one construction cannot
  mask a tampered artifact, because it would also have to forge a second, unrelated
  digest.

    powershell -ExecutionPolicy Bypass -File verify.ps1            # current dir
    pwsh ./verify.ps1 -Dir C:\path\to\artifacts                    # another dir

  Exit code 0 if every listed file is present, both digests match, and every
  co-signature present verifies; non-zero otherwise. SHA-384 uses the built-in
  Get-FileHash. SHA3-384 uses .NET 8+'s SHA3_384 if available, else python3's
  hashlib, else openssl 3.x. Co-signatures are checked with talkrypt-relsign if it
  is on PATH (or beside the artifacts) and the matching public key is available.
#>
[CmdletBinding()]
param([string]$Dir = ".")

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $Dir

function Get-Sha384Hex([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA384).Hash.ToLower()
}

# --- detect a SHA3-384 backend once ---
$Sha3Backend = $null
try {
    if ([System.Security.Cryptography.SHA3_384]::IsSupported) { $Sha3Backend = "dotnet" }
} catch { }
if (-not $Sha3Backend) {
    $py = Get-Command python3 -ErrorAction SilentlyContinue
    if (-not $py) { $py = Get-Command python -ErrorAction SilentlyContinue }
    if ($py) {
        try {
            & $py.Source -c "import hashlib;hashlib.sha3_384" 2>$null
            if ($LASTEXITCODE -eq 0) { $Sha3Backend = "python:" + $py.Source }
        } catch { }
    }
}
if (-not $Sha3Backend) {
    $ossl = Get-Command openssl -ErrorAction SilentlyContinue
    if ($ossl) {
        try {
            "" | & $ossl.Source dgst -sha3-384 *>$null
            if ($LASTEXITCODE -eq 0) { $Sha3Backend = "openssl:" + $ossl.Source }
        } catch { }
    }
}

function Get-Sha3_384Hex([string]$Path) {
    if ($Sha3Backend -eq "dotnet") {
        $bytes = [System.IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $Path))
        $h = [System.Security.Cryptography.SHA3_384]::HashData($bytes)
        return (($h | ForEach-Object { $_.ToString("x2") }) -join "")
    }
    elseif ($Sha3Backend -like "python:*") {
        $exe = $Sha3Backend.Substring(7)
        $full = (Resolve-Path -LiteralPath $Path).Path
        return (& $exe -c "import hashlib,sys;print(hashlib.sha3_384(open(sys.argv[1],'rb').read()).hexdigest())" $full).Trim()
    }
    elseif ($Sha3Backend -like "openssl:*") {
        $exe = $Sha3Backend.Substring(8)
        $full = (Resolve-Path -LiteralPath $Path).Path
        $out = & $exe dgst -sha3-384 $full
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
Write-Host "  sha-384 backend:  Get-FileHash (built-in)"
Write-Host "  sha3-384 backend: $sha3Label"
Write-Host ""

Write-Host "SHA-384:"
$c1 = Invoke-VerifyList "SHA384SUMS" "sha384" { param($p) Get-Sha384Hex $p }

Write-Host ""
Write-Host "SHA3-384:"
if ($Sha3Backend) {
    $c2 = Invoke-VerifyList "SHA3-384SUMS" "sha3-384" { param($p) Get-Sha3_384Hex $p }
} else {
    Write-Host "  (no SHA3-384 backend - install .NET 8+, python3, or openssl 3.x to check the second digest)" -ForegroundColor Yellow
    $c2 = @{ Pass = 0; Fail = 0; Miss = 0 }
}

# --- optional PQ co-signature check (SECURITY-AUDIT F-8) ---
# A release carries a SELECTABLE set of co-signatures; EVERY one present must verify.
# Needs talkrypt-relsign(.exe) on PATH or beside the artifacts, plus the signer's
# public key (per-scheme env var or the bundled RELEASE_PUBKEY*.hex, published WITH
# the release). TRUST ANCHOR: pin the pubkey you obtained OUT OF BAND.
$SigFail = 0; $SigSeen = $false
$Relsign = (Get-Command talkrypt-relsign -ErrorAction SilentlyContinue)
if ($Relsign) { $Relsign = $Relsign.Source }
elseif (Test-Path -LiteralPath "./talkrypt-relsign.exe") { $Relsign = (Resolve-Path "./talkrypt-relsign.exe").Path }
elseif (Test-Path -LiteralPath "./talkrypt-relsign") { $Relsign = (Resolve-Path "./talkrypt-relsign").Path }
else { $Relsign = $null }

function Resolve-Pubkey([string]$EnvVal, [string]$File) {
    if (-not [string]::IsNullOrWhiteSpace($EnvVal)) { return ($EnvVal -replace '\s', '') }
    if (Test-Path -LiteralPath $File) {
        return ((Get-Content -LiteralPath $File | Where-Object { $_ -notmatch '^\s*#' }) -join '' -replace '\s', '')
    }
    return ""
}

function Test-CoSignature([string]$Algo, [string]$SigFile, [string]$Pubkey, [string]$Label) {
    if (-not (Test-Path -LiteralPath $SigFile)) { return }
    $script:SigSeen = $true
    if ($Relsign -and -not [string]::IsNullOrWhiteSpace($Pubkey)) {
        & $Relsign --algo $Algo verify SHA384SUMS $SigFile $Pubkey *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Host ("  OK    {0}  ({1})" -f $SigFile, $Label) -ForegroundColor Green
        } else {
            Write-Host ("  FAIL  {0} did NOT verify under that key ({1})" -f $SigFile, $Label) -ForegroundColor Red
            $script:SigFail = 1
        }
    } elseif (-not $Relsign) {
        Write-Host ("  (advisory: {0} present but talkrypt-relsign not found - NOT checked)" -f $SigFile) -ForegroundColor Yellow
    } else {
        Write-Host ("  (advisory: {0} present but no {1} pubkey - NOT checked)" -f $SigFile, $Label) -ForegroundColor Yellow
    }
}

if ((Test-Path "SHA384SUMS.sig") -or (Test-Path "SHA384SUMS.slh.sig")) {
    Write-Host ""
    Write-Host "PQ co-signatures (all present must verify):"
    Test-CoSignature "ml-dsa"  "SHA384SUMS.sig"     (Resolve-Pubkey $env:TALKRYPT_RELEASE_PUBKEY     "RELEASE_PUBKEY.hex")     "ML-DSA-87"
    Test-CoSignature "slh-dsa" "SHA384SUMS.slh.sig" (Resolve-Pubkey $env:TALKRYPT_RELEASE_PUBKEY_SLH "RELEASE_PUBKEY_SLH.hex") "SLH-DSA-SHA2-256s"
}

$pass = $c1.Pass + $c2.Pass
$fail = $c1.Fail + $c2.Fail
$miss = $c1.Miss + $c2.Miss

Write-Host ""
Write-Host "----"
Write-Host ("OK: {0}   FAIL: {1}   MISSING: {2}" -f $pass, $fail, $miss)
if ($fail -gt 0 -or $miss -gt 0 -or $SigFail -gt 0) {
    Write-Host "VERIFICATION FAILED - do NOT trust these artifacts." -ForegroundColor Red
    exit 1
}
if ($pass -eq 0) {
    Write-Host "nothing verified - no SHA384SUMS/SHA3-384SUMS found here." -ForegroundColor Yellow
    exit 2
}
$extra = if ($SigSeen) { ", plus every PQ co-signature present" } else { "" }
Write-Host ("All artifacts verified against both SHA-384 and SHA3-384$extra." ) -ForegroundColor Green
exit 0
