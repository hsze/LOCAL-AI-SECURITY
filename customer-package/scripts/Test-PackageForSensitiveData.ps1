[CmdletBinding()]
param(
    [string]$PackageRoot
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $PackageRoot) {
    $PackageRoot = Split-Path -Parent $scriptDirectory
}

$self = $MyInvocation.MyCommand.Path
$textExtensions = @(
    '.cs', '.csproj', '.json', '.md', '.ps1', '.txt', '.yaml', '.yml',
    '.config', '.xml', '.gitignore'
)
$publicIdentifiers = @(
    '9b975845-388f-4429-889e-eab1ef63949c'
)
$patterns = [ordered]@{
    'Windows user-profile path' = '(?i)[A-Z]:\\Users\\(?!<)[^\\\s]+'
    'Microsoft Entra tenant domain' = '(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.onmicrosoft\.com\b'
    'GUID requiring review' = '(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
    'JWT-like token' = '\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b'
    'Private key marker' = '-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'
    'Connection string secret' = '(?i)(AccountKey|SharedAccessKey|ClientSecret|Password)\s*=\s*[^<\s][^;\r\n]*'
}

$findings = [System.Collections.Generic.List[object]]::new()
$files = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File |
    Where-Object {
        $_.FullName -ne $self -and
        $_.FullName -notmatch '[\\/](bin|obj|logs)[\\/]' -and
        $textExtensions -contains $_.Extension.ToLowerInvariant()
    }

foreach ($file in $files) {
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $file.FullName) {
        $lineNumber++
        foreach ($entry in $patterns.GetEnumerator()) {
            foreach ($match in [regex]::Matches($line, $entry.Value)) {
                if ($publicIdentifiers -contains $match.Value) {
                    continue
                }

                $findings.Add([pscustomobject]@{
                    Rule = $entry.Key
                    File = $file.FullName.Substring($PackageRoot.Length).TrimStart('\')
                    Line = $lineNumber
                    Value = $match.Value
                })
            }
        }
    }
}

$forbiddenFiles = Get-ChildItem -LiteralPath $PackageRoot -Recurse -File |
    Where-Object {
        $_.Extension -in '.pfx', '.pem', '.key' -or
        $_.Name -eq 'a365.generated.config.json' -or
        $_.Name -like '*.jsonl' -or
        $_.Name -eq 'runtime-assessment.json'
    }
foreach ($file in $forbiddenFiles) {
    $findings.Add([pscustomobject]@{
        Rule = 'Generated or sensitive artifact'
        File = $file.FullName.Substring($PackageRoot.Length).TrimStart('\')
        Line = 0
        Value = $file.Name
    })
}

if ($findings.Count -gt 0) {
    $findings | Format-Table -AutoSize
    throw "Sensitive-data review failed with $($findings.Count) finding(s)."
}

Write-Host "PASS: no package-specific sensitive-data patterns found in $PackageRoot"