$ErrorActionPreference = 'Stop'
$Root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
try {
    & (Join-Path $Root 'settool.ps1')
    Set-Location $Root
    if ($args.Count -gt 0 -and $args[0] -eq 'server') {
        Write-Host 'Starting ShadowNetX server on port 8443...'
        mvn -q compile exec:java '-Dexec.args=server'
    } else {
        Write-Host 'Starting ShadowNetX client...'
        mvn -q compile exec:java
    }
    if ($LASTEXITCODE -ne 0) { throw "Maven exited with code $LASTEXITCODE." }
} catch {
    Write-Host "ShadowNetX stopped because of an error: $_" -ForegroundColor Red
    Read-Host 'Press Enter to close'
}
