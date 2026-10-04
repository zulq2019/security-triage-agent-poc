# SYNTHETIC usage data for the Usage tab demo (see seed-usage.sh). Not run by default; rows are flagged synthetic = 1.
#   .\scripts\seed-usage.ps1            # 30 days
#   .\scripts\seed-usage.ps1 --clear    # remove synthetic rows
$root = Split-Path -Parent $PSScriptRoot
$dll = Join-Path $root 'src\SecAgent.Dashboard\bin\Debug\net10.0\secagent.dll'
if (-not (Test-Path $dll)) { dotnet build (Join-Path $root 'SecAgent.slnx') -v q }
dotnet $dll seed-usage @args
