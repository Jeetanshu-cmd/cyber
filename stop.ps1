# stop.ps1 - Finds and stops NIDS services by matching command lines

# If not running as Administrator, elevate to ensure elevated sniffer and command lines are accessible
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "Elevating stop.ps1 to Administrator privileges..." -ForegroundColor Cyan
    $scriptPath = if ($PSCommandPath) { $PSCommandPath } else { "$PSScriptRoot\stop.ps1" }
    try {
        Start-Process powershell -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`"" -Wait
        exit
    } catch {
        Write-Warning "Could not elevate ($($_.Exception.Message)). Continuing without elevation..."
    }
}

$filters = @(
    "CommandLine LIKE '%uvicorn%'",
    "CommandLine LIKE '%http.server%' AND CommandLine LIKE '%5173%'",
    "CommandLine LIKE '%capture.sniffer%'"
)

$targetCount = 0
$processedPids = @{}

foreach ($filter in $filters) {
    $processes = Get-CimInstance Win32_Process -Filter $filter | Where-Object { 
        $_.ProcessId -ne $PID -and $_.CommandLine -notlike "*stop.ps1*" -and $_.CommandLine -notlike "*Get-CimInstance*"
    }

    foreach ($proc in $processes) {
        if (-not $processedPids.ContainsKey($proc.ProcessId)) {
            $processedPids[$proc.ProcessId] = $true
            if (Get-Process -Id $proc.ProcessId -ErrorAction SilentlyContinue) {
                $targetCount++
                Write-Host "Stopping process $($proc.ProcessId) ($($proc.Name))..."
                # Kill process and its full process tree to cleanly close the terminal window
                & taskkill.exe /F /T /PID $proc.ProcessId 2>$null | Out-Null
                Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
                Write-Host "Stopped process $($proc.ProcessId)." -ForegroundColor Green
            }
        }
    }
}

if ($targetCount -eq 0) {
    Write-Host "No running NIDS processes found." -ForegroundColor Yellow
} else {
    Write-Host "All targeted NIDS processes stopped." -ForegroundColor Green
}
