# run.ps1 - NIDS Services Launcher
$repoRoot = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

Write-Host "Launching NIDS services..." -ForegroundColor Cyan

# 1. API server (from repo root, venv activated first)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$repoRoot'; .\venv\Scripts\Activate.ps1; uvicorn api.main:app --reload"

# 2. Dashboard (from dashboard/)
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$repoRoot\dashboard'; python -m http.server 5173"

# 3. Sniffer (from repo root, venv activated, Administrator privileges)
try {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-Command", "Set-Location '$repoRoot'; .\venv\Scripts\Activate.ps1; python -m capture.sniffer --iface `"Wi-Fi`"" -ErrorAction Stop
} catch {
    # Fallback to standard launch if RunAs verb is not supported in the calling environment
    Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$repoRoot'; .\venv\Scripts\Activate.ps1; python -m capture.sniffer --iface `"Wi-Fi`""
}

Write-Host ""
Write-Host "Services launched:" -ForegroundColor Green
Write-Host "  API docs:  http://localhost:8000/docs"
Write-Host "  Dashboard: http://localhost:5173"
Write-Host ""
Write-Host "Note: Please wait ~5 seconds for everything to finish starting before testing." -ForegroundColor Yellow
Write-Host "The sniffer window will show a UAC prompt once." -ForegroundColor Yellow
