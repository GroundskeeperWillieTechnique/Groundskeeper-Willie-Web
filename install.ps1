$ErrorActionPreference = "Stop"

Write-Host "🏴󠁧󠁢󠁳󠁣󠁴󠁿 INSTALLING GROUNDSKEEPER WILLIE GLOBALLY..." -ForegroundColor Cyan

# 1. Create willie.bat
$batContent = "@echo off`r`npython `"%~dp0run_willie.py`" %*"
Set-Content -Path ".\willie.bat" -Value $batContent
Write-Host "✅ Created willie.bat wrapper." -ForegroundColor Green

# 2. Add to PATH (User Scope via .NET)
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
$thisDir = Get-Location
if ($currentPath -notlike "*$thisDir*") {
    $newPath = "$currentPath;$thisDir"
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Write-Host "✅ Added $thisDir to User PATH." -ForegroundColor Green
    Write-Host "⚠️  YOU MUST RESTART YOUR TERMINAL FOR CHANGES TO TAKE EFFECT." -ForegroundColor Yellow
} else {
    Write-Host "✅ Willie is already in your PATH." -ForegroundColor Green
}

Write-Host "`r`n🚀 USAGE:" -ForegroundColor Cyan
Write-Host "   willie scan . --auto-fix"
