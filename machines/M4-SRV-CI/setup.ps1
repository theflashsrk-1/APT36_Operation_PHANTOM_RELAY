# M4-SRV-CI Setup Script — Operation PHANTOM RELAY (GRIDFALL)
# Run as Administrator on the target machine

Write-Host "[*] Starting M4-SRV-CI configuration..." -ForegroundColor Cyan

$os = Get-WmiObject Win32_OperatingSystem
Write-Host "[+] OS: $($os.Caption) Build $($os.BuildNumber)" -ForegroundColor Green

$adapter = Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1
Write-Host "[+] Network adapter: $($adapter.Name) - $($adapter.Status)" -ForegroundColor Green

Set-TimeZone -Id "UTC" -ErrorAction SilentlyContinue
Write-Host "[+] Time zone set to UTC" -ForegroundColor Green

Write-Host "[+] PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Green

Write-Host "[+] M4-SRV-CI base configuration complete" -ForegroundColor Green
