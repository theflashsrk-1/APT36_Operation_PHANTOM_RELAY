# M5-SRV-BASTION Setup Script — Operation PHANTOM RELAY (GRIDFALL)
# Run as Administrator on the target machine

Write-Host "[*] Starting M5-SRV-BASTION configuration..." -ForegroundColor Cyan

$os = Get-WmiObject Win32_OperatingSystem
Write-Host "[+] OS: $($os.Caption) Build $($os.BuildNumber)" -ForegroundColor Green

$adapter = Get-NetAdapter | Where-Object Status -eq Up | Select-Object -First 1
Write-Host "[+] Network adapter: $($adapter.Name) - $($adapter.Status)" -ForegroundColor Green

Set-TimeZone -Id "UTC" -ErrorAction SilentlyContinue
Write-Host "[+] Time zone set to UTC" -ForegroundColor Green

Write-Host "[+] PowerShell: $($PSVersionTable.PSVersion)" -ForegroundColor Green

Write-Host "[+] M5-SRV-BASTION base configuration complete" -ForegroundColor Green
