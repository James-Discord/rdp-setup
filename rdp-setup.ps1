if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

$rdpWrapUrl = "https://github.com/stascorp/rdpwrap/releases/download/v1.6.2/RDPWrap-v1.6.2.zip"
$rdpWrapZip = "$env:TEMP\RDPWrap.zip"
$rdpWrapExtractPath = "$env:ProgramFiles\RDP Wrapper"
$iniPath = "$rdpWrapExtractPath\rdpwrap.ini"

Write-Host "Downloading RDP Wrapper..."
Invoke-WebRequest -Uri $rdpWrapUrl -OutFile $rdpWrapZip
Write-Host "Extracting RDP Wrapper..."
Expand-Archive -Path $rdpWrapZip -DestinationPath $rdpWrapExtractPath -Force

$iniUrl = "https://raw.githubusercontent.com/sebaxakerhtc/rdpwrap.ini/refs/heads/master/rdpwrap.ini"
Write-Host "Downloading latest rdpwrap.ini..."
Invoke-WebRequest -Uri $iniUrl -OutFile $iniPath

Write-Host "Installing RDP Wrapper..."
Start-Process -FilePath "$rdpWrapExtractPath\install.bat" -Wait -NoNewWindow
Start-Process -FilePath "$rdpWrapExtractPath\RDPConf.exe" -Wait -NoNewWindow

Write-Host "Installation complete. Please restart your computer for the changes to take effect."

$newUsername = Read-Host "Enter the new username"
$newPassword = Read-Host "Enter the new password" -AsSecureString
if (-not (Get-LocalUser -Name $newUsername -ErrorAction SilentlyContinue)) {
    New-LocalUser -Name $newUsername -Password $newPassword -FullName "$newUsername" -Description "RDP User"
    Add-LocalGroupMember -Group "Remote Desktop Users" -Member $newUsername
    Write-Host "User $newUsername created and added to Remote Desktop Users group."
} else {
    Write-Host "User $newUsername already exists. Skipping creation."
}

Write-Host "Enabling RDP and configuring settings..."
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

$regPath = "HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services"
if (!(Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
}
Set-ItemProperty -Path $regPath -Name "MaxIdleTime" -Value 0
Set-ItemProperty -Path $regPath -Name "MaxDisconnectionTime" -Value 0
Set-ItemProperty -Path $regPath -Name "KeepAliveEnable" -Value 1

Write-Host "RDP setup complete. A system restart is required for changes to take effect."
