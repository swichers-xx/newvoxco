@echo off
echo Configuring WinRM...

REM Enable WinRM Quickconfig
echo y | winrm quickconfig

REM Enable Basic Authentication
winrm set winrm/config/service/Auth @{Basic="true"}

REM Allow Unencrypted Traffic
winrm set winrm/config/service @{AllowUnencrypted="true"}

REM Set Maximum Memory Per Shell (1024 MB)
winrm set winrm/config/winrs @{MaxMemoryPerShellMB="1024"}

echo WinRM configuration complete.
pause
