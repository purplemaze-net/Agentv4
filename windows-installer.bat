@echo off
setlocal EnableDelayedExpansion

:: NSSM
echo Downloading NSSM...
curl -L -o nssm.zip https://nssm.cc/release/nssm-2.24.zip
powershell -command "Expand-Archive -Path nssm.zip -DestinationPath ."
move nssm-2.24\win64\nssm.exe .
rd /s /q nssm-2.24

:: PAgent
echo Downloading PAgent...
:: Download latest release
curl -L -o agent.exe https://github.com/purplemaze-net/Agentv4/releases/latest/download/agent-windows-x64.exe

:: public IP detection
echo Getting public IP...
for /f "delims=" %%a in ('curl -s ifconfig.me') do set PUBLIC_IP=%%a
echo Detected public IP: %PUBLIC_IP%

:: Info gathering
set /p OVERRIDE_IP="Do you want to use a different public IP? (leave empty to use %PUBLIC_IP%): "
if not "%OVERRIDE_IP%"=="" set PUBLIC_IP=%OVERRIDE_IP%

:: Loop for infos
set ARGS=
set /p NB_CONFIGS=""

set /p SLUG="Server Slug (find it on the settings page) : "
set /p PORT="FiveM server port : "
set ARGS="!SLUG!:!PUBLIC_IP!:!PORT!"

nssm install PAgent "%~dp0agent.exe" %ARGS%
nssm start PAgent

echo.
echo PAgent installed and started as a service
pause