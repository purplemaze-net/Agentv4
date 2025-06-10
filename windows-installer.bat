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
curl -L -o agent.exe https://github.com/purplemaze-net/Agentv4/releases/latest/download/agent-windows-x64.exe

:: Public IP detection
echo Getting public IP...
for /f "delims=" %%a in ('curl --ipv4 -s ifconfig.me') do set PUBLIC_IP=%%a
echo Detected public IP: %PUBLIC_IP%

:: Info gathering
set /p OVERRIDE_IP="Do you want to use a different public IP? (leave empty to use %PUBLIC_IP%): "
if not "%OVERRIDE_IP%"=="" set PUBLIC_IP=%OVERRIDE_IP%

:: Loop for multiple configs
set /p NB_CONFIGS="How much servers do you want to config? "

for /L %%i in (1,1,%NB_CONFIGS%) do (
    echo.
    echo === Configuration %%i / %NB_CONFIGS% ===
    
    set /p SLUG="Server Slug for config %%i (find it on the settings page): "
    set /p PORT="FiveM server port for config %%i: "
    
    :: Build service name and arguments
    set SERVICE_NAME=PAgent_%%i
    set ARGS=!SLUG!:!PUBLIC_IP!:!PORT!
    
    echo Installing service: !SERVICE_NAME! with args: !ARGS!
    nssm install !SERVICE_NAME! "%~dp0agent.exe" !ARGS!
    nssm start !SERVICE_NAME!
    
    echo Service !SERVICE_NAME! installed and started
)

echo.
echo All %NB_CONFIGS% PAgent services installed and started
pause
