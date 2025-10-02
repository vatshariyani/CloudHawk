@echo off
REM CloudHawk Launch Script for Windows
REM Easy deployment and management like OpenVAS

setlocal enabledelayedexpansion

REM Configuration
set CLOUDHAWK_VERSION=2.0.0
set CLOUDHAWK_IMAGE=cloudhawk:latest
set CLOUDHAWK_CONTAINER=cloudhawk
set CLOUDHAWK_PORT=5000
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..

REM Colors (Windows doesn't support colors in batch, but we can use echo)
set INFO=[CloudHawk]
set SUCCESS=[CloudHawk] ✓
set WARNING=[CloudHawk] ⚠
set ERROR=[CloudHawk] ✗

REM Show banner
:show_banner
echo.
echo ╔══════════════════════════════════════════════════════════════╗
echo ║                    CloudHawk v%CLOUDHAWK_VERSION%                    ║
echo ║              Multi-Cloud Security Monitoring Tool           ║
echo ║                                                              ║
echo ║  🚀 Easy deployment and management like OpenVAS            ║
echo ║  🔒 Enterprise-grade cloud security monitoring             ║
echo ║  🤖 ML-based anomaly detection and behavioral analysis  ║
echo ║  📊 Real-time dashboard with advanced filtering             ║
echo ║  🌐 RESTful API with comprehensive documentation           ║
echo ╚══════════════════════════════════════════════════════════════╝
echo.

REM Check if Docker is available
:check_docker
echo %INFO% Checking Docker installation...
docker --version >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Docker is not installed or not in PATH
    echo Please install Docker Desktop: https://docs.docker.com/desktop/windows/
    pause
    exit /b 1
)

docker info >nul 2>&1
if errorlevel 1 (
    echo %ERROR% Docker daemon is not running
    echo Please start Docker Desktop and try again
    pause
    exit /b 1
)

echo %SUCCESS% Docker is available

REM Build CloudHawk image
:build_image
echo %INFO% Building CloudHawk Docker image...
cd /d "%PROJECT_DIR%"
docker build -t %CLOUDHAWK_IMAGE% .
if errorlevel 1 (
    echo %ERROR% Failed to build Docker image
    pause
    exit /b 1
)
echo %SUCCESS% Docker image built successfully

REM Start CloudHawk
:start_cloudhawk
echo %INFO% Starting CloudHawk container...

REM Stop existing container if running
docker ps -q -f name=%CLOUDHAWK_CONTAINER% | findstr . >nul 2>&1
if not errorlevel 1 (
    echo %INFO% Stopping existing CloudHawk container...
    docker stop %CLOUDHAWK_CONTAINER%
    docker rm %CLOUDHAWK_CONTAINER%
)

REM Create necessary directories
if not exist "%PROJECT_DIR%\logs" mkdir "%PROJECT_DIR%\logs"
if not exist "%PROJECT_DIR%\config" mkdir "%PROJECT_DIR%\config"
if not exist "%PROJECT_DIR%\data" mkdir "%PROJECT_DIR%\data"

REM Start CloudHawk container
docker run -d ^
    --name %CLOUDHAWK_CONTAINER% ^
    --restart unless-stopped ^
    -p %CLOUDHAWK_PORT%:%CLOUDHAWK_PORT% ^
    -v "%PROJECT_DIR%\logs:/opt/cloudhawk/logs" ^
    -v "%PROJECT_DIR%\config:/opt/cloudhawk/config" ^
    -v "%PROJECT_DIR%\data:/opt/cloudhawk/data" ^
    -e CLOUDHAWK_PORT=%CLOUDHAWK_PORT% ^
    -e CLOUDHAWK_HOST=0.0.0.0 ^
    -e PYTHONUNBUFFERED=1 ^
    %CLOUDHAWK_IMAGE%

if errorlevel 1 (
    echo %ERROR% Failed to start CloudHawk container
    pause
    exit /b 1
)

echo %SUCCESS% CloudHawk container started

REM Wait for CloudHawk to be ready
:wait_for_ready
echo %INFO% Waiting for CloudHawk to be ready...
set /a max_attempts=30
set /a attempt=1

:wait_loop
if %attempt% gtr %max_attempts% (
    echo %ERROR% CloudHawk failed to start within expected time
    echo Check logs with: %0 logs
    pause
    exit /b 1
)

curl -f http://localhost:%CLOUDHAWK_PORT%/api/v1/health >nul 2>&1
if not errorlevel 1 (
    echo %SUCCESS% CloudHawk is ready!
    goto :show_access
)

echo|set /p="."
timeout /t 2 /nobreak >nul
set /a attempt+=1
goto :wait_loop

REM Show access information
:show_access
echo.
echo 🎉 CloudHawk is now running!
echo.
echo 🌐 Web Interface:
echo    🏠 Main Dashboard:     http://localhost:%CLOUDHAWK_PORT%/
echo    📊 Enhanced Dashboard: http://localhost:%CLOUDHAWK_PORT%/enhanced-dashboard
echo    📚 API Documentation:  http://localhost:%CLOUDHAWK_PORT%/api/docs
echo    ❤️  Health Check:      http://localhost:%CLOUDHAWK_PORT%/api/v1/health
echo    ⚠️  Alerts:            http://localhost:%CLOUDHAWK_PORT%/alerts
echo    🔧 Configuration:      http://localhost:%CLOUDHAWK_PORT%/config
echo    📋 Rules:              http://localhost:%CLOUDHAWK_PORT%/rules
echo    🔍 Security Scan:      http://localhost:%CLOUDHAWK_PORT%/scan
echo.
echo 🔧 Management Commands:
echo    View logs:    %0 logs
echo    Stop:         %0 stop
echo    Restart:      %0 restart
echo    Status:       %0 status
echo    Clean:        %0 clean
echo.
echo 📊 Features Available:
echo    ✅ Multi-cloud security monitoring (AWS, Azure, GCP)
echo    ✅ ML-based anomaly detection with behavioral analysis
echo    ✅ Compliance reporting (SOC2, PCI-DSS, CIS benchmarks)
echo    ✅ Real-time dashboard with advanced filtering and search
echo    ✅ RESTful API with 20+ endpoints and Swagger documentation
echo    ✅ Interactive visualizations and trend analysis
echo    ✅ Webhook support for external integrations
echo.
echo 🚀 CloudHawk is ready for use!
echo.
pause
goto :eof

REM Handle different commands
:handle_commands
if "%1"=="deploy" goto :deploy
if "%1"=="start" goto :deploy
if "%1"=="run" goto :deploy
if "%1"=="stop" goto :stop
if "%1"=="restart" goto :restart
if "%1"=="status" goto :status
if "%1"=="logs" goto :logs
if "%1"=="shell" goto :shell
if "%1"=="clean" goto :clean
if "%1"=="help" goto :help
if "%1"=="-h" goto :help
if "%1"=="--help" goto :help
if "%1"=="" goto :deploy

echo %ERROR% Unknown command: %1
echo Use '%0 help' for available commands
pause
exit /b 1

:deploy
call :show_banner
call :check_docker
call :build_image
call :start_cloudhawk
call :wait_for_ready
call :show_access
goto :eof

:stop
echo %INFO% Stopping CloudHawk...
docker stop %CLOUDHAWK_CONTAINER% 2>nul
echo %SUCCESS% CloudHawk stopped
goto :eof

:restart
echo %INFO% Restarting CloudHawk...
docker restart %CLOUDHAWK_CONTAINER% 2>nul
call :wait_for_ready
call :show_access
goto :eof

:status
docker ps -q -f name=%CLOUDHAWK_CONTAINER% | findstr . >nul 2>&1
if not errorlevel 1 (
    echo %SUCCESS% CloudHawk is running
    call :show_access
) else (
    echo %WARNING% CloudHawk is not running
)
goto :eof

:logs
docker logs %CLOUDHAWK_CONTAINER%
goto :eof

:shell
echo %INFO% Opening CloudHawk container shell...
docker exec -it %CLOUDHAWK_CONTAINER% /bin/bash
goto :eof

:clean
echo %WARNING% This will remove CloudHawk container and image. Continue? (y/N)
set /p response=
if /i "%response%"=="y" (
    echo %INFO% Cleaning up CloudHawk...
    docker stop %CLOUDHAWK_CONTAINER% 2>nul
    docker rm %CLOUDHAWK_CONTAINER% 2>nul
    docker rmi %CLOUDHAWK_IMAGE% 2>nul
    echo %SUCCESS% Cleanup completed
) else (
    echo %INFO% Cleanup cancelled
)
goto :eof

:help
call :show_banner
echo Usage: %0 [command]
echo.
echo Commands:
echo   deploy, start, run  - Deploy and start CloudHawk (default)
echo   stop                - Stop CloudHawk
echo   restart             - Restart CloudHawk
echo   status              - Show CloudHawk status
echo   logs                - Show CloudHawk logs
echo   shell               - Open CloudHawk container shell
echo   clean               - Remove CloudHawk container and image
echo   help                - Show this help message
echo.
echo Examples:
echo   %0                  # Deploy and start CloudHawk
echo   %0 start            # Start CloudHawk
echo   %0 logs             # View CloudHawk logs
echo   %0 status           # Check CloudHawk status
goto :eof

REM Main execution
if "%1"=="" (
    call :deploy
) else (
    call :handle_commands
)
