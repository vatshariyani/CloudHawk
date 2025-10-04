@echo off
REM CloudHawk Docker Deployment Script for Windows
REM This script helps deploy CloudHawk using pre-built Docker images

setlocal enabledelayedexpansion

REM Default values
set DEFAULT_IMAGE=ghcr.io/vatshariyani/cloudhawk:latest
set DEFAULT_PORT=5000
set DEFAULT_COMPOSE_FILE=docker-compose.prod.yml

REM Function to print colored output
:print_status
echo [INFO] %~1
goto :eof

:print_success
echo [SUCCESS] %~1
goto :eof

:print_warning
echo [WARNING] %~1
goto :eof

:print_error
echo [ERROR] %~1
goto :eof

REM Function to check if Docker is installed
:check_docker
docker --version >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker is not installed. Please install Docker Desktop first."
    exit /b 1
)

docker-compose --version >nul 2>&1
if errorlevel 1 (
    docker compose version >nul 2>&1
    if errorlevel 1 (
        call :print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit /b 1
    )
)

call :print_success "Docker and Docker Compose are installed"
exit /b 0

REM Function to check if image exists
:check_image
set IMAGE=%~1
call :print_status "Checking if image %IMAGE% exists..."

docker image inspect %IMAGE% >nul 2>&1
if errorlevel 1 (
    call :print_warning "Image %IMAGE% not found locally. Will attempt to pull from registry."
    exit /b 1
) else (
    call :print_success "Image %IMAGE% found locally"
    exit /b 0
)

REM Function to pull image
:pull_image
set IMAGE=%~1
call :print_status "Pulling image %IMAGE%..."

docker pull %IMAGE%
if errorlevel 1 (
    call :print_error "Failed to pull image %IMAGE%"
    call :print_error "Please check if the image exists and you have access to the registry"
    exit /b 1
) else (
    call :print_success "Successfully pulled image %IMAGE%"
    exit /b 0
)

REM Function to create environment file
:create_env_file
if not exist ".env" (
    call :print_status "Creating .env file from template..."
    if exist "config\env.example" (
        copy config\env.example .env >nul
        call :print_success "Created .env file. Please edit it with your configuration."
        call :print_warning "You need to update the GITHUB_REPOSITORY variable in .env with your actual repository."
    ) else (
        call :print_warning "env.example not found. Creating basic .env file..."
        (
            echo # CloudHawk Configuration
            echo GITHUB_REPOSITORY=vatshariyani/cloudhawk
            echo CLOUDHAWK_PORT=5000
            echo CLOUDHAWK_DOMAIN=cloudhawk.local
            echo.
            echo # AWS Configuration
            echo AWS_ACCESS_KEY_ID=your_aws_access_key_id
            echo AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
            echo AWS_DEFAULT_REGION=us-east-1
        ) > .env
        call :print_success "Created basic .env file. Please edit it with your configuration."
    )
) else (
    call :print_status ".env file already exists"
)
exit /b 0

REM Function to create necessary directories
:create_directories
call :print_status "Creating necessary directories..."
if not exist "logs" mkdir logs
if not exist "config" mkdir config
if not exist "ssl" mkdir ssl
call :print_success "Created directories: logs, config, ssl"
exit /b 0

REM Function to start CloudHawk
:start_cloudhawk
set COMPOSE_FILE=%~1
call :print_status "Starting CloudHawk with %COMPOSE_FILE%..."

docker-compose -f %COMPOSE_FILE% up -d
if errorlevel 1 (
    call :print_error "Failed to start CloudHawk"
    exit /b 1
) else (
    call :print_success "CloudHawk started successfully!"
    call :print_status "CloudHawk is running on port %CLOUDHAWK_PORT%"
    call :print_status "Access the web dashboard at: http://localhost:%CLOUDHAWK_PORT%"
    exit /b 0
)

REM Function to show logs
:show_logs
set COMPOSE_FILE=%~1
call :print_status "Showing CloudHawk logs..."
docker-compose -f %COMPOSE_FILE% logs -f cloudhawk
exit /b 0

REM Function to stop CloudHawk
:stop_cloudhawk
set COMPOSE_FILE=%~1
call :print_status "Stopping CloudHawk..."
docker-compose -f %COMPOSE_FILE% down
call :print_success "CloudHawk stopped"
exit /b 0

REM Function to show status
:show_status
set COMPOSE_FILE=%~1
call :print_status "CloudHawk status:"
docker-compose -f %COMPOSE_FILE% ps
exit /b 0

REM Function to show help
:show_help
echo CloudHawk Docker Deployment Script for Windows
echo.
echo Usage: %~nx0 [OPTIONS] COMMAND
echo.
echo Commands:
echo   start     Start CloudHawk
echo   stop      Stop CloudHawk
echo   restart   Restart CloudHawk
echo   status    Show CloudHawk status
echo   logs      Show CloudHawk logs
echo   pull      Pull latest CloudHawk image
echo   setup     Setup CloudHawk (create .env, directories, etc.)
echo.
echo Options:
echo   -i, --image IMAGE       Docker image to use (default: %DEFAULT_IMAGE%)
echo   -p, --port PORT         Port to expose (default: %DEFAULT_PORT%)
echo   -f, --file FILE         Docker Compose file to use (default: %DEFAULT_COMPOSE_FILE%)
echo   -h, --help              Show this help message
echo.
echo Examples:
echo   %~nx0 setup
echo   %~nx0 start
echo   %~nx0 -i ghcr.io/my-org/cloudhawk:latest start
echo   %~nx0 -p 8080 start
exit /b 0

REM Parse command line arguments
set IMAGE=%DEFAULT_IMAGE%
set PORT=%DEFAULT_PORT%
set COMPOSE_FILE=%DEFAULT_COMPOSE_FILE%
set COMMAND=

:parse_args
if "%~1"=="" goto :main_execution
if "%~1"=="-i" (
    set IMAGE=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--image" (
    set IMAGE=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="-p" (
    set PORT=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--port" (
    set PORT=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="-f" (
    set COMPOSE_FILE=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="--file" (
    set COMPOSE_FILE=%~2
    shift
    shift
    goto :parse_args
)
if "%~1"=="-h" (
    call :show_help
    exit /b 0
)
if "%~1"=="--help" (
    call :show_help
    exit /b 0
)
if "%~1"=="start" (
    set COMMAND=start
    shift
    goto :parse_args
)
if "%~1"=="stop" (
    set COMMAND=stop
    shift
    goto :parse_args
)
if "%~1"=="restart" (
    set COMMAND=restart
    shift
    goto :parse_args
)
if "%~1"=="status" (
    set COMMAND=status
    shift
    goto :parse_args
)
if "%~1"=="logs" (
    set COMMAND=logs
    shift
    goto :parse_args
)
if "%~1"=="pull" (
    set COMMAND=pull
    shift
    goto :parse_args
)
if "%~1"=="setup" (
    set COMMAND=setup
    shift
    goto :parse_args
)
call :print_error "Unknown option: %~1"
call :show_help
exit /b 1

:main_execution
REM Set environment variables
set CLOUDHAWK_PORT=%PORT%

REM Main execution
if "%COMMAND%"=="setup" (
    call :print_status "Setting up CloudHawk..."
    call :check_docker
    if errorlevel 1 exit /b 1
    call :create_env_file
    call :create_directories
    call :print_success "Setup completed! Please edit .env file with your configuration."
    exit /b 0
)

if "%COMMAND%"=="start" (
    call :print_status "Starting CloudHawk..."
    call :check_docker
    if errorlevel 1 exit /b 1
    call :check_image %IMAGE%
    if errorlevel 1 (
        call :pull_image %IMAGE%
        if errorlevel 1 exit /b 1
    )
    call :start_cloudhawk %COMPOSE_FILE%
    exit /b 0
)

if "%COMMAND%"=="stop" (
    call :stop_cloudhawk %COMPOSE_FILE%
    exit /b 0
)

if "%COMMAND%"=="restart" (
    call :print_status "Restarting CloudHawk..."
    call :stop_cloudhawk %COMPOSE_FILE%
    timeout /t 2 /nobreak >nul
    call :start_cloudhawk %COMPOSE_FILE%
    exit /b 0
)

if "%COMMAND%"=="status" (
    call :show_status %COMPOSE_FILE%
    exit /b 0
)

if "%COMMAND%"=="logs" (
    call :show_logs %COMPOSE_FILE%
    exit /b 0
)

if "%COMMAND%"=="pull" (
    call :check_docker
    if errorlevel 1 exit /b 1
    call :pull_image %IMAGE%
    exit /b 0
)

if "%COMMAND%"=="" (
    call :print_error "No command specified"
    call :show_help
    exit /b 1
)

call :print_error "Unknown command: %COMMAND%"
call :show_help
exit /b 1
