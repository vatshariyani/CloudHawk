@echo off
REM CloudHawk Docker Build Test Script for Windows
REM This script tests the Docker build locally before pushing to GitHub

setlocal enabledelayedexpansion

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

REM Function to check if Docker is running
:check_docker
docker info >nul 2>&1
if errorlevel 1 (
    call :print_error "Docker is not running. Please start Docker Desktop and try again."
    exit /b 1
)
call :print_success "Docker is running"
exit /b 0

REM Function to test Docker build
:test_docker_build
set IMAGE_NAME=cloudhawk:test
call :print_status "Testing Docker build..."

REM Build the image
docker build -f deployment/Dockerfile -t %IMAGE_NAME% .
if errorlevel 1 (
    call :print_error "Docker build failed"
    exit /b 1
)
call :print_success "Docker build completed successfully"

REM Test the image
call :print_status "Testing Docker image..."
docker run --rm %IMAGE_NAME% python -c "import sys; print('Python version:', sys.version)"
if errorlevel 1 (
    call :print_error "Docker image test failed"
    exit /b 1
)
call :print_success "Docker image test passed"

REM Clean up test image
call :print_status "Cleaning up test image..."
docker rmi %IMAGE_NAME% >nul 2>&1
call :print_success "Test image cleaned up"
exit /b 0

REM Function to show GitHub setup instructions
:show_github_setup
call :print_status "GitHub Container Registry Setup Instructions:"
echo.
echo 1. Push your code to GitHub:
echo    git add .
echo    git commit -m "Add Docker deployment support"
echo    git push origin main
echo.
echo 2. The GitHub Actions workflow will automatically:
echo    - Build the Docker image
echo    - Push it to GitHub Container Registry (ghcr.io)
echo    - Tag it with 'latest' and version tags
echo.
echo 3. After the workflow completes, your image will be available at:
echo    ghcr.io/vatshariyani/cloudhawk:latest
echo.
echo 4. Users can then pull and run your image:
echo    docker pull ghcr.io/vatshariyani/cloudhawk:latest
echo    docker run -p 5000:5000 ghcr.io/vatshariyani/cloudhawk:latest
echo.
call :print_warning "Note: Make sure your GitHub repository is public or you have proper permissions for GitHub Container Registry"
exit /b 0

REM Function to show manual build instructions
:show_manual_build
call :print_status "Manual Docker Build Instructions:"
echo.
echo If you want to build and push manually:
echo.
echo 1. Build the image:
echo    docker build -f deployment/Dockerfile -t ghcr.io/vatshariyani/cloudhawk:latest .
echo.
echo 2. Login to GitHub Container Registry:
echo    echo %GITHUB_TOKEN% | docker login ghcr.io -u vatshariyani --password-stdin
echo.
echo 3. Push the image:
echo    docker push ghcr.io/vatshariyani/cloudhawk:latest
echo.
call :print_warning "Note: You need a GitHub Personal Access Token with 'write:packages' permission"
exit /b 0

REM Main execution
call :print_status "CloudHawk Docker Build Test"
echo ==================================

REM Check if Docker is available
call :check_docker
if errorlevel 1 exit /b 1

REM Test Docker build
call :test_docker_build
if errorlevel 1 exit /b 1

call :print_success "All tests passed! Your Docker setup is ready."
echo.

REM Show next steps
call :show_github_setup
echo.
call :show_manual_build
