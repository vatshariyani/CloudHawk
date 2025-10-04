#!/bin/bash

# CloudHawk Docker Build Test Script
# This script tests the Docker build locally before pushing to GitHub

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if Docker is running
check_docker() {
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker Desktop and try again."
        exit 1
    fi
    print_success "Docker is running"
}

# Function to test Docker build
test_docker_build() {
    local image_name="cloudhawk:test"
    print_status "Testing Docker build..."
    
    # Build the image
    if docker build -f deployment/Dockerfile -t "$image_name" .; then
        print_success "Docker build completed successfully"
    else
        print_error "Docker build failed"
        exit 1
    fi
    
    # Test the image
    print_status "Testing Docker image..."
    if docker run --rm "$image_name" python -c "import sys; print('Python version:', sys.version)"; then
        print_success "Docker image test passed"
    else
        print_error "Docker image test failed"
        exit 1
    fi
    
    # Clean up test image
    print_status "Cleaning up test image..."
    docker rmi "$image_name" >/dev/null 2>&1 || true
    print_success "Test image cleaned up"
}

# Function to show GitHub setup instructions
show_github_setup() {
    print_status "GitHub Container Registry Setup Instructions:"
    echo ""
    echo "1. Push your code to GitHub:"
    echo "   git add ."
    echo "   git commit -m 'Add Docker deployment support'"
    echo "   git push origin main"
    echo ""
    echo "2. The GitHub Actions workflow will automatically:"
    echo "   - Build the Docker image"
    echo "   - Push it to GitHub Container Registry (ghcr.io)"
    echo "   - Tag it with 'latest' and version tags"
    echo ""
    echo "3. After the workflow completes, your image will be available at:"
    echo "   ghcr.io/vatshariyani/cloudhawk:latest"
    echo ""
    echo "4. Users can then pull and run your image:"
    echo "   docker pull ghcr.io/vatshariyani/cloudhawk:latest"
    echo "   docker run -p 5000:5000 ghcr.io/vatshariyani/cloudhawk:latest"
    echo ""
    print_warning "Note: Make sure your GitHub repository is public or you have proper permissions for GitHub Container Registry"
}

# Function to show manual build instructions
show_manual_build() {
    print_status "Manual Docker Build Instructions:"
    echo ""
    echo "If you want to build and push manually:"
    echo ""
    echo "1. Build the image:"
    echo "   docker build -f deployment/Dockerfile -t ghcr.io/vatshariyani/cloudhawk:latest ."
    echo ""
    echo "2. Login to GitHub Container Registry:"
    echo "   echo \$GITHUB_TOKEN | docker login ghcr.io -u vatshariyani --password-stdin"
    echo ""
    echo "3. Push the image:"
    echo "   docker push ghcr.io/vatshariyani/cloudhawk:latest"
    echo ""
    print_warning "Note: You need a GitHub Personal Access Token with 'write:packages' permission"
}

# Main execution
print_status "CloudHawk Docker Build Test"
echo "=================================="

# Check if Docker is available
check_docker

# Test Docker build
test_docker_build

print_success "All tests passed! Your Docker setup is ready."
echo ""

# Show next steps
show_github_setup
echo ""
show_manual_build
