#!/bin/bash

# CloudHawk Setup Script
# Easy installation and deployment like OpenVAS

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# CloudHawk configuration
CLOUDHAWK_VERSION="2.0.0"
CLOUDHAWK_PORT=5000
CLOUDHAWK_HOST="0.0.0.0"
CLOUDHAWK_IMAGE="cloudhawk:latest"
CLOUDHAWK_CONTAINER="cloudhawk"

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    CloudHawk Setup v$CLOUDHAWK_VERSION                    ║"
echo "║              Multi-Cloud Security Monitoring Tool           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Docker is installed
check_docker() {
    print_status "Checking Docker installation..."
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Visit: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        echo "Visit: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    print_status "Docker and Docker Compose are installed ✓"
}

# Check if port is available
check_port() {
    print_status "Checking if port $CLOUDHAWK_PORT is available..."
    if lsof -Pi :$CLOUDHAWK_PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
        print_warning "Port $CLOUDHAWK_PORT is already in use."
        read -p "Do you want to continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    else
        print_status "Port $CLOUDHAWK_PORT is available ✓"
    fi
}

# Create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p logs
    mkdir -p config
    mkdir -p data
    print_status "Directories created ✓"
}

# Build Docker image
build_image() {
    print_status "Building CloudHawk Docker image..."
    docker build -t $CLOUDHAWK_IMAGE .
    print_status "Docker image built successfully ✓"
}

# Start CloudHawk
start_cloudhawk() {
    print_status "Starting CloudHawk..."
    
    # Stop existing container if running
    if docker ps -q -f name=$CLOUDHAWK_CONTAINER | grep -q .; then
        print_status "Stopping existing CloudHawk container..."
        docker stop $CLOUDHAWK_CONTAINER
        docker rm $CLOUDHAWK_CONTAINER
    fi
    
    # Start new container
    docker run -d \
        --name $CLOUDHAWK_CONTAINER \
        --restart unless-stopped \
        -p $CLOUDHAWK_PORT:$CLOUDHAWK_PORT \
        -v $(pwd)/logs:/opt/cloudhawk/logs \
        -v $(pwd)/config:/opt/cloudhawk/config \
        -v $(pwd)/data:/opt/cloudhawk/data \
        $CLOUDHAWK_IMAGE
    
    print_status "CloudHawk started successfully ✓"
}

# Wait for CloudHawk to be ready
wait_for_cloudhawk() {
    print_status "Waiting for CloudHawk to be ready..."
    
    max_attempts=30
    attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if curl -f http://localhost:$CLOUDHAWK_PORT/api/v1/health >/dev/null 2>&1; then
            print_status "CloudHawk is ready! ✓"
            return 0
        fi
        
        echo -n "."
        sleep 2
        attempt=$((attempt + 1))
    done
    
    print_error "CloudHawk failed to start within expected time"
    return 1
}

# Display access information
show_access_info() {
    echo -e "${GREEN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    CloudHawk is Ready!                      ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${BLUE}🌐 Web Interface:${NC}"
    echo "   Main Dashboard:     http://localhost:$CLOUDHAWK_PORT/"
    echo "   Enhanced Dashboard: http://localhost:$CLOUDHAWK_PORT/enhanced-dashboard"
    echo "   API Documentation:  http://localhost:$CLOUDHAWK_PORT/api/docs"
    echo "   Health Check:      http://localhost:$CLOUDHAWK_PORT/api/v1/health"
    
    echo -e "\n${BLUE}🔧 Management Commands:${NC}"
    echo "   View logs:          docker logs $CLOUDHAWK_CONTAINER"
    echo "   Stop CloudHawk:     docker stop $CLOUDHAWK_CONTAINER"
    echo "   Start CloudHawk:    docker start $CLOUDHAWK_CONTAINER"
    echo "   Restart CloudHawk:  docker restart $CLOUDHAWK_CONTAINER"
    echo "   Remove CloudHawk:   docker rm -f $CLOUDHAWK_CONTAINER"
    
    echo -e "\n${BLUE}📊 Features Available:${NC}"
    echo "   ✅ Multi-cloud security monitoring (AWS, Azure, GCP)"
    echo "   ✅ ML-based anomaly detection"
    echo "   ✅ Compliance reporting (SOC2, PCI-DSS, CIS)"
    echo "   ✅ Real-time dashboard with advanced filtering"
    echo "   ✅ RESTful API with 20+ endpoints"
    echo "   ✅ Swagger/OpenAPI documentation"
    
    echo -e "\n${GREEN}🎉 CloudHawk is now running and accessible!${NC}"
}

# Main setup function
main() {
    echo -e "${BLUE}Starting CloudHawk setup...${NC}\n"
    
    check_docker
    check_port
    create_directories
    build_image
    start_cloudhawk
    
    if wait_for_cloudhawk; then
        show_access_info
    else
        print_error "Setup failed. Check logs with: docker logs $CLOUDHAWK_CONTAINER"
        exit 1
    fi
}

# Handle command line arguments
case "${1:-}" in
    "start")
        print_status "Starting CloudHawk..."
        start_cloudhawk
        wait_for_cloudhawk && show_access_info
        ;;
    "stop")
        print_status "Stopping CloudHawk..."
        docker stop $CLOUDHAWK_CONTAINER 2>/dev/null || true
        print_status "CloudHawk stopped ✓"
        ;;
    "restart")
        print_status "Restarting CloudHawk..."
        docker restart $CLOUDHAWK_CONTAINER 2>/dev/null || true
        wait_for_cloudhawk && show_access_info
        ;;
    "status")
        if docker ps -q -f name=$CLOUDHAWK_CONTAINER | grep -q .; then
            print_status "CloudHawk is running ✓"
            show_access_info
        else
            print_warning "CloudHawk is not running"
        fi
        ;;
    "logs")
        docker logs $CLOUDHAWK_CONTAINER
        ;;
    "clean")
        print_status "Cleaning up CloudHawk..."
        docker stop $CLOUDHAWK_CONTAINER 2>/dev/null || true
        docker rm $CLOUDHAWK_CONTAINER 2>/dev/null || true
        docker rmi $CLOUDHAWK_IMAGE 2>/dev/null || true
        print_status "Cleanup completed ✓"
        ;;
    *)
        main
        ;;
esac
