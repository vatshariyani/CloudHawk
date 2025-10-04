#!/bin/bash

# CloudHawk Docker Deployment Script
# This script helps deploy CloudHawk using pre-built Docker images

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
DEFAULT_IMAGE="ghcr.io/vatshariyani/cloudhawk:latest"
DEFAULT_PORT="5000"
DEFAULT_COMPOSE_FILE="docker-compose.prod.yml"

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

# Function to check if Docker is installed
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        exit 1
    fi
    
    print_success "Docker and Docker Compose are installed"
}

# Function to check if image exists
check_image() {
    local image=$1
    print_status "Checking if image $image exists..."
    
    if docker image inspect "$image" &> /dev/null; then
        print_success "Image $image found locally"
        return 0
    else
        print_warning "Image $image not found locally. Will attempt to pull from registry."
        return 1
    fi
}

# Function to pull image
pull_image() {
    local image=$1
    print_status "Pulling image $image..."
    
    if docker pull "$image"; then
        print_success "Successfully pulled image $image"
    else
        print_error "Failed to pull image $image"
        print_error "Please check if the image exists and you have access to the registry"
        exit 1
    fi
}

# Function to create environment file
create_env_file() {
    if [ ! -f ".env" ]; then
        print_status "Creating .env file from template..."
        if [ -f "config/env.example" ]; then
            cp config/env.example .env
            print_success "Created .env file. Please edit it with your configuration."
            print_warning "You need to update the GITHUB_REPOSITORY variable in .env with your actual repository."
        else
            print_warning "env.example not found. Creating basic .env file..."
            cat > .env << EOF
# CloudHawk Configuration
GITHUB_REPOSITORY=vatshariyani/cloudhawk
CLOUDHAWK_PORT=5000
CLOUDHAWK_DOMAIN=cloudhawk.local

# AWS Configuration
AWS_ACCESS_KEY_ID=your_aws_access_key_id
AWS_SECRET_ACCESS_KEY=your_aws_secret_access_key
AWS_DEFAULT_REGION=us-east-1
EOF
            print_success "Created basic .env file. Please edit it with your configuration."
        fi
    else
        print_status ".env file already exists"
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p logs
    mkdir -p config
    mkdir -p ssl
    print_success "Created directories: logs, config, ssl"
}

# Function to start CloudHawk
start_cloudhawk() {
    local compose_file=$1
    print_status "Starting CloudHawk with $compose_file..."
    
    if docker-compose -f "$compose_file" up -d; then
        print_success "CloudHawk started successfully!"
        print_status "CloudHawk is running on port ${CLOUDHAWK_PORT:-5000}"
        print_status "Access the web dashboard at: http://localhost:${CLOUDHAWK_PORT:-5000}"
    else
        print_error "Failed to start CloudHawk"
        exit 1
    fi
}

# Function to show logs
show_logs() {
    local compose_file=$1
    print_status "Showing CloudHawk logs..."
    docker-compose -f "$compose_file" logs -f cloudhawk
}

# Function to stop CloudHawk
stop_cloudhawk() {
    local compose_file=$1
    print_status "Stopping CloudHawk..."
    docker-compose -f "$compose_file" down
    print_success "CloudHawk stopped"
}

# Function to show status
show_status() {
    local compose_file=$1
    print_status "CloudHawk status:"
    docker-compose -f "$compose_file" ps
}

# Function to show help
show_help() {
    echo "CloudHawk Docker Deployment Script"
    echo ""
    echo "Usage: $0 [OPTIONS] COMMAND"
    echo ""
    echo "Commands:"
    echo "  start     Start CloudHawk"
    echo "  stop      Stop CloudHawk"
    echo "  restart   Restart CloudHawk"
    echo "  status    Show CloudHawk status"
    echo "  logs      Show CloudHawk logs"
    echo "  pull      Pull latest CloudHawk image"
    echo "  setup     Setup CloudHawk (create .env, directories, etc.)"
    echo ""
    echo "Options:"
    echo "  -i, --image IMAGE       Docker image to use (default: $DEFAULT_IMAGE)"
    echo "  -p, --port PORT         Port to expose (default: $DEFAULT_PORT)"
    echo "  -f, --file FILE         Docker Compose file to use (default: $DEFAULT_COMPOSE_FILE)"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 setup"
    echo "  $0 start"
    echo "  $0 -i ghcr.io/my-org/cloudhawk:latest start"
    echo "  $0 -p 8080 start"
}

# Parse command line arguments
IMAGE="$DEFAULT_IMAGE"
PORT="$DEFAULT_PORT"
COMPOSE_FILE="$DEFAULT_COMPOSE_FILE"
COMMAND=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -i|--image)
            IMAGE="$2"
            shift 2
            ;;
        -p|--port)
            PORT="$2"
            shift 2
            ;;
        -f|--file)
            COMPOSE_FILE="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        start|stop|restart|status|logs|pull|setup)
            COMMAND="$1"
            shift
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

# Set environment variables
export CLOUDHAWK_PORT="$PORT"

# Main execution
case $COMMAND in
    setup)
        print_status "Setting up CloudHawk..."
        check_docker
        create_env_file
        create_directories
        print_success "Setup completed! Please edit .env file with your configuration."
        ;;
    start)
        print_status "Starting CloudHawk..."
        check_docker
        check_image "$IMAGE" || pull_image "$IMAGE"
        start_cloudhawk "$COMPOSE_FILE"
        ;;
    stop)
        stop_cloudhawk "$COMPOSE_FILE"
        ;;
    restart)
        print_status "Restarting CloudHawk..."
        stop_cloudhawk "$COMPOSE_FILE"
        sleep 2
        start_cloudhawk "$COMPOSE_FILE"
        ;;
    status)
        show_status "$COMPOSE_FILE"
        ;;
    logs)
        show_logs "$COMPOSE_FILE"
        ;;
    pull)
        check_docker
        pull_image "$IMAGE"
        ;;
    "")
        print_error "No command specified"
        show_help
        exit 1
        ;;
    *)
        print_error "Unknown command: $COMMAND"
        show_help
        exit 1
        ;;
esac
