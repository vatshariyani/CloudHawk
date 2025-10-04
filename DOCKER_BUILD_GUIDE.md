# 🐳 Docker Build and Upload Guide

This guide explains how to build and upload the CloudHawk Docker image to GitHub Container Registry (GHCR).

## 🚀 Quick Start

### Option 1: Automatic Build (Recommended)

The easiest way is to use GitHub Actions to automatically build and push the image:

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Add Docker deployment support"
   git push origin main
   ```

2. **The GitHub Actions workflow will automatically:**
   - Build the Docker image for multiple platforms (AMD64, ARM64)
   - Push it to GitHub Container Registry (ghcr.io)
   - Tag it with 'latest' and version tags
   - Generate build attestations for security

3. **Your image will be available at:**
   ```
   ghcr.io/vatshariyani/cloudhawk:latest
   ```

### Option 2: Manual Build and Push

If you prefer to build and push manually:

1. **Build the image:**
   ```bash
   docker build -t ghcr.io/vatshariyani/cloudhawk:latest .
   ```

2. **Login to GitHub Container Registry:**
   ```bash
   echo $GITHUB_TOKEN | docker login ghcr.io -u vatshariyani --password-stdin
   ```

3. **Push the image:**
   ```bash
   docker push ghcr.io/vatshariyani/cloudhawk:latest
   ```

## 🧪 Testing the Build

### Local Testing

Before pushing to GitHub, you can test the Docker build locally:

#### Linux/macOS:
```bash
./scripts/test-docker-build.sh
```

#### Windows:
```cmd
scripts\test-docker-build.bat
```

#### Manual Testing:
```bash
# Build the image
docker build -t cloudhawk:test .

# Test the image
docker run --rm cloudhawk:test python -c "import sys; print('Python version:', sys.version)"

# Clean up
docker rmi cloudhawk:test
```

## 📋 Prerequisites

### For Automatic Build (GitHub Actions)
- GitHub repository (public or private with proper permissions)
- GitHub Actions enabled
- No additional setup required

### For Manual Build
- Docker installed and running
- GitHub Personal Access Token with `write:packages` permission
- Access to GitHub Container Registry

## 🔧 GitHub Actions Workflow

The workflow (`.github/workflows/docker-build.yml`) automatically:

### Triggers
- Push to `main` or `master` branch
- Push tags starting with `v` (e.g., `v1.0.0`)
- Pull requests to `main` or `master`
- Manual trigger via GitHub UI

### Build Process
1. **Checkout code** from the repository
2. **Set up Docker Buildx** for multi-platform builds
3. **Login to GHCR** using GitHub token
4. **Extract metadata** for tagging
5. **Build and push** image for multiple platforms
6. **Generate attestations** for security

### Image Tags
The workflow automatically creates these tags:
- `latest` (for main/master branch)
- `main` or `master` (branch name)
- `v1.0.0` (for version tags)
- `v1.0` (major.minor)
- `v1` (major version)

## 🏷️ Image Management

### Viewing Images
```bash
# List all images in your repository
docker search ghcr.io/vatshariyani/cloudhawk

# Pull the latest image
docker pull ghcr.io/vatshariyani/cloudhawk:latest

# Pull a specific version
docker pull ghcr.io/vatshariyani/cloudhawk:v1.0.0
```

### Running the Image
```bash
# Basic run
docker run -p 5000:5000 ghcr.io/vatshariyani/cloudhawk:latest

# With environment variables
docker run -p 5000:5000 \
  -e AWS_ACCESS_KEY_ID=your_key \
  -e AWS_SECRET_ACCESS_KEY=your_secret \
  ghcr.io/vatshariyani/cloudhawk:latest

# With volumes
docker run -p 5000:5000 \
  -v $(pwd)/logs:/opt/cloudhawk/logs \
  -v $(pwd)/config:/opt/cloudhawk/config \
  ghcr.io/vatshariyani/cloudhawk:latest
```

## 🔒 Security Considerations

### GitHub Container Registry
- Images are stored in GitHub Container Registry
- Access controlled by repository permissions
- Images are scanned for vulnerabilities
- Build attestations provide supply chain security

### Image Security
- Multi-stage build reduces attack surface
- Non-root user inside container
- Minimal base image (python:3.11-slim)
- No secrets embedded in image

### Access Control
- Repository visibility controls image access
- Personal Access Tokens for manual operations
- GitHub Actions uses built-in authentication

## 📊 Monitoring and Maintenance

### Build Status
- Check GitHub Actions tab for build status
- View build logs for troubleshooting
- Monitor for failed builds

### Image Updates
- Automatic updates on code changes
- Version tags for stable releases
- `latest` tag for development builds

### Cleanup
```bash
# Remove old images locally
docker image prune

# Remove specific image
docker rmi ghcr.io/vatshariyani/cloudhawk:old-tag
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Build Fails
```bash
# Check Docker is running
docker info

# Check Dockerfile syntax
docker build --no-cache -t test .

# Check GitHub Actions logs
# Go to Actions tab in GitHub repository
```

#### 2. Push Fails
```bash
# Check authentication
docker login ghcr.io

# Check token permissions
# Ensure token has 'write:packages' permission
```

#### 3. Image Not Found
```bash
# Check image exists
docker search ghcr.io/vatshariyani/cloudhawk

# Check repository permissions
# Ensure repository is public or you have access
```

### Debug Commands
```bash
# Check image details
docker inspect ghcr.io/vatshariyani/cloudhawk:latest

# Check image layers
docker history ghcr.io/vatshariyani/cloudhawk:latest

# Test image locally
docker run --rm ghcr.io/vatshariyani/cloudhawk:latest python --version
```

## 📈 Performance Optimization

### Build Optimization
- Multi-stage build reduces final image size
- Layer caching improves build speed
- Parallel builds for multiple platforms

### Runtime Optimization
- Minimal base image
- Optimized Python dependencies
- Efficient startup script

## 🔄 Continuous Integration

### Automated Workflow
The GitHub Actions workflow provides:
- **Automatic builds** on code changes
- **Multi-platform support** (AMD64, ARM64)
- **Security scanning** and attestations
- **Version management** with tags

### Manual Triggers
You can manually trigger builds:
1. Go to GitHub repository
2. Click "Actions" tab
3. Select "Build and Push Docker Image"
4. Click "Run workflow"

## 📞 Support

### Getting Help
- **GitHub Issues**: Report build problems
- **Actions Logs**: Check build output
- **Documentation**: Review this guide

### Common Solutions
- **Build fails**: Check Dockerfile syntax
- **Push fails**: Verify authentication
- **Image not found**: Check repository permissions

---

**Next Steps**: After your image is built and uploaded, users can deploy CloudHawk using the pre-built image with the deployment scripts we created earlier!
