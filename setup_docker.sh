#!/bin/bash

# Create .env file if it doesn't exist
if [ ! -f .env ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    echo "Please edit the .env file and set your GitHub token and organization"
    exit 1
fi

# Make sure Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "Docker is not running. Please start Docker and try again."
    exit 1
fi

# Pull latest images and build containers
echo "Building Docker containers..."
docker-compose build

echo "\nSetup complete! You can now run the scanner with:\n"
echo "  docker-compose up"
echo ""
echo "Or with custom parameters:"
echo "  docker-compose run --rm auditgh --org your-org-name --include-forks"

# Make the script executable
chmod +x setup_docker.sh
