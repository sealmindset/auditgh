#!/bin/bash

# Check if .env exists
if [ ! -f .env ]; then
    echo "Error: .env file not found. Please run setup_docker.sh first."
    exit 1
fi

# Load environment variables
set -a
source .env
set +a

# Default values
ORG=${GITHUB_ORG:-sleepnumberinc}
MAX_WORKERS=4
INCLUDE_FORKS=""
INCLUDE_ARCHIVED=""
LOG_LEVEL="INFO"

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --org)
            ORG="$2"
            shift 2
            ;;
        --max-workers)
            MAX_WORKERS="$2"
            shift 2
            ;;
        --include-forks)
            INCLUDE_FORKS="--include-forks"
            shift
            ;;
        --include-archived)
            INCLUDE_ARCHIVED="--include-archived"
            shift
            ;;
        --loglevel)
            LOG_LEVEL="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Build command
CMD="docker-compose run --rm auditgh \
    --org $ORG \
    --max-workers $MAX_WORKERS \
    --loglevel $LOG_LEVEL"

# Add optional flags
[ -n "$INCLUDE_FORKS" ] && CMD="$CMD $INCLUDE_FORKS"
[ -n "$INCLUDE_ARCHIVED" ] && CMD="$CMD $INCLUDE_ARCHIVED"

# Run the command
echo "Running scan with the following parameters:"
echo "  Organization: $ORG"
echo "  Max Workers: $MAX_WORKERS"
echo "  Include Forks: ${INCLUDE_FORKS:-false}"
echo "  Include Archived: ${INCLUDE_ARCHIVED:-false}"
echo "  Log Level: $LOG_LEVEL"
echo ""

eval $CMD

# Make the script executable
chmod +x run_scan.sh
