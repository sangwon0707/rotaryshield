#!/bin/bash
# RotaryShield Docker Test Helper Script

set -e

CONTAINER_NAME="rotaryshield-test"

case "$1" in
    build)
        echo "Building RotaryShield Docker image..."
        docker-compose build
        echo "Build complete!"
        ;;

    start)
        echo "Starting RotaryShield container..."
        docker-compose up -d
        echo "Container started!"
        echo ""
        echo "Connect with: ./docker-test.sh shell"
        ;;

    stop)
        echo "Stopping RotaryShield container..."
        docker-compose down
        echo "Container stopped!"
        ;;

    shell)
        echo "Connecting to RotaryShield container..."
        docker exec -it $CONTAINER_NAME bash
        ;;

    root)
        echo "Connecting as root..."
        docker exec -it -u root $CONTAINER_NAME bash
        ;;

    logs)
        docker-compose logs -f
        ;;

    rebuild)
        echo "Rebuilding container..."
        docker-compose down
        docker-compose build --no-cache
        docker-compose up -d
        echo "Rebuild complete!"
        ;;

    test)
        echo "Running quick CLI tests..."
        docker exec -it $CONTAINER_NAME bash -c '
            echo "=== RotaryShield CLI Test ==="
            echo ""
            echo "1. Checking Python imports..."
            python3 -c "from rotaryshield.cli import RotaryShieldCLI, RICH_AVAILABLE; print(f\"   Rich available: {RICH_AVAILABLE}\")"
            echo ""
            echo "2. Testing CLI help..."
            python3 -m rotaryshield.cli 2>/dev/null || true
            echo ""
            echo "3. Testing stats command..."
            rotaryshield-stats --help
            echo ""
            echo "=== Tests Complete ==="
        '
        ;;

    *)
        echo "RotaryShield Docker Test Helper"
        echo ""
        echo "Usage: $0 {build|start|stop|shell|root|logs|rebuild|test}"
        echo ""
        echo "Commands:"
        echo "  build   - Build the Docker image"
        echo "  start   - Start the container"
        echo "  stop    - Stop the container"
        echo "  shell   - Connect to container shell"
        echo "  root    - Connect as root user"
        echo "  logs    - View container logs"
        echo "  rebuild - Rebuild from scratch"
        echo "  test    - Run quick CLI tests"
        echo ""
        echo "Quick start:"
        echo "  ./docker-test.sh build"
        echo "  ./docker-test.sh start"
        echo "  ./docker-test.sh shell"
        ;;
esac
