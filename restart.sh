#!/bin/bash

echo "Restarting all servers..."

# Stop all servers
./stop.sh

# Wait a moment to ensure all processes are stopped
sleep 2

# Start all servers
./start.sh

echo "All servers restarted successfully"