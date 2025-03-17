#!/bin/bash

# Function to stop a server
stop_server() {
  local server_file=$1
  local pid_file="pids/$server_file.pid"
  
  if [ -f "$pid_file" ]; then
    PID=$(cat "$pid_file")
    echo "Stopping $server_file (PID: $PID)..."
    
    # Check if process is running
    if ps -p $PID > /dev/null; then
      kill $PID
      # Wait for process to terminate
      sleep 1
      if ps -p $PID > /dev/null; then
        echo "Process still running, sending SIGKILL..."
        kill -9 $PID
      fi
      echo "$server_file stopped"
    else
      echo "$server_file is not running"
    fi
    
    # Remove PID file
    rm "$pid_file"
  else
    echo "PID file for $server_file not found"
  fi
}

# Create pids directory if it doesn't exist
mkdir -p pids

echo "Stopping all Voxco Server Monitoring Dashboard services..."

# Stop frontend server
stop_server "frontend.pid"

# Stop all backend servers
stop_server "server.py"
stop_server "server_improved.py"
stop_server "simple_api_server.py"
stop_server "simple_server.py"

# Clean up port files
if [ -d "ports" ]; then
  echo "Cleaning up port files..."
  rm -f ports/*.txt
fi

# Check if any processes are still running
pids_count=$(ls pids/*.pid 2>/dev/null | wc -l)
if [ "$pids_count" -gt 0 ]; then
  echo "Warning: Some processes may still be running. PID files remaining:"
  ls -la pids/*.pid 2>/dev/null
else
  echo "All servers stopped successfully"
fi

echo ""
echo "To restart the servers, run: ./start.sh"