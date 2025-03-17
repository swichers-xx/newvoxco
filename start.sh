#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
  export $(grep -v '^#' .env | xargs)
else
  echo "Creating default .env file..."
  cat > .env << EOL
# Server Configuration
PORT=3000
API_PORT=5001
JWT_SECRET=your_jwt_secret_key_here
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin

# WinRM Configuration
WINRM_ENABLED=false
WINRM_USERNAME=Administrator
WINRM_PASSWORD=
WINRM_HOST=
WINRM_PORT=5985
EOL
  echo ".env file created with default values."
fi

# Function to start a server
start_server() {
  local server_file=$1
  local log_file=$2
  local port_arg=$3
  
  echo "Starting $server_file..."
  if [ -n "$port_arg" ]; then
    python backend/$server_file --port $port_arg > logs/$log_file 2>&1 &
  else
    python backend/$server_file > logs/$log_file 2>&1 &
  fi
  PID=$!
  echo "$PID" > pids/$server_file.pid
  echo "$server_file started with PID: $PID"
}

# Create logs and pids directories if they don't exist
mkdir -p logs
mkdir -p pids
mkdir -p ports

# Generate frontend configuration
echo "Generating frontend configuration..."
node generate-frontend-config.js

# Start HTTP server for frontend
echo "Starting HTTP server for frontend..."
python frontend_server.py > logs/frontend.log 2>&1 &
PID=$!
echo "$PID" > pids/frontend.pid
echo "Frontend server started with PID: $PID"

# Wait for the port file to be created
sleep 1
if [ -f ports/frontend_port.txt ]; then
  FRONTEND_PORT=$(cat ports/frontend_port.txt)
  echo "Frontend available at: http://localhost:$FRONTEND_PORT"
else
  echo "Frontend port file not found, check logs for details"
fi

# Start API server with specific port (5001)
echo "Starting API server on port 5001..."
start_server "simple_api_server.py" "simple_api_server.log" "5001"
echo "API server available at: http://localhost:5001/api"

# Start other backend servers
start_server "server.py" "server.log"
start_server "server_improved.py" "server_improved.log"
start_server "simple_server.py" "simple_server.log"

echo "All servers started successfully"
echo ""
echo "Dashboard available at: http://localhost:3000"
echo "Admin interface available at: http://localhost:3000/admin"
echo "API available at: http://localhost:5001/api"
echo ""
echo "WinRM functionality is available for Windows server monitoring"
echo "Use './stop.sh' to stop all servers"