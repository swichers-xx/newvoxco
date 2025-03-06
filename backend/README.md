# Voxco Server Monitoring Dashboard - Improved Backend

This improved backend server provides enhanced functionality for the Voxco Server Monitoring Dashboard, including:

1. **JWT Authentication** - Secure authentication with JSON Web Tokens
2. **Real-time Updates** - WebSocket integration for live server status updates
3. **Detailed Server Simulation** - More sophisticated server status simulation with detailed metrics
4. **Logging System** - Comprehensive logging of server status changes and user actions
5. **Caching Mechanism** - Efficient caching of server data to reduce load

## Features

### Enhanced Authentication
- JWT-based authentication with token expiration
- Role-based access control (admin vs. user roles)
- Secure password hashing

### Improved WebSocket Integration
- Real-time server status updates
- Service-specific update events
- Server reboot notifications
- Client subscription to specific servers

### Sophisticated Server Simulation
- Detailed server information (OS, type, location)
- Resource usage metrics (CPU, memory, disk)
- Uptime tracking
- More realistic service status distribution

### Logging System
- Comprehensive logging of all server status changes
- User action tracking
- Filterable log access API

### Caching Mechanism
- Efficient server data caching
- Configurable cache expiration
- Automatic cache refresh

## API Endpoints

### Authentication
- `POST /api/login` - Authenticate and receive JWT token

### Server Management
- `GET /api/servers` - Get all servers with optional filtering
- `GET /api/servers/<server_name>` - Get detailed information about a specific server
- `POST /api/server/reboot` - Reboot a server

### Service Management
- `POST /api/services/start` - Start a service on a server
- `POST /api/services/stop` - Stop a service on a server
- `POST /api/services/restart` - Restart a service on a server

### Monitoring
- `GET /api/stats` - Get server statistics
- `GET /api/logs` - Get server logs with optional filtering

### WebSocket Events
- `server-update` - Emitted when server status changes
- `service-update` - Emitted when a service status changes
- `server-reboot` - Emitted when a server is rebooting

## Getting Started

### Prerequisites
- Python 3.7+
- Flask and dependencies

### Installation
1. Install required packages:
   ```
   pip install flask flask-cors flask-socketio pyjwt werkzeug
   ```

2. Run the server:
   ```
   python server_improved.py
   ```

### Usage
The server will run on port 5000 by default. You can access the API at `http://localhost:5000/api/`.

#### Authentication
To authenticate, send a POST request to `/api/login` with username and password:
```json
{
  "username": "admin",
  "password": "admin"
}
```

Use the returned token in the Authorization header for subsequent requests:
```
Authorization: Bearer <your_token>
```

## WebSocket Integration

To connect to the WebSocket server:
```javascript
const socket = io('http://localhost:5000');

// Listen for server updates
socket.on('server-update', (data) => {
  console.log('Server update:', data);
});

// Listen for service updates
socket.on('service-update', (data) => {
  console.log('Service update:', data);
});

// Subscribe to specific servers
socket.emit('subscribe', { servers: ['VXSQL1', 'VXCATI1'] });