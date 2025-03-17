from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from flask_socketio import SocketIO
import requests
import secrets
import jwt
import datetime
import logging
import os
import json
import time
import random
import dotenv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.serving import WSGIRequestHandler
import sys
from datetime import datetime, timedelta

# Add parent directory to path to import port_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from port_utils import find_free_port, save_port

# Load environment variables from .env file
dotenv.load_dotenv()

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server_status.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Get CORS allowed origins from environment variable or use default
cors_origins = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:3000')
cors_origins_list = cors_origins.split(',')

# Configure Flask with larger header size limit
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max size
app.config['MAX_COOKIE_SIZE'] = 16 * 1024  # 16KB max cookie size

# Configure request handling for larger headers
WSGIRequestHandler.protocol_version = "HTTP/1.1"  # Use HTTP/1.1 for better header handling
# Set a larger buffer size for headers
if hasattr(WSGIRequestHandler, 'header_size_limit'):
    WSGIRequestHandler.header_size_limit = 32 * 1024  # 32KB max header size

# Configure CORS
CORS(app, resources={r"/api/*": {"origins": cors_origins_list}}, supports_credentials=True)

# Configure Socket.IO with compatible options
socketio = SocketIO(
    app,
    cors_allowed_origins=cors_origins_list,
    logger=True,
    engineio_logger=True,
    ping_timeout=60,
    ping_interval=25,
    max_http_buffer_size=1e8,  # 100MB
    # Only use options that are compatible with the installed version
    async_mode='threading'     # Use threading mode for better performance
)

# Configuration from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'voxco_server_dashboard_secret_key')
app.config['JWT_EXPIRATION_SECONDS'] = int(os.getenv('JWT_EXPIRATION_SECONDS', 3600))  # 1 hour
app.config['CACHE_EXPIRATION_SECONDS'] = int(os.getenv('CACHE_EXPIRATION_SECONDS', 60))  # 1 minute

# In-memory cache
cache = {
    'servers': None,
    'last_updated': 0
}

# In-memory user database (replace with a real database in production)
admin_username = os.getenv('ADMIN_USERNAME', 'admin')
admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

users = {
    admin_username: {
        'password': generate_password_hash(admin_password),
        'role': 'admin'
    },
    'user': {
        'password': generate_password_hash('user'),
        'role': 'user'
    }
}

# Server status history for monitoring
server_status_history = {}

# JWT Authentication
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if not auth_header:
            return jsonify({'error': 'Missing Authorization header'}), 401
            
        if auth_header.startswith('Bearer '):
            token = auth_header.replace('Bearer ', '')
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
            
        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            logger.warning("Login attempt with invalid JSON data")
            return jsonify({'message': 'Invalid request format'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            logger.warning("Login attempt with missing credentials")
            return jsonify({'message': 'Missing username or password'}), 400
            
        if username not in users:
            logger.warning(f"Login attempt with unknown username: {username}")
            return jsonify({'message': 'Invalid credentials'}), 401
            
        if check_password_hash(users[username]['password'], password):
            # Generate JWT token with minimal payload to reduce size
            token = jwt.encode({
                'username': username,
                'role': users[username]['role'],
                'exp': datetime.utcnow() + timedelta(seconds=app.config['JWT_EXPIRATION_SECONDS'])
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            logger.info(f"User {username} logged in successfully")
            return jsonify({'message': 'Login successful', 'token': token})
        else:
            logger.warning(f"Failed login attempt for user {username} (invalid password)")
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

@app.route('/api/broadcast', methods=['POST'])
@token_required
def broadcast_update(current_user):
    data = request.get_json()
    socketio.emit('server-update', data)
    logger.info(f"Real-time update broadcast by {current_user}")
    return jsonify({'message': 'Real-time update broadcast'})

def get_server_location():
    """Generate a random location for a server"""
    locations = ["New York", "London", "Tokyo", "Sydney", "Berlin", "Paris", "Toronto", "Singapore"]
    return random.choice(locations)

def get_server_type():
    """Generate a random server type"""
    types = ["Web Server", "Database Server", "Application Server", "File Server", "Mail Server", "Proxy Server"]
    return random.choice(types)

def get_server_os():
    """Generate a random OS for a server"""
    os_list = ["Windows Server 2019", "Windows Server 2016", "Ubuntu 20.04 LTS", "CentOS 8", "Red Hat Enterprise Linux 8"]
    return random.choice(os_list)

def get_random_uptime():
    """Generate a random uptime in days"""
    return round(random.uniform(1, 365), 1)

def get_random_cpu_usage():
    """Generate a random CPU usage percentage"""
    return round(random.uniform(5, 95), 1)

def get_random_memory_usage():
    """Generate a random memory usage percentage"""
    return round(random.uniform(10, 90), 1)

def get_random_disk_usage():
    """Generate a random disk usage percentage"""
    return round(random.uniform(20, 95), 1)

def simulate_server_status():
    """Simulate server status with more detailed information"""
    servers = [
        {"name": "VXSQL1", "ip": "172.16.1.150", "type": "Database Server", "os": "Windows Server 2019"},
        {"name": "VXDIRSRV", "ip": "172.16.1.151", "type": "Directory Server", "os": "Windows Server 2019"},
        {"name": "VXOADMIN", "ip": "172.16.1.160", "type": "Admin Server", "os": "Windows Server 2016"},
        {"name": "VXSERVNO", "ip": "172.16.1.27", "type": "Application Server", "os": "Windows Server 2016"},
        {"name": "VXCATI1", "ip": "172.16.1.156", "type": "CATI Server", "os": "Windows Server 2019"},
        {"name": "VXCATI2", "ip": "172.16.1.157", "type": "CATI Server", "os": "Windows Server 2019"},
        {"name": "VXREPORT", "ip": "172.16.1.153", "type": "Reporting Server", "os": "Windows Server 2016"},
        {"name": "VXDIAL1", "ip": "172.16.1.161", "type": "Dialer Server", "os": "Windows Server 2016"},
        {"name": "VXDIAL2", "ip": "172.16.1.162", "type": "Dialer Server", "os": "Windows Server 2016"},
        {"name": "VXDLR1", "ip": "172.16.1.163", "type": "Dialer Server", "os": "Windows Server 2016"}
    ]
    
    # Define common services for all servers
    common_services = [
        {"name": "Voxco.InstallationService.exe", "description": "Installation Service"},
        {"name": "WindowsUpdateService", "description": "Windows Update Service"},
        {"name": "W3SVC", "description": "IIS Web Server"}
    ]
    
    # Define specific services for each server type
    specific_services = {
        "Database Server": [
            {"name": "SQL Server", "description": "SQL Database Engine"},
            {"name": "SQLAgent", "description": "SQL Server Agent"}
        ],
        "Directory Server": [
            {"name": "VoxcoDirectoryService", "description": "Directory Service"},
            {"name": "ActiveDirectory", "description": "Active Directory"}
        ],
        "Admin Server": [
            {"name": "Voxco A4S Task Server", "description": "A4S Task Service"},
            {"name": "Voxco Email Server", "description": "Email Service"},
            {"name": "Voxco Integration Service", "description": "Integration Service"},
            {"name": "Voxco Task Server", "description": "Task Service"}
        ],
        "Application Server": [
            {"name": "ServNoServer", "description": "ServNo Service"},
            {"name": "ApplicationPool", "description": "IIS Application Pool"}
        ],
        "CATI Server": [
            {"name": "VoxcoBridgeService", "description": "Bridge Service"},
            {"name": "VoxcoCATIService", "description": "CATI Service"}
        ],
        "Reporting Server": [
            {"name": "VoxcoReportingService", "description": "Reporting Service"},
            {"name": "SQLReportingServices", "description": "SQL Reporting Services"}
        ],
        "Dialer Server": [
            {"name": "ProntoServer", "description": "Pronto Dialer Service"},
            {"name": "DialerManager", "description": "Dialer Management Service"}
        ]
    }
    
    # Status probabilities (80% online, 15% warning, 5% offline)
    status_weights = {'online': 0.8, 'warning': 0.15, 'offline': 0.05}
    
    detailed_servers = []
    for server in servers:
        # Get services for this server
        services = common_services.copy()
        if server["type"] in specific_services:
            services.extend(specific_services[server["type"]])
        
        # Assign status to each service
        for service in services:
            status = random.choices(
                ['online', 'warning', 'offline'], 
                [status_weights['online'], status_weights['warning'], status_weights['offline']]
            )[0]
            service["status"] = status
        
        # Add additional server details
        detailed_server = {
            "name": server["name"],
            "ip": server["ip"],
            "location": get_server_location(),
            "type": server["type"],
            "os": server["os"],
            "uptime": get_random_uptime(),
            "cpu_usage": get_random_cpu_usage(),
            "memory_usage": get_random_memory_usage(),
            "disk_usage": get_random_disk_usage(),
            "services": services
        }
        
        detailed_servers.append(detailed_server)
        
        # Track status changes for logging
        if server["name"] in server_status_history:
            previous_services = {s["name"]: s["status"] for s in server_status_history[server["name"]]}
            current_services = {s["name"]: s["status"] for s in services}
            
            # Log status changes
            for service_name, current_status in current_services.items():
                if service_name in previous_services and previous_services[service_name] != current_status:
                    logger.info(f"Service status change: {server['name']} - {service_name} changed from {previous_services[service_name]} to {current_status}")
        
        # Update status history
        server_status_history[server["name"]] = services
    
    return detailed_servers

def get_cached_servers():
    """Get servers from cache or simulate new data if cache is expired"""
    current_time = time.time()
    
    # If cache is expired or empty, refresh it
    if cache['servers'] is None or (current_time - cache['last_updated']) > app.config['CACHE_EXPIRATION_SECONDS']:
        logger.info("Cache expired, refreshing server data")
        cache['servers'] = simulate_server_status()
        cache['last_updated'] = current_time
        
        # Broadcast updates via WebSocket
        socketio.emit('server-update', {'servers': cache['servers'], 'timestamp': datetime.utcnow().isoformat()})
    
    return cache['servers']

@app.route('/api/servers', methods=['GET'])
@token_required
def get_servers(current_user):
    """Get all servers with optional filtering"""
    servers = get_cached_servers()
    
    # Apply filters if provided
    search = request.args.get('search', '').lower()
    status = request.args.get('status', '')
    
    if search or status:
        filtered_servers = []
        for server in servers:
            # Filter by search term
            if search and not (search in server['name'].lower() or search in server['ip'].lower() or search in server['location'].lower()):
                continue
                
            # Filter by status
            if status:
                has_status = any(service['status'] == status for service in server['services'])
                if not has_status:
                    continue
                    
            filtered_servers.append(server)
        
        return jsonify(filtered_servers)
    
    return jsonify(servers)

@app.route('/api/servers/<server_name>', methods=['GET'])
@token_required
def get_server_details(current_user, server_name):
    """Get detailed information about a specific server"""
    servers = get_cached_servers()
    
    for server in servers:
        if server['name'] == server_name:
            return jsonify(server)
    
    return jsonify({'error': 'Server not found'}), 404

@app.route('/api/services/start', methods=['POST'])
@token_required
def start_service(current_user):
    """Start a service on a server"""
    data = request.get_json()
    server_name = data.get('server')
    service_name = data.get('service')
    
    if not server_name or not service_name:
        return jsonify({'error': 'Missing server or service name'}), 400
    
    # Simulate starting the service
    servers = get_cached_servers()
    for server in servers:
        if server['name'] == server_name:
            for service in server['services']:
                if service['name'] == service_name:
                    if service['status'] == 'online':
                        return jsonify({'message': f'Service {service_name} is already running'})
                    
                    # Update service status
                    old_status = service['status']
                    service['status'] = 'online'
                    
                    # Log the change
                    logger.info(f"Service {service_name} on {server_name} started by {current_user} (changed from {old_status} to online)")
                    
                    # Update cache
                    cache['servers'] = servers
                    
                    # Broadcast update
                    socketio.emit('service-update', {
                        'server': server_name,
                        'service': service_name,
                        'status': 'online',
                        'timestamp': datetime.utcnow().isoformat(),
                        'user': current_user
                    })
                    
                    return jsonify({'message': f'Service {service_name} started successfully'})
            
            return jsonify({'error': 'Service not found'}), 404
    
    return jsonify({'error': 'Server not found'}), 404

@app.route('/api/services/stop', methods=['POST'])
@token_required
def stop_service(current_user):
    """Stop a service on a server"""
    data = request.get_json()
    server_name = data.get('server')
    service_name = data.get('service')
    
    if not server_name or not service_name:
        return jsonify({'error': 'Missing server or service name'}), 400
    
    # Simulate stopping the service
    servers = get_cached_servers()
    for server in servers:
        if server['name'] == server_name:
            for service in server['services']:
                if service['name'] == service_name:
                    if service['status'] == 'offline':
                        return jsonify({'message': f'Service {service_name} is already stopped'})
                    
                    # Update service status
                    old_status = service['status']
                    service['status'] = 'offline'
                    
                    # Log the change
                    logger.info(f"Service {service_name} on {server_name} stopped by {current_user} (changed from {old_status} to offline)")
                    
                    # Update cache
                    cache['servers'] = servers
                    
                    # Broadcast update
                    socketio.emit('service-update', {
                        'server': server_name,
                        'service': service_name,
                        'status': 'offline',
                        'timestamp': datetime.utcnow().isoformat(),
                        'user': current_user
                    })
                    
                    return jsonify({'message': f'Service {service_name} stopped successfully'})
            
            return jsonify({'error': 'Service not found'}), 404
    
    return jsonify({'error': 'Server not found'}), 404

@app.route('/api/services/restart', methods=['POST'])
@token_required
def restart_service(current_user):
    """Restart a service on a server"""
    data = request.get_json()
    server_name = data.get('server')
    service_name = data.get('service')
    
    if not server_name or not service_name:
        return jsonify({'error': 'Missing server or service name'}), 400
    
    # Simulate restarting the service
    servers = get_cached_servers()
    for server in servers:
        if server['name'] == server_name:
            for service in server['services']:
                if service['name'] == service_name:
                    # Update service status
                    old_status = service['status']
                    service['status'] = 'online'
                    
                    # Log the change
                    logger.info(f"Service {service_name} on {server_name} restarted by {current_user} (changed from {old_status} to online)")
                    
                    # Update cache
                    cache['servers'] = servers
                    
                    # Broadcast update
                    socketio.emit('service-update', {
                        'server': server_name,
                        'service': service_name,
                        'status': 'online',
                        'timestamp': datetime.utcnow().isoformat(),
                        'user': current_user
                    })
                    
                    return jsonify({'message': f'Service {service_name} restarted successfully'})
            
            return jsonify({'error': 'Service not found'}), 404
    
    return jsonify({'error': 'Server not found'}), 404

@app.route('/api/server/reboot', methods=['POST'])
@token_required
def reboot_server(current_user):
    """Reboot a server"""
    data = request.get_json()
    server_name = data.get('server')
    
    if not server_name:
        return jsonify({'error': 'Missing server name'}), 400
    
    # Simulate rebooting the server
    servers = get_cached_servers()
    for server in servers:
        if server['name'] == server_name:
            # Log the reboot
            logger.info(f"Server {server_name} rebooted by {current_user}")
            
            # Set all services to offline temporarily
            for service in server['services']:
                service['status'] = 'offline'
            
            # Update cache
            cache['servers'] = servers
            
            # Broadcast update
            socketio.emit('server-reboot', {
                'server': server_name,
                'timestamp': datetime.utcnow().isoformat(),
                'user': current_user
            })
            
            # Schedule services to come back online after a delay
            def bring_services_online():
                time.sleep(5)  # Simulate reboot time
                for service in server['services']:
                    service['status'] = random.choices(['online', 'warning'], [0.9, 0.1])[0]
                
                # Update cache
                cache['servers'] = servers
                
                # Broadcast update
                socketio.emit('server-update', {
                    'servers': [server],
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                logger.info(f"Server {server_name} completed reboot")
            
            # Start the reboot process in a background thread
            import threading
            threading.Thread(target=bring_services_online).start()
            
            return jsonify({'message': f'Server {server_name} is rebooting'})
    
    return jsonify({'error': 'Server not found'}), 404

@app.route('/api/logs', methods=['GET'])
@token_required
def get_logs(current_user):
    """Get server logs with optional filtering"""
    # Check if user has admin role
    if users.get(current_user, {}).get('role') != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    # Get log parameters
    limit = request.args.get('limit', 100, type=int)
    server = request.args.get('server', '')
    service = request.args.get('service', '')
    level = request.args.get('level', '')
    
    # Read log file
    try:
        with open("server_status.log", "r") as f:
            logs = f.readlines()
    except FileNotFoundError:
        return jsonify([])
    
    # Apply filters
    filtered_logs = []
    for log in logs[-limit:]:
        if server and server not in log:
            continue
        if service and service not in log:
            continue
        if level and level.upper() not in log:
            continue
        filtered_logs.append(log.strip())
    
    return jsonify(filtered_logs)

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Get server statistics"""
    servers = get_cached_servers()
    
    # Calculate statistics
    total_servers = len(servers)
    total_services = sum(len(server['services']) for server in servers)
    
    online_services = 0
    warning_services = 0
    offline_services = 0
    
    for server in servers:
        for service in server['services']:
            if service['status'] == 'online':
                online_services += 1
            elif service['status'] == 'warning':
                warning_services += 1
            elif service['status'] == 'offline':
                offline_services += 1
    
    uptime_percentage = (online_services / total_services * 100) if total_services > 0 else 0
    
    # Get average resource usage
    avg_cpu = sum(server['cpu_usage'] for server in servers) / total_servers if total_servers > 0 else 0
    avg_memory = sum(server['memory_usage'] for server in servers) / total_servers if total_servers > 0 else 0
    avg_disk = sum(server['disk_usage'] for server in servers) / total_servers if total_servers > 0 else 0
    
    return jsonify({
        'total_servers': total_servers,
        'total_services': total_services,
        'online_services': online_services,
        'warning_services': warning_services,
        'offline_services': offline_services,
        'uptime_percentage': round(uptime_percentage, 2),
        'avg_cpu_usage': round(avg_cpu, 2),
        'avg_memory_usage': round(avg_memory, 2),
        'avg_disk_usage': round(avg_disk, 2),
        'timestamp': datetime.utcnow().isoformat()
    })

# WebSocket event handlers
@socketio.on('connect')
def handle_connect():
    logger.info(f"Client connected: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    logger.info(f"Client disconnected: {request.sid}")

@socketio.on('subscribe')
def handle_subscribe(data):
    """Subscribe to updates for specific servers"""
    server_names = data.get('servers', [])
    room = request.sid
    
    for server_name in server_names:
        socketio.enter_room(room, server_name)
        logger.info(f"Client {request.sid} subscribed to updates for server {server_name}")

# Start the server
if __name__ == '__main__':
    # Initialize server data
    get_cached_servers()
    
    def background_status_updates():
        while True:
            time.sleep(30)  # Update every 30 seconds
            get_cached_servers()  # This will refresh the cache and broadcast updates
    
    import threading
    threading.Thread(target=background_status_updates, daemon=True).start()
    
    # Use a dynamic port with preference for 3000-3005
    port = find_free_port(preferred_range=(3000, 3005))
    save_port('server_improved', port)
    
    # Configure basic server options compatible with older versions
    server_options = {
        'debug': True,
        'port': port,
        'host': '0.0.0.0'  # Listen on all interfaces
    }
    
    # Log server startup
    header_size = getattr(WSGIRequestHandler, 'header_size_limit', 'default')
    logger.info(f"Starting server on port {port} with header_size_limit={header_size}")
    
    # Run the server with compatible options
    socketio.run(app, **server_options)