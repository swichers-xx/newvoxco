from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
import jwt
import datetime
import logging
import os
import json
import time
import random
import dotenv
import sys
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import subprocess
import json
import re

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

# Configure Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'voxco_server_dashboard_secret_key')
app.config['JWT_EXPIRATION_SECONDS'] = int(os.getenv('JWT_EXPIRATION_SECONDS', 3600))  # 1 hour
app.config['CACHE_EXPIRATION_SECONDS'] = int(os.getenv('CACHE_EXPIRATION_SECONDS', 60))  # 1 minute

# Configure CORS
CORS(app, resources={r"/api/*": {"origins": os.getenv('CORS_ALLOWED_ORIGINS', '*')}}, supports_credentials=True)

# Set response headers for all responses
@app.after_request
def add_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# In-memory cache
cache = {
    'servers': None,
    'last_updated': 0
}

# Get admin credentials from environment variables
admin_username = os.getenv('ADMIN_USERNAME', 'admin')
admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

# In-memory user database
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
            # Generate JWT token
            token = jwt.encode({
                'username': username,
                'role': users[username]['role'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['JWT_EXPIRATION_SECONDS'])
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            logger.info(f"User {username} logged in successfully")
            return jsonify({'message': 'Login successful', 'token': token})
        else:
            logger.warning(f"Failed login attempt for user {username} (invalid password)")
            return jsonify({'message': 'Invalid credentials'}), 401
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'message': f'Server error: {str(e)}'}), 500

def get_server_location():
    """Generate a random location for a server"""
    locations = ["New York", "London", "Tokyo", "Sydney", "Berlin", "Paris", "Toronto", "Singapore"]
    return random.choice(locations)

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
            
            # Schedule services to come back online after a delay
            def bring_services_online():
                time.sleep(5)  # Simulate reboot time
                for service in server['services']:
                    service['status'] = random.choices(['online', 'warning'], [0.9, 0.1])[0]
                
                # Update cache
                cache['servers'] = servers
                
                logger.info(f"Server {server_name} completed reboot")
            
            # Start the reboot process in a background thread
            import threading
            threading.Thread(target=bring_services_online, daemon=True).start()
            
            return jsonify({'message': f'Server {server_name} is rebooting'})
    
    return jsonify({'error': 'Server not found'}), 404

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
        'timestamp': datetime.datetime.now().isoformat()
    })

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

@app.route('/api/winrm/config', methods=['GET'])
@token_required
def get_winrm_config(current_user):
    """Get WinRM configuration from .env file"""
    try:
        config = {
            'enabled': os.environ.get('WINRM_ENABLED', 'false').lower() == 'true',
            'username': os.environ.get('WINRM_USERNAME', ''),
            'password': '********',  # Don't return actual password
            'host': os.environ.get('WINRM_HOST', ''),
            'port': os.environ.get('WINRM_PORT', '5985')
        }
        return jsonify(config)
    except Exception as e:
        app.logger.error(f"Error getting WinRM config: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/config', methods=['POST'])
@token_required
def save_winrm_config(current_user):
    """Save WinRM configuration to .env file"""
    try:
        data = request.json
        
        # Update .env file
        env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), '.env')
        
        # Read current .env file
        env_content = {}
        if os.path.exists(env_path):
            with open(env_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        env_content[key] = value
        
        # Update values
        env_content['WINRM_ENABLED'] = str(data.get('enabled', False)).lower()
        env_content['WINRM_USERNAME'] = data.get('username', '')
        if data.get('password') and data.get('password') != '********':
            env_content['WINRM_PASSWORD'] = data.get('password', '')
        env_content['WINRM_HOST'] = data.get('host', '')
        env_content['WINRM_PORT'] = data.get('port', '5985')
        
        # Write back to .env file
        with open(env_path, 'w') as f:
            for key, value in env_content.items():
                f.write(f"{key}={value}\n")
        
        # Update current environment
        os.environ['WINRM_ENABLED'] = str(data.get('enabled', False)).lower()
        os.environ['WINRM_USERNAME'] = data.get('username', '')
        if data.get('password') and data.get('password') != '********':
            os.environ['WINRM_PASSWORD'] = data.get('password', '')
        os.environ['WINRM_HOST'] = data.get('host', '')
        os.environ['WINRM_PORT'] = data.get('port', '5985')
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Error saving WinRM config: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/status', methods=['GET'])
@token_required
def get_winrm_status(current_user):
    """Get WinRM status"""
    try:
        enabled = os.environ.get('WINRM_ENABLED', 'false').lower() == 'true'
        username = os.environ.get('WINRM_USERNAME', '')
        password = os.environ.get('WINRM_PASSWORD', '')
        host = os.environ.get('WINRM_HOST', '')
        port = os.environ.get('WINRM_PORT', '5985')
        
        status = {
            'enabled': enabled,
            'configured': enabled and username and password and host and port
        }
        
        return jsonify(status)
    except Exception as e:
        app.logger.error(f"Error getting WinRM status: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/test', methods=['GET'])
@token_required
def test_winrm_connection(current_user):
    """Test WinRM connection to a server"""
    try:
        server = request.args.get('server', os.environ.get('WINRM_HOST', ''))
        
        if not server:
            return jsonify({'error': 'Server IP is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Test connection
        result = winrm.testConnection(server)
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Error testing WinRM connection: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/metrics', methods=['GET'])
@token_required
def get_server_metrics_winrm(current_user, server_ip):
    """Get server metrics using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Get metrics
        cpu_usage = winrm.getCPUUsage(server_ip)
        memory_usage = winrm.getMemoryUsage(server_ip)
        disk_usage = winrm.getDiskUsage(server_ip)
        uptime = winrm.getUptime(server_ip)
        server_info = winrm.getServerInfo(server_ip)
        
        metrics = {
            'cpuUsage': cpu_usage,
            'memoryUsage': memory_usage,
            'diskUsage': disk_usage,
            'uptime': uptime,
            'serverInfo': server_info
        }
        
        return jsonify(metrics)
    except Exception as e:
        app.logger.error(f"Error getting server metrics via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/info', methods=['GET'])
@token_required
def get_server_info_winrm(current_user, server_ip):
    """Get server information using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Get server info
        server_info = winrm.getServerInfo(server_ip)
        
        return jsonify(server_info)
    except Exception as e:
        app.logger.error(f"Error getting server info via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/services', methods=['GET'])
@token_required
def get_services_winrm(current_user, server_ip):
    """Get all services from a server using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Get services
        services = winrm.getServices(server_ip)
        
        return jsonify(services)
    except Exception as e:
        app.logger.error(f"Error getting services via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/service/<service_name>/start', methods=['POST'])
@token_required
def start_service_winrm(current_user, server_ip, service_name):
    """Start a service on a server using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        if not service_name:
            return jsonify({'error': 'Service name is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Start service
        result = winrm.startService(server_ip, service_name)
        
        return jsonify({'success': result})
    except Exception as e:
        app.logger.error(f"Error starting service via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/service/<service_name>/stop', methods=['POST'])
@token_required
def stop_service_winrm(current_user, server_ip, service_name):
    """Stop a service on a server using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        if not service_name:
            return jsonify({'error': 'Service name is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Stop service
        result = winrm.stopService(server_ip, service_name)
        
        return jsonify({'success': result})
    except Exception as e:
        app.logger.error(f"Error stopping service via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/service/<service_name>/restart', methods=['POST'])
@token_required
def restart_service_winrm(current_user, server_ip, service_name):
    """Restart a service on a server using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        if not service_name:
            return jsonify({'error': 'Service name is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Restart service
        result = winrm.restartService(server_ip, service_name)
        
        return jsonify({'success': result})
    except Exception as e:
        app.logger.error(f"Error restarting service via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/winrm/server/<server_ip>/reboot', methods=['POST'])
@token_required
def reboot_server_winrm(current_user, server_ip):
    """Reboot a server using WinRM"""
    try:
        if not server_ip:
            return jsonify({'error': 'Server IP is required'}), 400
        
        # Import winrmConnection module
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        import winrmConnection as winrm
        
        # Reboot server
        result = winrm.rebootServer(server_ip)
        
        return jsonify({'success': result})
    except Exception as e:
        app.logger.error(f"Error rebooting server via WinRM: {str(e)}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Add parent directory to path to import port_utils
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from port_utils import find_free_port, save_port
    
    # Parse command line arguments
    import argparse
    parser = argparse.ArgumentParser(description='Start the Voxco API server')
    parser.add_argument('--port', type=int, help='Port to run the server on')
    args = parser.parse_args()
    
    # Initialize server data
    get_cached_servers()
    
    # Start background task to periodically update server status
    def background_status_updates():
        while True:
            time.sleep(30)  # Update every 30 seconds
            get_cached_servers()  # This will refresh the cache
    
    import threading
    threading.Thread(target=background_status_updates, daemon=True).start()
    
    # Use specified port or find a dynamic port
    if args.port:
        port = args.port
    else:
        # Use a dynamic port with preference for 3000-3005
        port = find_free_port(preferred_range=(3000, 3005))
    
    save_port('simple_api_server', port)
    
    # Log server startup
    logger.info(f"Starting server on port {port}")
    
    # Run the server
    app.run(debug=True, host='0.0.0.0', port=port)