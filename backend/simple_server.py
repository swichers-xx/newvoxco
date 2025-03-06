from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import datetime
import logging
import os
import dotenv
from werkzeug.security import generate_password_hash, check_password_hash

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
cors_origins = os.getenv('CORS_ALLOWED_ORIGINS', 'http://localhost:3000,http://localhost:5001,http://localhost:5002')
cors_origins_list = cors_origins.split(',')

# Configure Flask with larger header size limit
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max size
app.config['MAX_COOKIE_SIZE'] = 16 * 1024  # 16KB max cookie size

# Configure CORS with more permissive settings
CORS(app,
     origins=cors_origins_list,
     resources={r"/api/*": {"origins": cors_origins_list}},
     supports_credentials=True,
     allow_headers=["Content-Type", "Authorization", "Accept"],
     expose_headers=["Content-Type", "Authorization"],
     methods=["GET", "POST", "OPTIONS"])

# Add CORS headers to all responses
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization,Accept'
    response.headers['Access-Control-Allow-Methods'] = 'GET,POST,OPTIONS'
    return response

# Configuration from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'voxco_server_dashboard_secret_key')
app.config['JWT_EXPIRATION_SECONDS'] = int(os.getenv('JWT_EXPIRATION_SECONDS', 3600))  # 1 hour

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

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            logger.warning("Login attempt with invalid JSON data")
            return jsonify({'message': 'Invalid request format'}), 400
            
        username = data.get('username')
        password = data.get('password')
        
        logger.info(f"Login attempt for user: {username}")
        
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

@app.route('/api/test', methods=['GET'])
def test():
    return jsonify({'message': 'API is working'})

# Mock JWT Authentication
def token_required(f):
    from functools import wraps
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

# Actual server data from the original implementation
def get_server_location():
    """Generate a random location for a server"""
    import random
    locations = ["New York", "London", "Tokyo", "Sydney", "Berlin", "Paris", "Toronto", "Singapore"]
    return random.choice(locations)

def get_random_uptime():
    """Generate a random uptime in days"""
    import random
    return round(random.uniform(1, 365), 1)

def get_random_cpu_usage():
    """Generate a random CPU usage percentage"""
    import random
    return round(random.uniform(5, 95), 1)

def get_random_memory_usage():
    """Generate a random memory usage percentage"""
    import random
    return round(random.uniform(10, 90), 1)

def get_random_disk_usage():
    """Generate a random disk usage percentage"""
    import random
    return round(random.uniform(20, 95), 1)

def get_mock_servers():
    """Generate server data with the actual servers from the original implementation"""
    import random
    
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
        {"name": "Voxco.InstallationService.exe", "description": "Installation Service", "status": ""},
        {"name": "WindowsUpdateService", "description": "Windows Update Service", "status": ""},
        {"name": "W3SVC", "description": "IIS Web Server", "status": ""}
    ]
    
    # Define specific services for each server type
    specific_services = {
        "Database Server": [
            {"name": "SQL Server", "description": "SQL Database Engine", "status": ""},
            {"name": "SQLAgent", "description": "SQL Server Agent", "status": ""}
        ],
        "Directory Server": [
            {"name": "VoxcoDirectoryService", "description": "Directory Service", "status": ""},
            {"name": "ActiveDirectory", "description": "Active Directory", "status": ""}
        ],
        "Admin Server": [
            {"name": "Voxco A4S Task Server", "description": "A4S Task Service", "status": ""},
            {"name": "Voxco Email Server", "description": "Email Service", "status": ""},
            {"name": "Voxco Integration Service", "description": "Integration Service", "status": ""},
            {"name": "Voxco Task Server", "description": "Task Service", "status": ""}
        ],
        "Application Server": [
            {"name": "ServNoServer", "description": "ServNo Service", "status": ""},
            {"name": "ApplicationPool", "description": "IIS Application Pool", "status": ""}
        ],
        "CATI Server": [
            {"name": "VoxcoBridgeService", "description": "Bridge Service", "status": ""},
            {"name": "VoxcoCATIService", "description": "CATI Service", "status": ""}
        ],
        "Reporting Server": [
            {"name": "VoxcoReportingService", "description": "Reporting Service", "status": ""},
            {"name": "SQLReportingServices", "description": "SQL Reporting Services", "status": ""}
        ],
        "Dialer Server": [
            {"name": "ProntoServer", "description": "Pronto Dialer Service", "status": ""},
            {"name": "DialerManager", "description": "Dialer Management Service", "status": ""}
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
    
    return detailed_servers

# Cache for server data
server_cache = {
    'data': None,
    'last_updated': 0
}

@app.route('/api/servers', methods=['GET'])
@token_required
def get_servers(current_user):
    """Get all servers with optional filtering"""
    import time
    
    # Refresh cache every 30 seconds
    current_time = time.time()
    if server_cache['data'] is None or (current_time - server_cache['last_updated']) > 30:
        server_cache['data'] = get_mock_servers()
        server_cache['last_updated'] = current_time
        logger.info("Server data refreshed in cache")
    
    servers = server_cache['data']
    
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

@app.route('/api/stats', methods=['GET'])
@token_required
def get_stats(current_user):
    """Get server statistics"""
    import time
    
    # Use cached server data if available
    current_time = time.time()
    if server_cache['data'] is None or (current_time - server_cache['last_updated']) > 30:
        server_cache['data'] = get_mock_servers()
        server_cache['last_updated'] = current_time
        logger.info("Server data refreshed in cache for stats")
    
    servers = server_cache['data']
    
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

# Start the server
if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.getenv('API_PORT', 5002))
    
    # Log server startup
    logger.info(f"Starting simple server on port {port}")
    
    # Run the server
    app.run(host='0.0.0.0', port=port, debug=True)