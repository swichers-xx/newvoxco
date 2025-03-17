from flask import Flask, jsonify, request
from flask_cors import CORS
import jwt
import datetime
import logging
import os
import dotenv
import sys
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
    # Placeholder for fetching live server data
    # Implement logic to fetch live data from your data source
    return []

# Cache for server data
server_cache = {
    'data': None,
    'last_updated': 0
}

@app.route('/api/servers', methods=['GET'])
@token_required
def get_servers(current_user):
    """Get all servers with optional filtering using live data"""
    import time
    
    # Refresh cache every 30 seconds
    current_time = time.time()
    # Placeholder for fetching live server data
    # Implement logic to fetch live data from your data source
    server_cache['data'] = []  # Replace with live data fetching logic
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
    # Add parent directory to path to import port_utils
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from port_utils import find_free_port, save_port
    
    # Use a dynamic port with preference for 3000-3005
    port = find_free_port(preferred_range=(3000, 3005))
    save_port('simple_server', port)
    
    # Log server startup
    logger.info(f"Starting simple server on port {port}")
    
    # Run the server
    app.run(host='0.0.0.0', port=port, debug=True)