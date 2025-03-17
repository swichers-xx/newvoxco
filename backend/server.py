from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
from flask_socketio import SocketIO, emit
import winrm
import requests
import secrets
import os
import dotenv
import json
import time
import sys
from pathlib import Path

# Add parent directory to path to import port_utils
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from port_utils import find_free_port, save_port

# Load environment variables from .env file
dotenv.load_dotenv()

# Create data directory if it doesn't exist
data_dir = Path('data')
data_dir.mkdir(exist_ok=True)

# Path to server data file
SERVERS_FILE = data_dir / 'servers_data.json'
CONFIG_FILE = data_dir / 'config_data.json'

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins=os.getenv('CORS_ALLOWED_ORIGINS', '*'))

# Basic Authentication Mechanism
authorized_tokens = set()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Get admin credentials from environment variables
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_password = os.getenv('ADMIN_PASSWORD', 'admin')

    # Replace with actual user validation logic
    if username == admin_username and password == admin_password:
        token = secrets.token_hex(16)
        authorized_tokens.add(token)
        return jsonify({'message': 'Login successful', 'token': token})
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.before_request
def check_auth():
    # Exclude certain endpoints from requiring auth
    if request.endpoint in ['login', 'static']:
        return None

    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Missing Authorization header'}), 401

    token = auth_header.replace('Bearer ', '')
    if token not in authorized_tokens:
        return jsonify({'error': 'Invalid token'}), 401

    return None

@app.route('/api/broadcast', methods=['POST'])
def broadcast_update():
    data = request.get_json()
    socketio.emit('server-update', data)
    return jsonify({'message': 'Real-time update broadcast'})

def load_servers_data():
    """Load servers data from file or return default data if file doesn't exist"""
    if SERVERS_FILE.exists():
        try:
            with open(SERVERS_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading servers data: {e}")
    
    # Default server data if file doesn't exist or is invalid
    return [
        {
            "name": "VXSQL1",
            "ip": "172.16.1.150",
            "services": [
                { "name": "SQL Server", "status": "online" },
                { "name": "SQL Server Agent", "status": "online" },
                { "name": "SQL Browser", "status": "online" }
            ],
            "specs": {
                "cpu": "Intel Xeon E5-2690 v4",
                "cores": 14,
                "ram": "64GB DDR4",
                "storage": "4TB SSD RAID-10",
                "os": "Windows Server 2019"
            },
            "uptime": "99.98%",
            "lastReboot": "2023-09-15 02:00:00"
        },
        {
            "name": "VXDIRSRV",
            "ip": "172.16.1.151",
            "services": [
                { "name": "VoxcoDirectoryService", "status": "online" },
                { "name": "Voxco.InstallationService.exe", "status": "online" },
                { "name": "Active Directory Services", "status": "online" },
                { "name": "DNS Server", "status": "online" }
            ],
            "specs": {
                "cpu": "Intel Xeon E5-2680 v3",
                "cores": 12,
                "ram": "32GB DDR4",
                "storage": "2TB SSD RAID-1",
                "os": "Windows Server 2016"
            },
            "uptime": "99.95%",
            "lastReboot": "2023-10-02 01:30:00"
        }
    ]

def save_servers_data(servers):
    """Save servers data to file"""
    try:
        with open(SERVERS_FILE, 'w') as f:
            json.dump(servers, f, indent=2)
        return True
    except IOError as e:
        print(f"Error saving servers data: {e}")
        return False

def load_config_data():
    """Load configuration data from file or return default data if file doesn't exist"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            print(f"Error loading config data: {e}")
    
    # Default config data if file doesn't exist or is invalid
    return {
        "API_BASE_URL": f"http://{os.getenv('API_HOST', 'localhost')}:{os.getenv('PORT', '5001')}/api",
        "POLLING_INTERVAL": int(os.getenv('POLLING_INTERVAL', 10000)),
        "AUTH_TOKEN_KEY": "voxco_auth_token",
        "MAX_RECONNECT_ATTEMPTS": int(os.getenv('MAX_RECONNECT_ATTEMPTS', 5))
    }

def save_config_data(config):
    """Save configuration data to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        return True
    except IOError as e:
        print(f"Error saving config data: {e}")
        return False

def fetch_live_server_status():
    """Fetch live server status or use stored data"""
    servers = load_servers_data()
    
    # In a real implementation, you would update the status of each server
    # by querying them. For now, we'll just return the stored data.
    return servers

def execute_winrm_command(server_ip, command):
    winrm_port = os.getenv('WINRM_PORT', 5985)
    winrm_username = os.getenv('WINRM_USERNAME', 'username')
    winrm_password = os.getenv('WINRM_PASSWORD', 'password')
    session = winrm.Session(f'http://{server_ip}:{winrm_port}/wsman', auth=(winrm_username, winrm_password))
    response = session.run_cmd(command)
    return response.status_code, response.std_out.decode(), response.std_err.decode()

@app.route('/api/services/start', methods=['POST'])
def start_service():
    data = request.get_json()
    server_ip = data.get('ip')
    service_name = data.get('service')
    command = f'sc start {service_name}'
    status_code, std_out, std_err = execute_winrm_command(server_ip, command)
    if status_code == 0:
        return jsonify({'status': 'Service started', 'output': std_out})
    else:
        return jsonify({'status': 'Failed to start service', 'error': std_err}), 500

@app.route('/api/services/stop', methods=['POST'])
def stop_service():
    data = request.get_json()
    server_ip = data.get('ip')
    service_name = data.get('service')
    command = f'sc stop {service_name}'
    status_code, std_out, std_err = execute_winrm_command(server_ip, command)
    if status_code == 0:
        return jsonify({'status': 'Service stopped', 'output': std_out})
    else:
        return jsonify({'status': 'Failed to stop service', 'error': std_err}), 500

@app.route('/api/services/status', methods=['POST'])
def get_service_status():
    data = request.get_json()
    server_ip = data.get('ip')
    service_name = data.get('service')
    command = f'sc query {service_name}'
    status_code, std_out, std_err = execute_winrm_command(server_ip, command)
    if status_code == 0:
        return jsonify({'status': 'Service status retrieved', 'output': std_out})
    else:
        return jsonify({'status': 'Failed to retrieve service status', 'error': std_err}), 500

@app.route('/api/server/status', methods=['POST'])
def get_server_status():
    data = request.get_json()
    server_ip = data.get('ip')
    command = 'systeminfo'
    status_code, std_out, std_err = execute_winrm_command(server_ip, command)
    if status_code == 0:
        return jsonify({'status': 'Server status retrieved', 'output': std_out})
    else:
        return jsonify({'status': 'Failed to retrieve server status', 'error': std_err}), 500

@app.route('/api/winrm/status', methods=['GET'])
def get_winrm_status():
    server_ip = request.args.get('ip')
    if not server_ip:
        return jsonify({'status': 'Failed', 'error': 'Server IP is required'}), 400
    try:
        # Attempt to execute a simple command to check WINRM connection
        status_code, _, _ = execute_winrm_command(server_ip, 'echo WINRM Test')
        if status_code == 0:
            return jsonify({'status': 'Connected'})
        else:
            return jsonify({'status': 'Disconnected'}), 500
    except Exception as e:
        return jsonify({'status': 'Error', 'error': str(e)}), 500

@app.route('/api/servers', methods=['GET'])
def get_servers():
    return jsonify(fetch_live_server_status())

@app.route('/api/servers', methods=['POST'])
def save_servers():
    """Save server data from admin interface"""
    data = request.get_json()
    if not isinstance(data, list):
        return jsonify({'error': 'Invalid server data format'}), 400
    
    if save_servers_data(data):
        # Broadcast the update to all connected clients
        socketio.emit('server-update', {'servers': data})
        return jsonify({'message': 'Server data saved successfully'})
    else:
        return jsonify({'error': 'Failed to save server data'}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get configuration data for admin interface"""
    return jsonify(load_config_data())

@app.route('/api/config', methods=['POST'])
def save_config():
    """Save configuration data from admin interface"""
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({'error': 'Invalid configuration data format'}), 400
    
    if save_config_data(data):
        return jsonify({'message': 'Configuration saved successfully'})
    else:
        return jsonify({'error': 'Failed to save configuration'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Get server statistics"""
    servers = fetch_live_server_status()
    
    # Calculate statistics
    total_servers = len(servers)
    total_services = sum(len(server.get('services', [])) for server in servers)
    online_services = sum(1 for server in servers for service in server.get('services', []) if service.get('status') == 'online')
    warning_services = sum(1 for server in servers for service in server.get('services', []) if service.get('status') == 'warning')
    offline_services = sum(1 for server in servers for service in server.get('services', []) if service.get('status') == 'offline')
    
    # Calculate uptime percentage
    uptime_percentage = round((online_services / total_services) * 100) if total_services > 0 else 0
    
    return jsonify({
        'total_servers': total_servers,
        'total_services': total_services,
        'online_services': online_services,
        'warning_services': warning_services,
        'offline_services': offline_services,
        'uptime_percentage': uptime_percentage,
        'avg_cpu_usage': 45,  # Placeholder values
        'avg_memory_usage': 62,
        'avg_disk_usage': 58
    })

if __name__ == '__main__':
    # Use a dynamic port with preference for 3000-3005
    port = find_free_port(preferred_range=(3000, 3005))
    save_port('server', port)
    print(f"Starting server on port {port}")
    socketio.run(app, debug=True, port=port)
