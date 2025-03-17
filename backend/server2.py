from flask import Flask, jsonify, request, make_response
from flask_cors import CORS
# We'll remove emit from the import to avoid the corruption issue:
from flask_socketio import SocketIO
import winrm
import requests
import secrets
import os
import dotenv

# Load environment variables from .env file
dotenv.load_dotenv()

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
    # Use socketio.emit() not direct emit
    socketio.emit('server-update', data)
    return jsonify({'message': 'Real-time update broadcast'})

def fetch_live_server_status():
    servers = [
        {"name": "VXSQL1", "ip": "172.16.1.150"},
        {"name": "VXDIRSRV", "ip": "172.16.1.151"},
        {"name": "VXOADMIN", "ip": "172.16.1.160"},
        {"name": "VXSERVNO", "ip": "172.16.1.27"},
        {"name": "VXCATI1", "ip": "172.16.1.156"},
        {"name": "VXCATI2", "ip": "172.16.1.157"},
        {"name": "VXREPORT", "ip": "172.16.1.153"}
    ]
    live_status = []
    for server in servers:
        try:
            response = requests.get(f"http://{server['ip']}/status", timeout=5)
            server_status = response.json()
            live_status.append({
                "name": server["name"],
                "ip": server["ip"],
                "services": server_status.get("services", [])
            })
        except requests.RequestException:
            live_status.append({
                "name": server["name"],
                "ip": server["ip"],
                "services": [{"name": "Unknown", "status": "offline"}]
            })
    return live_status

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

@app.route('/api/servers', methods=['GET'])
def get_servers():
    return jsonify(fetch_live_server_status())

if __name__ == '__main__':
    port = int(os.getenv('SOCKET_PORT', 5000))
    socketio.run(app, debug=True, port=port)