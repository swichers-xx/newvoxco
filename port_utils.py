#!/usr/bin/env python3
import socket
import os

def find_free_port(preferred_range=None):
    """
    Find a free port on the system, preferring ports in the given range if possible.
    
    Args:
        preferred_range (tuple): Optional tuple of (min_port, max_port) to try first
        
    Returns:
        int: An available port number
    """
    if preferred_range:
        # Try preferred range first
        for port in range(preferred_range[0], preferred_range[1] + 1):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
    
    # If no port in the preferred range is available, get any free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def save_port(service_name, port):
    """
    Save the port number to a file for the given service.
    
    Args:
        service_name (str): Name of the service
        port (int): Port number to save
    """
    # Create ports directory if it doesn't exist
    if not os.path.exists('ports'):
        os.makedirs('ports')
    
    # Write the port to a file
    with open(f'ports/{service_name}_port.txt', 'w') as f:
        f.write(str(port))
    
    return port

def get_port(service_name):
    """
    Get the port number for the given service from its port file.
    
    Args:
        service_name (str): Name of the service
        
    Returns:
        int or None: Port number if file exists, None otherwise
    """
    port_file = f'ports/{service_name}_port.txt'
    if os.path.exists(port_file):
        with open(port_file, 'r') as f:
            return int(f.read().strip())
    return None
