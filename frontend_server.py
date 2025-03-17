#!/usr/bin/env python3
import http.server
import socketserver
import os
import sys
from port_utils import find_free_port, save_port

# Use a dynamic port with preference for 3000-3005
PORT = find_free_port(preferred_range=(3000, 3005))
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class SPAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def do_GET(self):
        print(f"Received request for path: {self.path}")
        
        # Serve admin.html for /admin path
        if self.path == '/admin':
            print(f"Serving admin.html for {self.path}")
            self.path = '/admin.html'
        # For SPA routing, redirect all paths to index.html
        # except for files that actually exist
        elif not os.path.exists(os.path.join(DIRECTORY, self.path.lstrip('/'))) and not self.path.startswith('/api/'):
            print(f"Redirecting {self.path} to /index.html")
            self.path = '/index.html'
        
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

def run_server():
    handler = SPAHandler
    print(f"Starting server at http://localhost:{PORT}")
    print(f"Serving files from: {DIRECTORY}")
    
    # Save the port to a file
    save_port('frontend', PORT)
    
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Server running at http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    run_server()
