# Voxco Server Monitoring Dashboard - Deployment Guide

This guide provides instructions for deploying the Voxco Server Monitoring Dashboard in various environments.

## Deployment Options

### 1. Basic Deployment (Development/Testing)

The simplest deployment method using the built-in scripts:

```bash
./start.sh
```

This starts a basic HTTP server on port 3000 and the backend servers on their configured ports.

### 2. Production Deployment with PM2

For a more robust production deployment, use PM2 to manage the Node.js and Python processes:

1. Install PM2:

```bash
npm install -g pm2
```

2. Create a PM2 ecosystem file (`ecosystem.config.js`):

```javascript
module.exports = {
  apps: [
    {
      name: "voxco-frontend",
      script: "python",
      args: "-m http.server 3000",
      cwd: "/path/to/voxco-dashboard",
      env: {
        NODE_ENV: "production"
      }
    },
    {
      name: "voxco-backend-server",
      script: "python",
      args: "backend/server.py",
      cwd: "/path/to/voxco-dashboard",
      env: {
        NODE_ENV: "production"
      }
    },
    {
      name: "voxco-backend-server-improved",
      script: "python",
      args: "backend/server_improved.py",
      cwd: "/path/to/voxco-dashboard",
      env: {
        NODE_ENV: "production"
      }
    },
    {
      name: "voxco-api-server",
      script: "python",
      args: "backend/simple_api_server.py",
      cwd: "/path/to/voxco-dashboard",
      env: {
        NODE_ENV: "production"
      }
    },
    {
      name: "voxco-simple-server",
      script: "python",
      args: "backend/simple_server.py",
      cwd: "/path/to/voxco-dashboard",
      env: {
        NODE_ENV: "production"
      }
    }
  ]
};
```

3. Start the application with PM2:

```bash
pm2 start ecosystem.config.js
```

4. Configure PM2 to start on system boot:

```bash
pm2 startup
pm2 save
```

### 3. Docker Deployment

For containerized deployment:

1. Create a `Dockerfile`:

```dockerfile
FROM node:16-alpine

# Install Python
RUN apk add --no-cache python3 py3-pip

# Set working directory
WORKDIR /app

# Copy package files and install Node.js dependencies
COPY package*.json ./
RUN npm install

# Copy Python requirements and install dependencies
COPY requirements.txt ./
RUN pip3 install -r requirements.txt

# Copy application files
COPY . .

# Generate frontend configuration
RUN node generate-frontend-config.js

# Expose ports
EXPOSE 3000 5001 5002

# Start the application
CMD ["sh", "start.sh"]
```

2. Create a `docker-compose.yml` file for easier management:

```yaml
version: '3'

services:
  voxco-dashboard:
    build: .
    ports:
      - "3000:3000"
      - "5001:5001"
      - "5002:5002"
    volumes:
      - ./logs:/app/logs
    env_file:
      - .env
    restart: unless-stopped
```

3. Build and start the Docker container:

```bash
docker-compose up -d
```

### 4. Deployment with Nginx Reverse Proxy (Recommended for Production)

For a secure production deployment with HTTPS:

1. Install Nginx:

```bash
# Ubuntu/Debian
sudo apt-get install nginx

# CentOS/RHEL
sudo yum install nginx
```

2. Create an Nginx configuration file (`/etc/nginx/sites-available/voxco-dashboard`):

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name your-domain.com;
    
    # SSL configuration
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    
    # Frontend proxy
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    
    # API proxy
    location /api/ {
        proxy_pass http://localhost:5001/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. Enable the site and restart Nginx:

```bash
# Ubuntu/Debian
sudo ln -s /etc/nginx/sites-available/voxco-dashboard /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# CentOS/RHEL
sudo systemctl restart nginx
```

4. Update your `.env` file to use the correct API_HOST and CORS settings.

## Admin Interface Deployment Considerations

The dashboard includes an admin interface for managing servers and settings. For production deployments, consider the following:

1. **Access Control**: Restrict access to the admin interface to authorized personnel only
2. **Data Persistence**: The admin interface saves data to:
   - `data/servers_data.json` - Server configurations
   - `data/config_data.json` - Application settings
3. **Backup Strategy**: Regularly backup these data files to prevent data loss
4. **Volume Mounting**: When using Docker, ensure these files are persisted with proper volume mounts:
   ```yaml
   volumes:
     - ./data:/app/data
     - ./logs:/app/logs
   ```
5. **Permission Management**: Ensure the application has write permissions to the data directory

## Scaling Considerations

For larger deployments:

1. **Database Backend**: Consider moving server data to a database like MongoDB or PostgreSQL
2. **Load Balancing**: Use multiple instances behind a load balancer
3. **Microservices**: Split the backend into separate microservices
4. **Caching**: Implement Redis for caching frequently accessed data

## Monitoring and Maintenance

1. **Logging**: Configure centralized logging with ELK stack or similar
2. **Monitoring**: Set up Prometheus and Grafana for monitoring
3. **Backups**: Implement regular backups of configuration and data
4. **Updates**: Establish a process for regular updates and security patches

## Security Checklist

- [ ] SSL/TLS encryption enabled
- [ ] Strong admin credentials set
- [ ] Firewall rules configured
- [ ] Regular security updates applied
- [ ] Access logs monitored
- [ ] Authentication for all endpoints
- [ ] Rate limiting implemented
- [ ] Admin interface access restricted
- [ ] Data files properly secured