# Docker Deployment for Voxco Server Monitoring Dashboard

This document provides instructions for deploying the Voxco Server Monitoring Dashboard using Docker.

## Prerequisites

- Docker Engine 19.03.0+
- Docker Compose 1.27.0+

## Configuration

Before deploying the application, make sure to configure the environment variables:

1. Copy the template environment file to create your own configuration:
   ```bash
   cp .env.template .env
   ```

2. Edit the `.env` file to set your specific configuration values:
   - Update the `SECRET_KEY` with a secure random string
   - Set appropriate credentials for `ADMIN_USERNAME` and `ADMIN_PASSWORD`
   - Configure WinRM settings if needed

## Docker Deployment

### Building and Starting the Application

To build and start the application in a Docker container:

```bash
docker-compose up -d
```

This command:
- Builds the Docker image if it doesn't exist
- Creates and starts the container in detached mode
- Maps the required ports (3000, 5001, 5002) to the host
- Mounts volumes for logs and data persistence

### Stopping the Application

To stop the running containers:

```bash
docker-compose down
```

### Viewing Logs

To view the logs from the container:

```bash
docker-compose logs -f
```

## Volume Persistence

The Docker Compose configuration mounts the following directories as volumes:

- `./logs:/app/logs` - For application logs
- `./data:/app/data` - For configuration and server data
- `./pids:/app/pids` - For process ID files
- `./ports:/app/ports` - For port configuration files

This ensures that your data persists even if the container is removed.

## Health Checks

The container includes a health check that verifies the frontend server is running properly. The health check:
- Runs every 30 seconds
- Has a 10-second timeout
- Allows 40 seconds for initial startup
- Retries 3 times before marking the container as unhealthy

## Networking

The application runs on a dedicated bridge network named `voxco-network`. This provides isolation and allows for future expansion with additional services if needed.

## Customization

### Changing Exposed Ports

If you need to change the ports exposed on the host, modify the `ports` section in the `docker-compose.yml` file:

```yaml
ports:
  - "8080:3000"  # Map host port 8080 to container port 3000
  - "8001:5001"  # Map host port 8001 to container port 5001
  - "8002:5002"  # Map host port 8002 to container port 5002
```

### Adding Custom Environment Variables

To add custom environment variables, you can either:

1. Add them to your `.env` file, or
2. Add them directly to the `environment` section in `docker-compose.yml`

## Troubleshooting

### Container Fails to Start

If the container fails to start, check the logs:

```bash
docker-compose logs
```

Common issues include:
- Port conflicts (another service is using the same port)
- Missing or incorrect environment variables
- Permission issues with mounted volumes

### Health Check Failures

If the health check fails, the container will be marked as unhealthy. Check:
- If the frontend server is running inside the container
- If there are any errors in the application logs
- If the ports are correctly mapped

## Production Deployment Recommendations

For production environments:
1. Use a reverse proxy like Nginx to handle HTTPS
2. Set up proper backup procedures for the data directory
3. Configure monitoring and alerting for the container
4. Consider using Docker Swarm or Kubernetes for high availability
