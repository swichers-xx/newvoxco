# Voxco Server Monitoring Dashboard - Installation Guide

This guide provides step-by-step instructions for installing and configuring the Voxco Server Monitoring Dashboard.

## Prerequisites

- Node.js (v14 or higher)
- Python (v3.6 or higher)
- Windows servers with WinRM enabled (for remote monitoring)

## Installation Steps

### 1. Clone or Download the Repository

Download and extract the application package to your desired location.

### 2. Install Dependencies

```bash
# Install Node.js dependencies
npm install

# Install Python dependencies (if applicable)
pip install -r requirements.txt
```

### 3. Configure the Application

1. Copy the template environment file:

```bash
cp .env.template .env
```

2. Edit the `.env` file and update the following settings:

   - **Security Settings**:
     - Generate a new SECRET_KEY (you can use the command provided in the template)
     - Update ADMIN_USERNAME and ADMIN_PASSWORD with secure credentials

   - **WinRM Credentials**:
     - Set WINRM_HOST to your Windows server hostname or IP
     - Set WINRM_USERNAME and WINRM_PASSWORD to valid Windows credentials

   - **Server URL Configuration**:
     - Set API_HOST to the hostname or IP address where the application will be running

   - **Other Settings**:
     - Adjust PORT, SOCKET_PORT, and API_PORT if needed
     - Update CORS_ALLOWED_ORIGINS to include your frontend URL

### 4. Configure Windows Servers for WinRM (if needed)

If your Windows servers don't have WinRM configured:

1. Copy the `setupWinRM.cmd` script to each Windows server
2. Run the script as Administrator on each server

### 5. Start the Application

```bash
# Start all servers
./start.sh
```

The dashboard will be available at `http://localhost:3000` (or the hostname/IP you configured).

### 6. Using the Admin Interface

The dashboard includes an admin interface for managing servers and settings:

1. Log in to the dashboard using your admin credentials
2. Click the "Admin" button in the top-right corner
3. Use the admin interface to:
   - Add, edit, or remove servers
   - Add or remove services for each server
   - Configure application settings

All changes made through the admin interface are saved to the server and will persist across restarts.

### 7. Stop the Application

```bash
# Stop all servers
./stop.sh
```

## Troubleshooting

- **Connection Issues**: Ensure WinRM is properly configured on Windows servers
- **Authentication Failures**: Verify the credentials in the `.env` file
- **Server Startup Failures**: Check the logs in the `logs` directory

## Security Recommendations

1. **Use HTTPS**: For production deployments, configure a reverse proxy (like Nginx) with SSL/TLS
2. **Secure Credentials**: Use strong passwords for admin and WinRM accounts
3. **Network Security**: Restrict access to the dashboard using firewalls
4. **Regular Updates**: Keep the application and its dependencies updated

## Production Deployment

For production environments, consider:

1. Using a process manager like PM2 for Node.js applications
2. Setting up a reverse proxy with Nginx or Apache
3. Implementing proper logging and monitoring
4. Configuring automatic backups
5. Setting up SSL/TLS for secure communication