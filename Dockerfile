FROM node:16-alpine

# Install Python and required packages
RUN apk add --no-cache python3 py3-pip bash curl

# Set working directory
WORKDIR /app

# Copy package files and install Node.js dependencies
COPY package*.json ./
RUN npm install

# Copy Python requirements and install dependencies
COPY requirements.txt ./
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Make scripts executable
RUN chmod +x start.sh stop.sh

# Generate frontend configuration
RUN node generate-frontend-config.js

# Create logs, pids, and ports directories
RUN mkdir -p logs pids ports

# Expose ports
EXPOSE 3000 5001 5002

# Set environment variables
ENV NODE_ENV=production \
    PYTHONUNBUFFERED=1 \
    PORT=5001 \
    API_PORT=5002 \
    CORS_ALLOWED_ORIGINS=* \
    SECRET_KEY=balena_deployment_secret_key \
    JWT_EXPIRATION_SECONDS=3600 \
    ADMIN_USERNAME=admin \
    ADMIN_PASSWORD=admin

# Create a special start script for Balena
RUN echo '#!/bin/sh' > start-balena.sh && \
    echo 'echo "Starting Voxco Server Monitoring Dashboard in Balena environment"' >> start-balena.sh && \
    echo 'node generate-frontend-config.js' >> start-balena.sh && \
    echo 'echo "Starting API server on port 5001..."' >> start-balena.sh && \
    echo 'python backend/simple_api_server.py --port 5001 > logs/simple_api_server.log 2>&1 &' >> start-balena.sh && \
    echo 'echo "Starting frontend server..."' >> start-balena.sh && \
    echo 'python frontend_server.py > logs/frontend.log 2>&1' >> start-balena.sh && \
    chmod +x start-balena.sh

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3000 || exit 1

# Start the application with the Balena-specific script
CMD ["sh", "start-balena.sh"]