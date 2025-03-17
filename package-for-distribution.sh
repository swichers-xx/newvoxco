#!/bin/bash

# Script to package the Voxco Server Monitoring Dashboard for distribution

# Set version
VERSION="1.0.0"
PACKAGE_NAME="voxco-server-monitoring-dashboard-${VERSION}"

# Create a temporary directory for packaging
echo "Creating package directory..."
mkdir -p dist/${PACKAGE_NAME}

# Copy necessary files
echo "Copying files..."
cp -r backend components data index.html package.json package-lock.json README.md INSTALL.md DEPLOYMENT.md .env.template generate-frontend-config.js setupWinRM.cmd start.sh stop.sh restart.sh dist/${PACKAGE_NAME}/

# Create logs and pids directories
mkdir -p dist/${PACKAGE_NAME}/logs
mkdir -p dist/${PACKAGE_NAME}/pids

# Remove any existing .env file to avoid distributing sensitive information
rm -f dist/${PACKAGE_NAME}/.env

# Create a requirements.txt file for Python dependencies
echo "Creating requirements.txt..."
cat > dist/${PACKAGE_NAME}/requirements.txt << EOF
flask==2.0.1
flask-cors==3.0.10
python-dotenv==0.19.0
requests==2.26.0
websockets==10.0
EOF

# Create a zip archive
echo "Creating zip archive..."
cd dist
zip -r ${PACKAGE_NAME}.zip ${PACKAGE_NAME}
cd ..

# Create a tarball
echo "Creating tarball..."
cd dist
tar -czf ${PACKAGE_NAME}.tar.gz ${PACKAGE_NAME}
cd ..

echo "Package created successfully:"
echo "- dist/${PACKAGE_NAME}.zip"
echo "- dist/${PACKAGE_NAME}.tar.gz"
echo ""
echo "Distribution package is ready for publication."