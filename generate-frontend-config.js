#!/usr/bin/env node

/**
 * This script generates the frontend-config.json file from the .env file.
 * It reads the environment variables and creates a JSON file with the configuration
 * that will be served to the frontend.
 */

const fs = require('fs');
const path = require('path');
const dotenv = require('dotenv');

// Load environment variables from .env file
dotenv.config();

// Function to read a port from a port file
function readPortFromFile(serviceName) {
  try {
    const portFile = path.join(__dirname, 'ports', `${serviceName}_port.txt`);
    if (fs.existsSync(portFile)) {
      return parseInt(fs.readFileSync(portFile, 'utf8').trim(), 10);
    }
  } catch (error) {
    console.error(`Error reading port for ${serviceName}:`, error);
  }
  return null;
}

// Get the port for the API server
const apiPort = readPortFromFile('simple_api_server') || 
                readPortFromFile('server_improved') || 
                readPortFromFile('server') || 
                parseInt(process.env.PORT || 5000, 10);

// Define the frontend configuration
const frontendConfig = {
  // API configuration
  API_BASE_URL: `http://${process.env.API_HOST || 'localhost'}:${apiPort}/api`,
  POLLING_INTERVAL: parseInt(process.env.POLLING_INTERVAL || 10000, 10),
  
  // Authentication configuration
  AUTH_TOKEN_KEY: 'voxco_auth_token',
  
  // Connection configuration
  MAX_RECONNECT_ATTEMPTS: parseInt(process.env.MAX_RECONNECT_ATTEMPTS || 5, 10)
};

// Write the configuration to a JSON file
fs.writeFileSync(
  path.join(__dirname, 'frontend-config.json'),
  JSON.stringify(frontendConfig, null, 2)
);

console.log('Frontend configuration generated successfully.');