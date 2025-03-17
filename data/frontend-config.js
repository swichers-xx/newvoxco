// Frontend configuration loaded from environment variables
window.FRONTEND_CONFIG = {
  // API configuration
  API_BASE_URL: 'http://localhost:5001/api', // Default value
  POLLING_INTERVAL: 10000, // 10 seconds
  
  // Authentication configuration
  AUTH_TOKEN_KEY: 'voxco_auth_token',
  
  // Connection configuration
  MAX_RECONNECT_ATTEMPTS: 5
};

// Function to update configuration from server
async function loadFrontendConfig() {
  try {
    const response = await fetch('/frontend-config.json');
    if (response.ok) {
      const config = await response.json();
      
      // Update configuration with values from server
      Object.assign(window.FRONTEND_CONFIG, config);
      
      console.log('Frontend configuration loaded from server');
    } else {
      console.warn('Failed to load frontend configuration from server, using defaults');
    }
  } catch (error) {
    console.warn('Error loading frontend configuration:', error);
  }
}

// Load configuration on startup
loadFrontendConfig();