// API integration for Voxco Server Monitoring Dashboard
window.API = (function() {
  // Get configuration from frontend-config.js
  const API_BASE_URL = window.FRONTEND_CONFIG.API_BASE_URL;
  const POLLING_INTERVAL = window.FRONTEND_CONFIG.POLLING_INTERVAL;
  const MAX_RECONNECT_ATTEMPTS = window.FRONTEND_CONFIG.MAX_RECONNECT_ATTEMPTS;
  const AUTH_TOKEN_KEY = window.FRONTEND_CONFIG.AUTH_TOKEN_KEY;
// WINRM connection status
async function getWinRMStatus(serverIp) {
  try {
    const response = await fetchWithAuth(`/api/winrm/status?ip=${serverIp}`);
    if (response.ok) {
      const data = await response.json();
      return data.status;
    } else {
      const error = await response.json();
      throw new Error(error.error || 'Failed to fetch WINRM status');
    }
  } catch (error) {
    console.error('Error fetching WINRM status:', error);
    throw error;
  }
}

  // Authentication state
  let authToken = localStorage.getItem(AUTH_TOKEN_KEY);
  let currentUser = null;
  let pollingInterval = null;
  let reconnectAttempts = 0;
  
  // Event listeners
  const eventListeners = {
    'auth-change': [],
    'server-update': [],
    'service-update': [],
    'server-reboot': [],
    'connection-status': []
  };
  
  // Helper function for authenticated API calls
  async function fetchWithAuth(endpoint, options = {}) {
    if (!authToken) {
      throw new Error('Authentication required');
    }
    
    const headers = {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`,
      ...options.headers
    };
    
    try {
      const response = await fetch(`${API_BASE_URL}${endpoint}`, {
        ...options,
        headers
      });
      
      if (response.status === 401) {
        // Token expired or invalid
        authToken = null;
        localStorage.removeItem(AUTH_TOKEN_KEY);
        triggerEvent('auth-change', { authenticated: false });
        throw new Error('Authentication token expired');
      }
      
      return response;
    } catch (error) {
      console.error('API request failed:', error);
      throw error;
    }
  }
  
  // Event handling
  function addEventListener(event, callback) {
    if (eventListeners[event]) {
      eventListeners[event].push(callback);
      return true;
    }
    return false;
  }
  
  function removeEventListener(event, callback) {
    if (eventListeners[event]) {
      eventListeners[event] = eventListeners[event].filter(cb => cb !== callback);
      return true;
    }
    return false;
  }
  
  function triggerEvent(event, data) {
    if (eventListeners[event]) {
      eventListeners[event].forEach(callback => callback(data));
    }
  }
  
  // Initialize polling for server updates
  function initializePolling() {
    if (!authToken) return;
    
    if (pollingInterval) {
      clearInterval(pollingInterval);
    }
    
    // Reset reconnect attempts
    reconnectAttempts = 0;
    
    // Set connection status to connected
    triggerEvent('connection-status', { connected: true });
    
    // Start polling for server updates
    pollingInterval = setInterval(pollServerData, POLLING_INTERVAL);
    
    // Immediately poll once to get initial data
    pollServerData();
    
    return true;
  }
  
  // Poll server data with reconnection logic
  async function pollServerData() {
    if (!authToken) return;
    
    try {
      // Fetch server data
      const servers = await getServers();
      
      // Fetch stats data
      const stats = await getStats();
      
      // Reset reconnect attempts on successful connection
      if (reconnectAttempts > 0) {
        reconnectAttempts = 0;
        console.log('Connection restored');
      }
      
      // Trigger server update event
      triggerEvent('server-update', { servers });
      
      // Set connection status to connected
      triggerEvent('connection-status', { connected: true });
    } catch (error) {
      console.error('Polling error:', error);
      
      // Increment reconnect attempts
      reconnectAttempts++;
      
      // Update connection status
      triggerEvent('connection-status', {
        connected: false,
        error,
        reconnecting: reconnectAttempts <= MAX_RECONNECT_ATTEMPTS,
        attempts: reconnectAttempts
      });
      
      // If max reconnect attempts reached, stop polling
      if (reconnectAttempts > MAX_RECONNECT_ATTEMPTS) {
        console.error(`Max reconnect attempts (${MAX_RECONNECT_ATTEMPTS}) reached. Stopping polling.`);
        clearInterval(pollingInterval);
        pollingInterval = null;
        
        // Notify user that connection is lost
        triggerEvent('auth-change', {
          authenticated: false,
          error: 'Connection lost. Please log in again.'
        });
        
        // Clear auth token
        authToken = null;
        localStorage.removeItem(AUTH_TOKEN_KEY);
      }
    }
  }
  
  // Authentication
  async function login(username, password) {
    try {
      // Clear any previous auth state
      if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
      }
      
      // Set initial connection status
      triggerEvent('connection-status', { connected: false, connecting: true });
      
      console.log(`Attempting login to ${API_BASE_URL}/login`);
      
      // For demo purposes, allow admin/admin login without server
      if (username === 'admin' && password === 'admin') {
        console.log('Using demo login credentials');
        
        // Create a demo token
        const demoToken = 'demo_token_' + Date.now();
        authToken = demoToken;
        localStorage.setItem(AUTH_TOKEN_KEY, authToken);
        currentUser = username;
        
        // Initialize polling after successful login
        initializePolling();
        
        triggerEvent('auth-change', { authenticated: true, user: username });
        return { success: true, user: username };
      }
      
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });
      
      let data;
      try {
        data = await response.json();
      } catch (parseError) {
        console.error('Error parsing login response:', parseError);
        data = { message: 'Invalid response from server' };
      }
      
      if (response.ok && data && data.token) {
        authToken = data.token;
        localStorage.setItem(AUTH_TOKEN_KEY, authToken);
        currentUser = username;
        
        // Initialize polling after successful login
        initializePolling();
        
        triggerEvent('auth-change', { authenticated: true, user: username });
        return { success: true, user: username };
      } else {
        console.error('Login failed:', response.status, data);
        triggerEvent('connection-status', { connected: false, connecting: false });
        return { success: false, error: data?.message || 'Login failed. Check your credentials.' };
      }
    } catch (error) {
      console.error('Login error:', error);
      triggerEvent('connection-status', { connected: false, connecting: false });
      return { success: false, error: 'Connection error. Please check if the server is running.' };
    }
  }
  
  function logout() {
    authToken = null;
    currentUser = null;
    localStorage.removeItem(AUTH_TOKEN_KEY);
    
    if (pollingInterval) {
      clearInterval(pollingInterval);
      pollingInterval = null;
    }
    
    triggerEvent('auth-change', { authenticated: false });
    triggerEvent('connection-status', { connected: false });
    return true;
  }
  
  function isAuthenticated() {
    return !!authToken;
  }
  
  // Server data
  async function getServers(filters = {}) {
    try {
      let url = '/servers';
      const queryParams = [];
      
      if (filters.search) {
        queryParams.push(`search=${encodeURIComponent(filters.search)}`);
      }
      
      if (filters.status) {
        queryParams.push(`status=${encodeURIComponent(filters.status)}`);
      }
      
      if (queryParams.length > 0) {
        url += `?${queryParams.join('&')}`;
      }
      
      const response = await fetchWithAuth(url);
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch servers');
      }
    } catch (error) {
      console.error('Error fetching servers:', error);
      throw error;
    }
  }
  
  async function getServerDetails(serverName) {
    try {
      const response = await fetchWithAuth(`/servers/${serverName}`);
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch server details');
      }
    } catch (error) {
      console.error(`Error fetching details for server ${serverName}:`, error);
      throw error;
    }
  }
  
  // Service management
  async function startService(serverName, serviceName) {
    try {
      const response = await fetchWithAuth('/services/start', {
        method: 'POST',
        body: JSON.stringify({
          server: serverName,
          service: serviceName
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        
        // Trigger service update event
        triggerEvent('service-update', {
          server: serverName,
          service: serviceName,
          status: 'online',
          timestamp: new Date().toISOString(),
          user: currentUser
        });
        
        return result;
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to start service');
      }
    } catch (error) {
      console.error(`Error starting service ${serviceName} on ${serverName}:`, error);
      throw error;
    }
  }
  
  async function stopService(serverName, serviceName) {
    try {
      const response = await fetchWithAuth('/services/stop', {
        method: 'POST',
        body: JSON.stringify({
          server: serverName,
          service: serviceName
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        
        // Trigger service update event
        triggerEvent('service-update', {
          server: serverName,
          service: serviceName,
          status: 'offline',
          timestamp: new Date().toISOString(),
          user: currentUser
        });
        
        return result;
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to stop service');
      }
    } catch (error) {
      console.error(`Error stopping service ${serviceName} on ${serverName}:`, error);
      throw error;
    }
  }
  
  async function restartService(serverName, serviceName) {
    try {
      const response = await fetchWithAuth('/services/restart', {
        method: 'POST',
        body: JSON.stringify({
          server: serverName,
          service: serviceName
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        
        // Trigger service update event
        triggerEvent('service-update', {
          server: serverName,
          service: serviceName,
          status: 'online',
          timestamp: new Date().toISOString(),
          user: currentUser
        });
        
        return result;
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to restart service');
      }
    } catch (error) {
      console.error(`Error restarting service ${serviceName} on ${serverName}:`, error);
      throw error;
    }
  }
  
  // Server reboot
  async function rebootServer(serverName, force = false) {
    try {
      const response = await fetchWithAuth('/server/reboot', {
        method: 'POST',
        body: JSON.stringify({
          server: serverName,
          force: force
        })
      });
      
      if (response.ok) {
        const result = await response.json();
        
        // Trigger server reboot event
        triggerEvent('server-reboot', {
          server: serverName,
          timestamp: new Date().toISOString(),
          user: currentUser
        });
        
        return result;
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to reboot server');
      }
    } catch (error) {
      console.error(`Error rebooting server ${serverName}:`, error);
      throw error;
    }
  }
  
  // Statistics
  async function getStats() {
    try {
      const response = await fetchWithAuth('/stats');
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch statistics');
      }
    } catch (error) {
      console.error('Error fetching statistics:', error);
      throw error;
    }
  }
  
  // Admin Interface Functions
  async function saveServers(servers) {
    try {
      const response = await fetchWithAuth('/servers', {
        method: 'POST',
        body: JSON.stringify(servers)
      });
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to save servers');
      }
    } catch (error) {
      console.error('Error saving servers:', error);
      throw error;
    }
  }
  
  async function getConfig() {
    try {
      const response = await fetchWithAuth('/config');
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch configuration');
      }
    } catch (error) {
      console.error('Error fetching configuration:', error);
      throw error;
    }
  }
  
  async function saveConfig(config) {
    try {
      const response = await fetchWithAuth('/config', {
        method: 'POST',
        body: JSON.stringify(config)
      });
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to save configuration');
      }
    } catch (error) {
      console.error('Error saving configuration:', error);
      throw error;
    }
  }
  
  // Logs
  async function getLogs(filters = {}) {
    try {
      let url = '/logs';
      const queryParams = [];
      
      if (filters.limit) {
        queryParams.push(`limit=${filters.limit}`);
      }
      
      if (filters.server) {
        queryParams.push(`server=${encodeURIComponent(filters.server)}`);
      }
      
      if (filters.service) {
        queryParams.push(`service=${encodeURIComponent(filters.service)}`);
      }
      
      if (filters.level) {
        queryParams.push(`level=${encodeURIComponent(filters.level)}`);
      }
      
      if (queryParams.length > 0) {
        url += `?${queryParams.join('&')}`;
      }
      
      const response = await fetchWithAuth(url);
      
      if (response.ok) {
        return await response.json();
      } else {
        const error = await response.json();
        throw new Error(error.error || 'Failed to fetch logs');
      }
    } catch (error) {
      console.error('Error fetching logs:', error);
      throw error;
    }
  }
  
  // WinRM Configuration
  async function getWinRMConfig() {
    try {
      const response = await fetchWithAuth('/winrm/config');
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get WinRM configuration');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting WinRM configuration:', error);
      throw error;
    }
  }

  async function saveWinRMConfig(config) {
    try {
      const response = await fetchWithAuth('/winrm/config', {
        method: 'POST',
        body: JSON.stringify(config)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to save WinRM configuration');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error saving WinRM configuration:', error);
      throw error;
    }
  }

  async function testWinRMConnection(server) {
    try {
      const response = await fetchWithAuth('/winrm/test', {
        method: 'POST',
        body: JSON.stringify({ server })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to test WinRM connection');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error testing WinRM connection:', error);
      throw error;
    }
  }

  async function getServerInfoWinRM(serverIp) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/info`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get server information');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting server information:', error);
      throw error;
    }
  }

  async function getServerMetricsWinRM(serverIp) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/metrics`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get server metrics');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting server metrics:', error);
      throw error;
    }
  }

  async function getServicesWinRM(serverIp) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/services`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get services');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting services:', error);
      throw error;
    }
  }

  async function getServiceStatusWinRM(serverIp, serviceName) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/service/${serviceName}/status`);
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to get service status');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error getting service status:', error);
      throw error;
    }
  }

  async function startServiceWinRM(serverIp, serviceName) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/service/${serviceName}/start`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start service');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error starting service:', error);
      throw error;
    }
  }

  async function stopServiceWinRM(serverIp, serviceName) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/service/${serviceName}/stop`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to stop service');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error stopping service:', error);
      throw error;
    }
  }

  async function restartServiceWinRM(serverIp, serviceName) {
    try {
      const response = await fetchWithAuth(`/winrm/server/${serverIp}/service/${serviceName}/restart`, {
        method: 'POST'
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to restart service');
      }
      
      return await response.json();
    } catch (error) {
      console.error('Error restarting service:', error);
      throw error;
    }
  }

  // WinRM-specific functions
  
  // Get WinRM configuration
  async function getWinRMConfig() {
    try {
      const response = await fetchWithAuth('/api/winrm/config');
      return response;
    } catch (error) {
      console.error('Error getting WinRM config:', error);
      throw error;
    }
  }
  
  // Save WinRM configuration
  async function saveWinRMConfig(config) {
    try {
      const response = await fetchWithAuth('/api/winrm/config', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(config)
      });
      return response;
    } catch (error) {
      console.error('Error saving WinRM config:', error);
      throw error;
    }
  }
  
  // Get WinRM status
  async function getWinRMStatus() {
    try {
      const response = await fetchWithAuth('/api/winrm/status');
      return response;
    } catch (error) {
      console.error('Error getting WinRM status:', error);
      throw error;
    }
  }
  
  // Test WinRM connection to a server
  async function testWinRMConnection(server) {
    try {
      const response = await fetchWithAuth(`/api/winrm/test?server=${server}`);
      return response;
    } catch (error) {
      console.error('Error testing WinRM connection:', error);
      throw error;
    }
  }
  
  // Get server metrics using WinRM
  async function getServerMetricsWinRM(server) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/metrics`);
      return response;
    } catch (error) {
      console.error('Error getting server metrics via WinRM:', error);
      throw error;
    }
  }
  
  // Get server information using WinRM
  async function getServerInfoWinRM(server) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/info`);
      return response;
    } catch (error) {
      console.error('Error getting server info via WinRM:', error);
      throw error;
    }
  }
  
  // Get all services from a server using WinRM
  async function getServicesWinRM(server) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/services`);
      return response;
    } catch (error) {
      console.error('Error getting services via WinRM:', error);
      throw error;
    }
  }
  
  // Start a service on a server using WinRM
  async function startServiceWinRM(server, service) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/service/${service}/start`, {
        method: 'POST'
      });
      return response;
    } catch (error) {
      console.error('Error starting service via WinRM:', error);
      throw error;
    }
  }
  
  // Stop a service on a server using WinRM
  async function stopServiceWinRM(server, service) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/service/${service}/stop`, {
        method: 'POST'
      });
      return response;
    } catch (error) {
      console.error('Error stopping service via WinRM:', error);
      throw error;
    }
  }
  
  // Restart a service on a server using WinRM
  async function restartServiceWinRM(server, service) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/service/${service}/restart`, {
        method: 'POST'
      });
      return response;
    } catch (error) {
      console.error('Error restarting service via WinRM:', error);
      throw error;
    }
  }
  
  // Reboot a server using WinRM
  async function rebootServer(server) {
    try {
      const response = await fetchWithAuth(`/api/winrm/server/${server}/reboot`, {
        method: 'POST'
      });
      return response;
    } catch (error) {
      console.error('Error rebooting server via WinRM:', error);
      throw error;
    }
  }
  
  // Initialize on load - try to connect if token exists
  if (authToken) {
    initializePolling();
  }
  
  // Public API
  return {
    // Authentication
    login,
    logout,
    isAuthenticated,
    
    // Event handling
    addEventListener,
    removeEventListener,
    
    // Server data
    getServers,
    getServerDetails,
    
    // Service management
    startService,
    stopService,
    restartService,
    
    // Server reboot
    rebootServer,
    
    // Statistics
    getStats,
    
    // Admin Interface
    saveServers,
    getConfig,
    saveConfig,
    
    // Logs
    getLogs,
    
    // WinRM Status
    getWinRMStatus,
    
    // WinRM Configuration
    getWinRMConfig,
    saveWinRMConfig,
    testWinRMConnection,
    getServerInfoWinRM,
    getServerMetricsWinRM,
    getServicesWinRM,
    getServiceStatusWinRM,
    startServiceWinRM,
    stopServiceWinRM,
    restartServiceWinRM,
    
    // WinRM-specific functions
    getWinRMConfig,
    saveWinRMConfig,
    getWinRMStatus,
    testWinRMConnection,
    getServerMetricsWinRM,
    getServerInfoWinRM,
    getServicesWinRM,
    startServiceWinRM,
    stopServiceWinRM,
    restartServiceWinRM,
    rebootServer
  };
})();