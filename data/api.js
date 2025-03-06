// API integration for Voxco Server Monitoring Dashboard
window.API = (function() {
  // Configuration
  const API_BASE_URL = 'http://localhost:5001/api';
  const POLLING_INTERVAL = 10000; // 10 seconds
  
  // Authentication state
  let authToken = localStorage.getItem('voxco_auth_token');
  let currentUser = null;
  let pollingInterval = null;
  let reconnectAttempts = 0;
  const MAX_RECONNECT_ATTEMPTS = 5;
  
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
        localStorage.removeItem('voxco_auth_token');
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
        localStorage.removeItem('voxco_auth_token');
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
      
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
      });
      
      const data = await response.json();
      
      if (response.ok && data.token) {
        authToken = data.token;
        localStorage.setItem('voxco_auth_token', authToken);
        currentUser = username;
        
        // Initialize polling after successful login
        initializePolling();
        
        triggerEvent('auth-change', { authenticated: true, user: username });
        return { success: true, user: username };
      } else {
        triggerEvent('connection-status', { connected: false, connecting: false });
        return { success: false, error: data.message || 'Login failed' };
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
    localStorage.removeItem('voxco_auth_token');
    
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
    
    // Logs
    getLogs
  };
})();