// AdminInterface.jsx - Admin interface for managing servers and settings
window.AdminInterface = function AdminInterface({ onClose, servers, onUpdateServers, config, onUpdateConfig }) {
  const [activeTab, setActiveTab] = React.useState('servers');
  const [serverList, setServerList] = React.useState([]);
  const [configSettings, setConfigSettings] = React.useState(config || {});
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [winrmConfig, setWinrmConfig] = React.useState({
    username: '',
    password: '',
    host: '',
    port: '5985',
    enabled: false
  });
  const [winrmTestResult, setWinrmTestResult] = React.useState(null);
  const [winrmTestLoading, setWinrmTestLoading] = React.useState(false);
  const [liveDataLoading, setLiveDataLoading] = React.useState(false);
  const [selectedServer, setSelectedServer] = React.useState(null);
  const [serverMetrics, setServerMetrics] = React.useState(null);
  const [serverServices, setServerServices] = React.useState([]);
  const [serviceActionLoading, setServiceActionLoading] = React.useState(false);
  const [newServer, setNewServer] = React.useState({
    name: '',
    ip: '',
    services: [],
    specs: {
      cpu: '',
      cores: 0,
      ram: '',
      storage: '',
      os: ''
    },
    uptime: '100%',
    lastReboot: new Date().toISOString().split('T')[0] + ' 00:00:00'
  });
  const [newService, setNewService] = React.useState({
    serverIndex: 0,
    name: '',
    status: 'online'
  });
  const [availableServices, setAvailableServices] = React.useState([]);
  const [fetchingServices, setFetchingServices] = React.useState(false);
  const [selectedServerForServices, setSelectedServerForServices] = React.useState(null);
  const [showAddServiceModal, setShowAddServiceModal] = React.useState(false);

  console.log("AdminInterface rendered with showAdminInterface=true");
  console.log("Current pathname:", window.location.pathname);
  
  // Ensure servers have proper structure
  const normalizeServer = (server) => {
    if (!server) return null;
    
    return {
      name: server.name || '',
      ip: server.ip || '',
      services: Array.isArray(server.services) ? server.services : [],
      specs: {
        cpu: server.specs?.cpu || '',
        cores: server.specs?.cores || 0,
        ram: server.specs?.ram || '',
        storage: server.specs?.storage || '',
        os: server.specs?.os || ''
      },
      uptime: server.uptime || '100%',
      lastReboot: server.lastReboot || new Date().toISOString().split('T')[0] + ' 00:00:00'
    };
  };
  
  // Load servers if not provided
  React.useEffect(() => {
    if (!servers || servers.length === 0) {
      fetchServers();
    } else {
      // Normalize all servers to ensure they have the proper structure
      const normalizedServers = Array.isArray(servers) ? 
        servers.map(server => normalizeServer(server)).filter(Boolean) : 
        [];
      setServerList(normalizedServers);
    }
    
    if (!config || Object.keys(config).length === 0) {
      fetchConfig();
    } else {
      setConfigSettings(config);
    }
    
    // Fetch WinRM configuration
    fetchWinRMConfig();
  }, [servers, config]);

  // Fetch servers from API
  const fetchServers = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Check if API is available
      if (window.API && typeof window.API.getServers === 'function') {
        const data = await window.API.getServers();
        
        // Ensure data is an array
        const serversArray = Array.isArray(data) ? data : [];
        
        // Normalize each server object
        const formattedData = serversArray.map(server => normalizeServer(server)).filter(Boolean);
        
        setServerList(formattedData);
        console.log("Fetched servers:", formattedData);
      } else {
        console.error("API.getServers is not available");
        setError("API is not available. Please check if you're logged in.");
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching servers:', error);
      setError('Failed to load server data. Please try again.');
      setIsLoading(false);
    }
  };
  
  // Fetch config from API
  const fetchConfig = async () => {
    try {
      setIsLoading(true);
      
      // Check if API is available
      if (window.API && typeof window.API.getConfig === 'function') {
        const data = await window.API.getConfig();
        setConfigSettings(data || {});
        console.log("Fetched config:", data);
      } else {
        console.error("API.getConfig is not available");
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching config:', error);
      setIsLoading(false);
    }
  };

  // Fetch WinRM configuration
  const fetchWinRMConfig = async () => {
    try {
      setIsLoading(true);
      setError(null);
      
      // Check if API is available
      if (window.API && typeof window.API.getWinRMConfig === 'function') {
        const data = await window.API.getWinRMConfig();
        setWinrmConfig(data || {
          username: '',
          password: '',
          host: '',
          port: '5985',
          enabled: false
        });
        console.log("Fetched WinRM config:", data);
      } else {
        console.error("API.getWinRMConfig is not available");
        setError("WinRM API is not available. Please check if you're logged in.");
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching WinRM config:', error);
      setError('Failed to load WinRM configuration. Please try again.');
      setIsLoading(false);
    }
  };
  
  // Save changes to servers
  const saveServers = async () => {
    try {
      setIsLoading(true);
      
      // Check if API is available
      if (window.API && typeof window.API.saveServers === 'function') {
        await window.API.saveServers(serverList);
        alert('Servers saved successfully');
        if (onUpdateServers) onUpdateServers(serverList);
      } else {
        console.error("API.saveServers is not available");
        alert('API is not available. Please check if you are logged in.');
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error saving servers:', error);
      alert('Error saving servers: ' + error.message);
      setIsLoading(false);
    }
  };

  // Save changes to configuration
  const saveConfig = async () => {
    try {
      setIsLoading(true);
      
      // Check if API is available
      if (window.API && typeof window.API.saveConfig === 'function') {
        await window.API.saveConfig(configSettings);
        alert('Configuration saved successfully');
        if (onUpdateConfig) onUpdateConfig(configSettings);
      } else {
        console.error("API.saveConfig is not available");
        alert('API is not available. Please check if you are logged in.');
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error saving configuration:', error);
      alert('Error saving configuration: ' + error.message);
      setIsLoading(false);
    }
  };

  // Save WinRM configuration
  const saveWinRMConfig = async () => {
    try {
      setIsLoading(true);
      
      // Check if API is available
      if (window.API && typeof window.API.saveWinRMConfig === 'function') {
        await window.API.saveWinRMConfig(winrmConfig);
        alert('WinRM configuration saved successfully');
      } else {
        console.error("API.saveWinRMConfig is not available");
        alert('API is not available. Please check if you are logged in.');
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error saving WinRM configuration:', error);
      alert('Error saving WinRM configuration: ' + error.message);
      setIsLoading(false);
    }
  };
  
  // Test WinRM connection
  const testWinRMConnection = async (server) => {
    try {
      setWinrmTestLoading(true);
      setWinrmTestResult(null);
      
      // Check if API is available
      if (window.API && typeof window.API.testWinRMConnection === 'function') {
        const result = await window.API.testWinRMConnection(server || winrmConfig.host);
        setWinrmTestResult({
          success: true,
          message: result.message,
          data: result.data
        });
      } else {
        console.error("API.testWinRMConnection is not available");
        setWinrmTestResult({
          success: false,
          message: 'API is not available. Please check if you are logged in.'
        });
      }
      
      setWinrmTestLoading(false);
    } catch (error) {
      console.error('Error testing WinRM connection:', error);
      setWinrmTestResult({
        success: false,
        message: error.message || 'Failed to test WinRM connection'
      });
      setWinrmTestLoading(false);
    }
  };
  
  // Fetch live server data using WinRM
  const fetchLiveServerData = async (server) => {
    if (!server || !server.ip) {
      alert('Please select a valid server with an IP address');
      return;
    }
    
    try {
      setLiveDataLoading(true);
      setSelectedServer(server);
      setServerMetrics(null);
      setServerServices([]);
      
      // Check if API is available
      if (window.API && typeof window.API.getServerMetricsWinRM === 'function' && 
          typeof window.API.getServicesWinRM === 'function') {
        
        // Fetch server metrics
        const metrics = await window.API.getServerMetricsWinRM(server.ip);
        setServerMetrics(metrics);
        
        // Fetch server services
        const services = await window.API.getServicesWinRM(server.ip);
        setServerServices(Array.isArray(services) ? services : []);
        
        console.log("Fetched live server data:", { metrics, services });
      } else {
        console.error("WinRM API functions are not available");
        alert('WinRM API is not available. Please check if you are logged in.');
      }
      
      setLiveDataLoading(false);
    } catch (error) {
      console.error('Error fetching live server data:', error);
      alert('Error fetching live server data: ' + error.message);
      setLiveDataLoading(false);
    }
  };
  
  // Control service (start, stop, restart)
  const controlService = async (action, serviceName) => {
    if (!selectedServer || !selectedServer.ip || !serviceName) {
      alert('Please select a valid server and service');
      return;
    }
    
    try {
      setServiceActionLoading(true);
      
      // Check if API is available
      if (window.API) {
        let result;
        
        switch (action) {
          case 'start':
            if (typeof window.API.startServiceWinRM === 'function') {
              result = await window.API.startServiceWinRM(selectedServer.ip, serviceName);
            }
            break;
          case 'stop':
            if (typeof window.API.stopServiceWinRM === 'function') {
              result = await window.API.stopServiceWinRM(selectedServer.ip, serviceName);
            }
            break;
          case 'restart':
            if (typeof window.API.restartServiceWinRM === 'function') {
              result = await window.API.restartServiceWinRM(selectedServer.ip, serviceName);
            }
            break;
          default:
            throw new Error('Invalid action: ' + action);
        }
        
        if (result) {
          alert(`Service ${serviceName} ${action}ed successfully`);
          
          // Refresh services list
          await fetchLiveServerData(selectedServer);
        } else {
          throw new Error(`API.${action}ServiceWinRM is not available`);
        }
      } else {
        console.error("API is not available");
        alert('API is not available. Please check if you are logged in.');
      }
      
      setServiceActionLoading(false);
    } catch (error) {
      console.error(`Error ${action}ing service:`, error);
      alert(`Error ${action}ing service: ` + error.message);
      setServiceActionLoading(false);
    }
  };
  
  // Update server specs with live data
  const updateServerWithLiveData = () => {
    if (!selectedServer || !serverMetrics) {
      alert('No server or metrics data available');
      return;
    }
    
    const updatedServers = [...serverList];
    const serverIndex = updatedServers.findIndex(s => s.ip === selectedServer.ip);
    
    if (serverIndex === -1) {
      alert('Selected server not found in the server list');
      return;
    }
    
    // Update server specs with live data
    if (serverMetrics) {
      // Update CPU info
      if (serverMetrics.cpuUsage !== null && serverMetrics.cpuUsage !== undefined) {
        updatedServers[serverIndex].specs.cpu = `${serverMetrics.cpuUsage}% Usage`;
      }
      
      // Update memory info
      if (serverMetrics.memoryUsage !== null && serverMetrics.memoryUsage !== undefined) {
        updatedServers[serverIndex].specs.ram = `${serverMetrics.memoryUsage}% Usage`;
      }
      
      // Update uptime
      if (serverMetrics.uptime) {
        updatedServers[serverIndex].uptime = serverMetrics.uptime;
      }
    }
    
    // Update services with live data
    if (serverServices && serverServices.length > 0) {
      const updatedServices = serverServices.map(service => ({
        name: service.DisplayName || service.Name,
        status: service.Status === 'Running' ? 'online' : 
                service.Status === 'Stopped' ? 'offline' : 'warning'
      }));
      
      updatedServers[serverIndex].services = updatedServices;
    }
    
    setServerList(updatedServers);
    alert('Server updated with live data');
  };

  // Add a new server
  const addServer = () => {
    if (!newServer.name || !newServer.ip) {
      alert('Server name and IP are required');
      return;
    }
    
    // Ensure the server has the proper structure
    const serverToAdd = normalizeServer({...newServer});
    if (serverToAdd) {
      setServerList([...serverList, serverToAdd]);
    }
    
    setNewServer({
      name: '',
      ip: '',
      services: [],
      specs: {
        cpu: '',
        cores: 0,
        ram: '',
        storage: '',
        os: ''
      },
      uptime: '100%',
      lastReboot: new Date().toISOString().split('T')[0] + ' 00:00:00'
    });
  };

  // Remove a server
  const removeServer = (index) => {
    if (!serverList || index < 0 || index >= serverList.length) {
      return;
    }
    
    if (window.confirm(`Are you sure you want to remove server ${serverList[index].name}?`)) {
      const updatedServers = [...serverList];
      updatedServers.splice(index, 1);
      setServerList(updatedServers);
    }
  };

  // Add a service to a server
  const addService = () => {
    if (!newService.name) {
      alert('Service name is required');
      return;
    }
    
    if (!serverList || serverList.length === 0 || newService.serverIndex < 0 || newService.serverIndex >= serverList.length) {
      alert('No server selected or invalid server index');
      return;
    }
    
    const updatedServers = [...serverList];
    if (!updatedServers[newService.serverIndex].services) {
      updatedServers[newService.serverIndex].services = [];
    }
    
    updatedServers[newService.serverIndex].services.push({
      name: newService.name,
      status: newService.status
    });
    
    setServerList(updatedServers);
    setNewService({
      serverIndex: newService.serverIndex,
      name: '',
      status: 'online'
    });
  };

  // Remove a service from a server
  const removeService = (serverIndex, serviceIndex) => {
    if (!serverList || serverIndex < 0 || serverIndex >= serverList.length || 
        !serverList[serverIndex].services || serviceIndex < 0 || serviceIndex >= serverList[serverIndex].services.length) {
      return;
    }
    
    const updatedServers = [...serverList];
    updatedServers[serverIndex].services.splice(serviceIndex, 1);
    setServerList(updatedServers);
  };

  // Update server specs
  const updateServerSpecs = (serverIndex, field, value) => {
    if (!serverList || serverIndex < 0 || serverIndex >= serverList.length) {
      return;
    }
    
    const updatedServers = [...serverList];
    if (!updatedServers[serverIndex].specs) {
      updatedServers[serverIndex].specs = {
        cpu: '',
        cores: 0,
        ram: '',
        storage: '',
        os: ''
      };
    }
    
    updatedServers[serverIndex].specs[field] = value;
    setServerList(updatedServers);
  };

  // Update configuration setting
  const updateConfigSetting = (key, value) => {
    setConfigSettings({
      ...configSettings,
      [key]: value
    });
  };

  // Safely get server specs with fallback
  const getServerSpec = (server, field, defaultValue = '') => {
    if (!server) return defaultValue;
    if (!server.specs) return defaultValue;
    return server.specs[field] !== undefined ? server.specs[field] : defaultValue;
  };

  // Fetch all services from a server using WinRM
  const fetchAllServicesFromServer = async (server) => {
    if (!server || !server.ip) {
      alert('Server IP is required to fetch services');
      return;
    }
    
    try {
      setFetchingServices(true);
      setSelectedServerForServices(server);
      setError(null);
      
      // Check if API is available
      if (window.API && typeof window.API.getServicesWinRM === 'function') {
        const servicesData = await window.API.getServicesWinRM(server.ip);
        
        if (Array.isArray(servicesData)) {
          // Convert WinRM service format to our app's format
          const formattedServices = servicesData.map(service => ({
            name: service.DisplayName || service.Name,
            status: service.Status === 'Running' ? 'online' : 
                    service.Status === 'Stopped' ? 'offline' : 'warning',
            winrmName: service.Name, // Keep the original service name for WinRM operations
            displayName: service.DisplayName,
            startType: service.StartType
          }));
          
          setAvailableServices(formattedServices);
          setShowAddServiceModal(true);
        }
      } else {
        setError('WinRM API is not available. Please check if you are logged in.');
        alert('WinRM API is not available. Please check if you are logged in.');
      }
      
      setFetchingServices(false);
    } catch (error) {
      console.error('Error fetching services:', error);
      setError('Failed to fetch services: ' + error.message);
      alert('Failed to fetch services: ' + error.message);
      setFetchingServices(false);
    }
  };
  
  // Close the add service modal
  const closeAddServiceModal = () => {
    setShowAddServiceModal(false);
    setAvailableServices([]);
    setSelectedServerForServices(null);
  };
  
  // Add a service to a server from the modal
  const addServiceFromModal = async (service) => {
    if (!selectedServerForServices || !selectedServerForServices.ip || !service) {
      alert('Server IP and service name are required');
      return;
    }
    
    try {
      setServiceActionLoading(true);
      
      // Start the service if it's not already running
      if (service.status !== 'online') {
        if (window.API && typeof window.API.startServiceWinRM === 'function') {
          await window.API.startServiceWinRM(selectedServerForServices.ip, service.winrmName);
        }
      }
      
      // Update the server's services list
      const updatedServers = [...serverList];
      const serverIndex = updatedServers.findIndex(s => s.ip === selectedServerForServices.ip);
      
      if (serverIndex !== -1) {
        if (!updatedServers[serverIndex].services) {
          updatedServers[serverIndex].services = [];
        }
        
        // Check if service already exists
        const serviceExists = updatedServers[serverIndex].services.some(
          s => s.name === service.name || s.winrmName === service.winrmName
        );
        
        if (!serviceExists) {
          updatedServers[serverIndex].services.push({
            name: service.name,
            status: service.status,
            winrmName: service.winrmName
          });
          
          setServerList(updatedServers);
        }
      }
      
      setServiceActionLoading(false);
    } catch (error) {
      console.error('Error adding service:', error);
      alert('Failed to add service: ' + error.message);
      setServiceActionLoading(false);
    }
  };
  
  // Remove a service from a server
  const removeServiceFromServer = (serverIndex, serviceIndex) => {
    if (!serverList || serverIndex < 0 || serverIndex >= serverList.length || 
        !serverList[serverIndex].services || serviceIndex < 0 || serviceIndex >= serverList[serverIndex].services.length) {
      return;
    }
    
    const updatedServers = [...serverList];
    updatedServers[serverIndex].services.splice(serviceIndex, 1);
    setServerList(updatedServers);
  };

  return (
    <div className="fixed inset-0 bg-gray-800 bg-opacity-75 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-11/12 max-w-6xl max-h-[90vh] overflow-hidden">
        <div className="flex justify-between items-center p-4 border-b border-gray-200 dark:border-gray-700">
          <h2 className="text-2xl font-bold text-gray-800 dark:text-white">Admin Dashboard</h2>
          <button 
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M6 18L18 6M6 6l12 12"></path>
            </svg>
          </button>
        </div>
        
        {isLoading && (
          <div className="p-4 text-center">
            <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            <p className="mt-2 text-gray-600 dark:text-gray-400">Loading...</p>
          </div>
        )}
        
        {error && (
          <div className="p-4 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 border-l-4 border-red-500">
            <p>{error}</p>
            <button 
              onClick={fetchServers} 
              className="mt-2 px-3 py-1 bg-red-500 text-white rounded hover:bg-red-600"
            >
              Retry
            </button>
          </div>
        )}
        
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'servers' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('servers')}
          >
            Servers
          </button>
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'settings' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('settings')}
          >
            Settings
          </button>
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'winrm' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('winrm')}
          >
            WinRM
          </button>
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'live-data' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('live-data')}
          >
            Live Data
          </button>
        </div>
        
        <div className="p-4 overflow-y-auto" style={{ maxHeight: 'calc(90vh - 120px)' }}>
          {activeTab === 'servers' && (
            <div>
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-white">Server List</h3>
                <div className="overflow-x-auto">
                  <table className="min-w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                    <thead>
                      <tr className="bg-gray-100 dark:bg-gray-700">
                        <th className="py-2 px-4 border-b text-left">Name</th>
                        <th className="py-2 px-4 border-b text-left">IP</th>
                        <th className="py-2 px-4 border-b text-left">Services</th>
                        <th className="py-2 px-4 border-b text-left">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {serverList && serverList.length > 0 ? (
                        serverList.map((server, index) => (
                          <tr key={index} className="border-b border-gray-200 dark:border-gray-700">
                            <td className="py-2 px-4">{server.name}</td>
                            <td className="py-2 px-4">{server.ip}</td>
                            <td className="py-2 px-4">
                              <div className="flex flex-col">
                                {server.services && server.services.length > 0 ? (
                                  <div>
                                    <p className="mb-2">{server.services.length} services</p>
                                    <div className="flex flex-wrap gap-2">
                                      {server.services.map((service, serviceIndex) => (
                                        <div 
                                          key={serviceIndex} 
                                          className="flex items-center bg-gray-100 dark:bg-gray-700 px-2 py-1 rounded"
                                        >
                                          <span className={`w-2 h-2 rounded-full mr-1 ${
                                            service.status === 'online' ? 'bg-success' : 
                                            service.status === 'offline' ? 'bg-danger' : 
                                            'bg-warning'
                                          }`}></span>
                                          <span className="text-sm">{service.name}</span>
                                          <button 
                                            onClick={() => removeServiceFromServer(index, serviceIndex)}
                                            className="ml-1 text-danger hover:text-danger-dark"
                                            title="Remove service"
                                          >
                                            <svg className="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                                            </svg>
                                          </button>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                ) : (
                                  <p className="text-gray-500 dark:text-gray-400">No services</p>
                                )}
                                <button 
                                  onClick={() => fetchAllServicesFromServer(server)}
                                  className="mt-2 bg-primary text-white px-2 py-1 rounded text-sm hover:bg-primary-dark"
                                  disabled={fetchingServices}
                                >
                                  {fetchingServices && selectedServerForServices?.ip === server.ip ? 
                                    'Fetching...' : 'Add Service'}
                                </button>
                              </div>
                            </td>
                            <td className="py-2 px-4">
                              <button 
                                onClick={() => removeServer(index)}
                                className="bg-red-500 text-white px-3 py-1 rounded hover:bg-red-600"
                              >
                                Remove
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="4" className="py-4 text-center text-gray-500 dark:text-gray-400">
                            No servers found. Add a server using the form below.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
              
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-white">Add New Server</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Server Name</label>
                    <input 
                      type="text" 
                      value={newServer.name} 
                      onChange={(e) => setNewServer({...newServer, name: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. VXSQL1"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">IP Address</label>
                    <input 
                      type="text" 
                      value={newServer.ip} 
                      onChange={(e) => setNewServer({...newServer, ip: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 172.16.1.150"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">CPU Model</label>
                    <input 
                      type="text" 
                      value={newServer.specs?.cpu || ''} 
                      onChange={(e) => setNewServer({
                        ...newServer, 
                        specs: {...(newServer.specs || {}), cpu: e.target.value}
                      })}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. Intel Xeon E5-2680"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">CPU Cores</label>
                    <input 
                      type="number" 
                      value={newServer.specs?.cores || 0} 
                      onChange={(e) => setNewServer({
                        ...newServer, 
                        specs: {...(newServer.specs || {}), cores: parseInt(e.target.value) || 0}
                      })}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 8"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">RAM</label>
                    <input 
                      type="text" 
                      value={newServer.specs?.ram || ''} 
                      onChange={(e) => setNewServer({
                        ...newServer, 
                        specs: {...(newServer.specs || {}), ram: e.target.value}
                      })}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 32GB"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Storage</label>
                    <input 
                      type="text" 
                      value={newServer.specs?.storage || ''} 
                      onChange={(e) => setNewServer({
                        ...newServer, 
                        specs: {...(newServer.specs || {}), storage: e.target.value}
                      })}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 1TB SSD"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Operating System</label>
                    <input 
                      type="text" 
                      value={newServer.specs?.os || ''} 
                      onChange={(e) => setNewServer({
                        ...newServer, 
                        specs: {...(newServer.specs || {}), os: e.target.value}
                      })}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. Windows Server 2019"
                    />
                  </div>
                </div>
                <div className="mt-4">
                  <button 
                    onClick={addServer}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-blue-600"
                  >
                    Add Server
                  </button>
                </div>
              </div>
              
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-white">Add Service to Server</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Server</label>
                    <select 
                      value={newService.serverIndex} 
                      onChange={(e) => setNewService({...newService, serverIndex: parseInt(e.target.value)})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                    >
                      {serverList && serverList.map((server, index) => (
                        <option key={index} value={index}>{server.name}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Service Name</label>
                    <input 
                      type="text" 
                      value={newService.name} 
                      onChange={(e) => setNewService({...newService, name: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. SQL Server"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Status</label>
                    <select 
                      value={newService.status} 
                      onChange={(e) => setNewService({...newService, status: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                    >
                      <option value="online">Online</option>
                      <option value="warning">Warning</option>
                      <option value="offline">Offline</option>
                    </select>
                  </div>
                </div>
                <div className="mt-4">
                  <button 
                    onClick={addService}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-blue-600"
                    disabled={!serverList || serverList.length === 0}
                  >
                    Add Service
                  </button>
                </div>
              </div>
              
              <div className="mt-6">
                <button 
                  onClick={saveServers}
                  className="bg-success text-white px-4 py-2 rounded hover:bg-green-600"
                  disabled={isLoading}
                >
                  {isLoading ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </div>
          )}
          
          {activeTab === 'settings' && (
            <div>
              <div className="mb-6">
                <h3 className="text-lg font-semibold mb-2 text-gray-800 dark:text-white">Application Settings</h3>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">API Base URL</label>
                    <input 
                      type="text" 
                      value={configSettings.API_BASE_URL || ''} 
                      onChange={(e) => updateConfigSetting('API_BASE_URL', e.target.value)}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. http://localhost:5001/api"
                    />
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">The base URL for API requests</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Polling Interval (ms)</label>
                    <input 
                      type="number" 
                      value={configSettings.POLLING_INTERVAL || 10000} 
                      onChange={(e) => updateConfigSetting('POLLING_INTERVAL', parseInt(e.target.value) || 10000)}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 10000"
                    />
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">How often to poll for server updates (in milliseconds)</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Auth Token Key</label>
                    <input 
                      type="text" 
                      value={configSettings.AUTH_TOKEN_KEY || 'voxco_auth_token'} 
                      onChange={(e) => updateConfigSetting('AUTH_TOKEN_KEY', e.target.value)}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. voxco_auth_token"
                    />
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">The key used to store the authentication token in localStorage</p>
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Max Reconnect Attempts</label>
                    <input 
                      type="number" 
                      value={configSettings.MAX_RECONNECT_ATTEMPTS || 5} 
                      onChange={(e) => updateConfigSetting('MAX_RECONNECT_ATTEMPTS', parseInt(e.target.value) || 5)}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-700"
                      placeholder="e.g. 5"
                    />
                    <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">Maximum number of reconnection attempts before logging out</p>
                  </div>
                </div>
                <div className="mt-6">
                  <button 
                    onClick={saveConfig}
                    className="bg-success text-white px-4 py-2 rounded hover:bg-green-600"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Saving...' : 'Save Settings'}
                  </button>
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'winrm' && (
            <div>
              <h3 className="text-lg font-semibold mb-4 text-gray-800 dark:text-white">WinRM Configuration</h3>
              <div className="bg-white dark:bg-gray-700 p-4 rounded-lg shadow mb-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Username</label>
                    <input 
                      type="text" 
                      value={winrmConfig.username} 
                      onChange={(e) => setWinrmConfig({...winrmConfig, username: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                      placeholder="Administrator"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Password</label>
                    <input 
                      type="password" 
                      value={winrmConfig.password} 
                      onChange={(e) => setWinrmConfig({...winrmConfig, password: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                      placeholder="Password"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Default Host</label>
                    <input 
                      type="text" 
                      value={winrmConfig.host} 
                      onChange={(e) => setWinrmConfig({...winrmConfig, host: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                      placeholder="192.168.1.100"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Port</label>
                    <input 
                      type="text" 
                      value={winrmConfig.port} 
                      onChange={(e) => setWinrmConfig({...winrmConfig, port: e.target.value})}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                      placeholder="5985"
                    />
                  </div>
                </div>
                <div className="flex items-center mb-4">
                  <input 
                    type="checkbox" 
                    id="winrm-enabled" 
                    checked={winrmConfig.enabled} 
                    onChange={(e) => setWinrmConfig({...winrmConfig, enabled: e.target.checked})}
                    className="h-4 w-4 text-primary focus:ring-primary border-gray-300 rounded"
                  />
                  <label htmlFor="winrm-enabled" className="ml-2 block text-sm text-gray-700 dark:text-gray-300">
                    Enable WinRM
                  </label>
                </div>
                <div className="flex space-x-2">
                  <button 
                    onClick={saveWinRMConfig}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Saving...' : 'Save Configuration'}
                  </button>
                  <button 
                    onClick={() => testWinRMConnection(winrmConfig.host)}
                    className="bg-secondary text-white px-4 py-2 rounded hover:bg-secondary-dark"
                    disabled={winrmTestLoading}
                  >
                    {winrmTestLoading ? 'Testing...' : 'Test Connection'}
                  </button>
                </div>
                
                {winrmTestResult && (
                  <div className={`mt-4 p-3 rounded ${winrmTestResult.success ? 'bg-success/20 text-success' : 'bg-danger/20 text-danger'}`}>
                    <p className="font-medium">{winrmTestResult.success ? 'Connection Successful!' : 'Connection Failed!'}</p>
                    <p>{winrmTestResult.message}</p>
                    {winrmTestResult.data && (
                      <pre className="mt-2 bg-gray-100 dark:bg-gray-800 p-2 rounded text-xs overflow-auto">
                        {typeof winrmTestResult.data === 'object' ? JSON.stringify(winrmTestResult.data, null, 2) : winrmTestResult.data}
                      </pre>
                    )}
                  </div>
                )}
              </div>
              
              <h3 className="text-lg font-semibold mb-4 text-gray-800 dark:text-white">WinRM Server Testing</h3>
              <div className="bg-white dark:bg-gray-700 p-4 rounded-lg shadow">
                <p className="mb-4 text-gray-600 dark:text-gray-400">
                  Test connection to specific servers in your environment.
                </p>
                <div className="overflow-x-auto">
                  <table className="min-w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                    <thead>
                      <tr className="bg-gray-100 dark:bg-gray-700">
                        <th className="py-2 px-4 border-b text-left">Server Name</th>
                        <th className="py-2 px-4 border-b text-left">IP Address</th>
                        <th className="py-2 px-4 border-b text-left">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {serverList && serverList.length > 0 ? (
                        serverList.map((server, index) => (
                          <tr key={index} className="border-b border-gray-200 dark:border-gray-700">
                            <td className="py-2 px-4">{server.name}</td>
                            <td className="py-2 px-4">{server.ip}</td>
                            <td className="py-2 px-4">
                              <button 
                                onClick={() => testWinRMConnection(server)}
                                className="bg-secondary text-white px-3 py-1 rounded hover:bg-secondary-dark text-sm"
                                disabled={winrmTestLoading}
                              >
                                Test Connection
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan="3" className="py-4 text-center text-gray-500 dark:text-gray-400">
                            No servers found. Add servers in the Servers tab.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
          
          {activeTab === 'live-data' && (
            <div>
              <h3 className="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Live Server Data</h3>
              <div className="bg-white dark:bg-gray-700 p-4 rounded-lg shadow mb-6">
                <p className="mb-4 text-gray-600 dark:text-gray-400">
                  Fetch live data from your servers using WinRM. Select a server to view its current metrics and services.
                </p>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                  <div>
                    <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Select Server</label>
                    <select 
                      value={selectedServer ? serverList.findIndex(s => s.ip === selectedServer.ip) : ""}
                      onChange={(e) => setSelectedServer(serverList[e.target.value])}
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                    >
                      <option value="">-- Select a server --</option>
                      {serverList.map((server, index) => (
                        <option key={index} value={index}>{server.name} ({server.ip})</option>
                      ))}
                    </select>
                  </div>
                  <div className="flex items-end">
                    <button 
                      onClick={() => selectedServer && fetchLiveServerData(selectedServer)}
                      className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark"
                      disabled={!selectedServer || liveDataLoading}
                    >
                      {liveDataLoading ? 'Fetching...' : 'Fetch Live Data'}
                    </button>
                    
                    {serverMetrics && (
                      <button 
                        onClick={updateServerWithLiveData}
                        className="bg-success text-white px-4 py-2 rounded hover:bg-success-dark ml-2"
                      >
                        Update Server with Live Data
                      </button>
                    )}
                  </div>
                </div>
                
                {liveDataLoading && (
                  <div className="text-center py-8">
                    <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                    <p className="mt-2 text-gray-600 dark:text-gray-400">Fetching live data...</p>
                  </div>
                )}
                
                {!liveDataLoading && serverMetrics && (
                  <div className="mt-6">
                    <h4 className="text-md font-semibold mb-2 text-gray-800 dark:text-white">Server Metrics</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                      <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded">
                        <div className="text-sm text-gray-500 dark:text-gray-400">CPU Usage</div>
                        <div className="text-xl font-semibold">{serverMetrics.cpuUsage !== null ? `${serverMetrics.cpuUsage}%` : 'N/A'}</div>
                        <div className="w-full bg-gray-300 dark:bg-gray-600 h-2 rounded-full mt-2">
                          <div 
                            className="bg-primary h-2 rounded-full" 
                            style={{ width: `${serverMetrics.cpuUsage || 0}%` }}
                          ></div>
                        </div>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Memory Usage</div>
                        <div className="text-xl font-semibold">{serverMetrics.memoryUsage !== null ? `${serverMetrics.memoryUsage}%` : 'N/A'}</div>
                        <div className="w-full bg-gray-300 dark:bg-gray-600 h-2 rounded-full mt-2">
                          <div 
                            className="bg-primary h-2 rounded-full" 
                            style={{ width: `${serverMetrics.memoryUsage || 0}%` }}
                          ></div>
                        </div>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Uptime</div>
                        <div className="text-xl font-semibold">{serverMetrics.uptime || 'N/A'}</div>
                      </div>
                      <div className="bg-gray-100 dark:bg-gray-800 p-4 rounded">
                        <div className="text-sm text-gray-500 dark:text-gray-400">Disk Usage</div>
                        {serverMetrics.diskUsage && Array.isArray(serverMetrics.diskUsage) ? (
                          serverMetrics.diskUsage.map((disk, index) => (
                            <div key={index} className="mb-2">
                              <div className="flex justify-between">
                                <span>{disk.DeviceID}</span>
                                <span>{disk.PercentUsed}%</span>
                              </div>
                              <div className="w-full bg-gray-300 dark:bg-gray-600 h-2 rounded-full mt-1">
                                <div 
                                  className="bg-primary h-2 rounded-full" 
                                  style={{ width: `${disk.PercentUsed}%` }}
                                ></div>
                              </div>
                            </div>
                          ))
                        ) : (
                          <div className="text-xl font-semibold">N/A</div>
                        )}
                      </div>
                    </div>
                    
                    <h4 className="text-md font-semibold mb-2 text-gray-800 dark:text-white">Services</h4>
                    <div className="overflow-x-auto">
                      <table className="min-w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                        <thead>
                          <tr className="bg-gray-100 dark:bg-gray-700">
                            <th className="py-2 px-4 border-b text-left">Name</th>
                            <th className="py-2 px-4 border-b text-left">Display Name</th>
                            <th className="py-2 px-4 border-b text-left">Status</th>
                            <th className="py-2 px-4 border-b text-left">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {serverServices && serverServices.length > 0 ? (
                            serverServices.map((service, index) => (
                              <tr key={index} className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 px-4">{service.Name}</td>
                                <td className="py-2 px-4">{service.DisplayName}</td>
                                <td className="py-2 px-4">
                                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                    service.Status === 'Running' ? 'bg-success/20 text-success' : 
                                    service.Status === 'Stopped' ? 'bg-danger/20 text-danger' : 
                                    'bg-warning/20 text-warning'
                                  }`}>
                                    {service.Status}
                                  </span>
                                </td>
                                <td className="py-2 px-4">
                                  <div className="flex space-x-2">
                                    {service.Status !== 'Running' && (
                                      <button 
                                        onClick={() => controlService('start', service.Name)}
                                        className="bg-success text-white px-2 py-1 rounded text-xs"
                                        disabled={serviceActionLoading}
                                      >
                                        Start
                                      </button>
                                    )}
                                    {service.Status === 'Running' && (
                                      <button 
                                        onClick={() => controlService('stop', service.Name)}
                                        className="bg-danger text-white px-2 py-1 rounded text-xs"
                                        disabled={serviceActionLoading}
                                      >
                                        Stop
                                      </button>
                                    )}
                                    <button 
                                      onClick={() => controlService('restart', service.Name)}
                                      className="bg-warning text-white px-2 py-1 rounded text-xs"
                                      disabled={serviceActionLoading}
                                    >
                                      Restart
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))
                          ) : (
                            <tr>
                              <td colSpan="4" className="py-4 text-center text-gray-500 dark:text-gray-400">
                                {liveDataLoading ? 'Loading services...' : 'No services found or not fetched yet.'}
                              </td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
                
                {!liveDataLoading && !serverMetrics && selectedServer && (
                  <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                    Click "Fetch Live Data" to view server metrics and services.
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
      
      {/* Add Service Modal */}
      {showAddServiceModal && selectedServerForServices && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
            {/* Header */}
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h2 className="text-xl font-semibold text-gray-800 dark:text-white">
                Add Service to {selectedServerForServices.name} ({selectedServerForServices.ip})
              </h2>
              <button 
                onClick={closeAddServiceModal}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              {fetchingServices ? (
                <div className="text-center py-8">
                  <div className="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
                  <p className="mt-2 text-gray-600 dark:text-gray-400">Fetching services from server...</p>
                </div>
              ) : (
                <div>
                  <p className="mb-4 text-gray-600 dark:text-gray-400">
                    Select services to add to the server. Services that are already added to the server will not be shown.
                  </p>
                  
                  {/* Search box */}
                  <div className="mb-4">
                    <input 
                      type="text" 
                      placeholder="Search services..." 
                      className="w-full border border-gray-300 dark:border-gray-600 rounded px-3 py-2 dark:bg-gray-800"
                      onChange={(e) => {
                        const searchTerm = e.target.value.toLowerCase();
                        // Filter services based on search term
                        // This is client-side filtering, all services are already loaded
                        const filteredServices = availableServices.filter(service => 
                          (service.DisplayName || '').toLowerCase().includes(searchTerm) || 
                          (service.Name || '').toLowerCase().includes(searchTerm)
                        );
                        // You can set filtered services to state if needed
                      }}
                    />
                  </div>
                  
                  {/* Services list */}
                  <div className="overflow-x-auto">
                    <table className="min-w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                      <thead>
                        <tr className="bg-gray-100 dark:bg-gray-700">
                          <th className="py-2 px-4 border-b text-left">Display Name</th>
                          <th className="py-2 px-4 border-b text-left">Service Name</th>
                          <th className="py-2 px-4 border-b text-left">Status</th>
                          <th className="py-2 px-4 border-b text-left">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {availableServices && availableServices.length > 0 ? (
                          availableServices.map((service, index) => {
                            // Check if service already exists in the server
                            const existingServiceIndex = selectedServerForServices.services?.findIndex(
                              s => s.name === service.DisplayName || s.name === service.Name
                            );
                            
                            // Skip if service already exists
                            if (existingServiceIndex !== -1) {
                              return null;
                            }
                            
                            return (
                              <tr key={index} className="border-b border-gray-200 dark:border-gray-700">
                                <td className="py-2 px-4">{service.DisplayName || 'N/A'}</td>
                                <td className="py-2 px-4">{service.Name}</td>
                                <td className="py-2 px-4">
                                  <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                                    service.Status === 'Running' ? 'bg-success/20 text-success' : 
                                    service.Status === 'Stopped' ? 'bg-danger/20 text-danger' : 
                                    'bg-warning/20 text-warning'
                                  }`}>
                                    {service.Status}
                                  </span>
                                </td>
                                <td className="py-2 px-4">
                                  <button 
                                    onClick={() => addServiceFromModal(service)}
                                    className="bg-primary text-white px-3 py-1 rounded hover:bg-primary-dark text-sm"
                                  >
                                    Add
                                  </button>
                                </td>
                              </tr>
                            );
                          }).filter(Boolean) // Filter out null values (already added services)
                        ) : (
                          <tr>
                            <td colSpan="4" className="py-4 text-center text-gray-500 dark:text-gray-400">
                              No services found on this server.
                            </td>
                          </tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
            
            {/* Footer */}
            <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-700 flex justify-end">
              <button 
                onClick={closeAddServiceModal}
                className="bg-gray-300 dark:bg-gray-600 text-gray-800 dark:text-white px-4 py-2 rounded hover:bg-gray-400 dark:hover:bg-gray-500"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}