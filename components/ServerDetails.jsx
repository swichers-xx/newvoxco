// ServerDetails.jsx - Component for displaying detailed server information
window.ServerDetails = function ServerDetails({ server, onClose }) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [error, setError] = React.useState(null);
  const [liveData, setLiveData] = React.useState(null);
  const [services, setServices] = React.useState(server.services || []);
  const [serviceActionLoading, setServiceActionLoading] = React.useState(false);
  const [activeTab, setActiveTab] = React.useState('overview');
  const [winrmAvailable, setWinrmAvailable] = React.useState(false);
  
  // New state for service management
  const [showAddServiceModal, setShowAddServiceModal] = React.useState(false);
  const [availableServices, setAvailableServices] = React.useState([]);
  const [fetchingAvailableServices, setFetchingAvailableServices] = React.useState(false);
  const [serviceSearchTerm, setServiceSearchTerm] = React.useState('');
  const [selectedServer, setSelectedServer] = React.useState(server);
  
  // Check if WinRM is available
  React.useEffect(() => {
    const checkWinRMAvailability = async () => {
      try {
        if (window.API && typeof window.API.getWinRMStatus === 'function') {
          const status = await window.API.getWinRMStatus();
          setWinrmAvailable(status?.enabled || false);
        } else {
          setWinrmAvailable(false);
        }
      } catch (error) {
        console.error('Error checking WinRM availability:', error);
        setWinrmAvailable(false);
      }
    };
    
    checkWinRMAvailability();
  }, []);
  
  // Fetch live data using WinRM
  const fetchLiveData = async () => {
    if (!server || !server.ip) {
      setError('Server IP is required to fetch live data');
      return;
    }
    
    try {
      setIsLoading(true);
      setError(null);
      
      // Check if API is available
      if (window.API && typeof window.API.getServerMetricsWinRM === 'function') {
        const metrics = await window.API.getServerMetricsWinRM(server.ip);
        setLiveData(metrics);
        
        // Fetch services if available
        if (typeof window.API.getServicesWinRM === 'function') {
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
            
            setServices(formattedServices);
          }
        }
      } else {
        setError('WinRM API is not available. Please check if you are logged in.');
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error fetching live data:', error);
      setError('Failed to fetch live data: ' + error.message);
      setIsLoading(false);
    }
  };
  
  // Fetch all available services from the server
  const fetchAvailableServices = async () => {
    if (!server || !server.ip) {
      setError('Server IP is required to fetch available services');
      return;
    }
    
    try {
      setFetchingAvailableServices(true);
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
        }
      } else {
        setError('WinRM API is not available. Please check if you are logged in.');
      }
      
      setFetchingAvailableServices(false);
    } catch (error) {
      console.error('Error fetching available services:', error);
      setError('Failed to fetch available services: ' + error.message);
      setFetchingAvailableServices(false);
    }
  };
  
  // Open the add service modal
  const openAddServiceModal = async () => {
    await fetchAvailableServices();
    setShowAddServiceModal(true);
  };
  
  // Close the add service modal
  const closeAddServiceModal = () => {
    setShowAddServiceModal(false);
    setServiceSearchTerm('');
  };
  
  // Add a service to the server
  const addService = async (service) => {
    if (!server || !server.ip || !service) {
      setError('Server IP and service name are required');
      return;
    }
    
    try {
      setServiceActionLoading(true);
      setError(null);
      
      // Start the service if it's not already running
      if (service.status !== 'online') {
        await controlService('start', service);
      }
      
      // Update the services list
      setServices(prevServices => {
        // Check if service already exists
        const exists = prevServices.some(s => s.winrmName === service.winrmName);
        if (exists) {
          return prevServices;
        }
        return [...prevServices, service];
      });
      
      setServiceActionLoading(false);
      closeAddServiceModal();
    } catch (error) {
      console.error('Error adding service:', error);
      setError('Failed to add service: ' + error.message);
      setServiceActionLoading(false);
    }
  };
  
  // Remove a service from the server
  const removeService = async (service) => {
    if (!server || !server.ip || !service) {
      setError('Server IP and service name are required');
      return;
    }
    
    if (!confirm(`Are you sure you want to remove ${service.name} from the services list?`)) {
      return;
    }
    
    try {
      setServiceActionLoading(true);
      setError(null);
      
      // Update the services list
      setServices(prevServices => prevServices.filter(s => s.winrmName !== service.winrmName));
      
      setServiceActionLoading(false);
    } catch (error) {
      console.error('Error removing service:', error);
      setError('Failed to remove service: ' + error.message);
      setServiceActionLoading(false);
    }
  };
  
  // Control service (start, stop, restart)
  const controlService = async (action, service) => {
    if (!server || !server.ip || !service) {
      setError('Server IP and service name are required');
      return;
    }
    
    const serviceName = service.winrmName || service.name;
    
    try {
      setServiceActionLoading(true);
      setError(null);
      
      // Check if API is available
      if (window.API) {
        let result;
        
        switch (action) {
          case 'start':
            if (typeof window.API.startServiceWinRM === 'function') {
              result = await window.API.startServiceWinRM(server.ip, serviceName);
            }
            break;
          case 'stop':
            if (typeof window.API.stopServiceWinRM === 'function') {
              result = await window.API.stopServiceWinRM(server.ip, serviceName);
            }
            break;
          case 'restart':
            if (typeof window.API.restartServiceWinRM === 'function') {
              result = await window.API.restartServiceWinRM(server.ip, serviceName);
            }
            break;
          default:
            throw new Error('Invalid action: ' + action);
        }
        
        if (result) {
          alert(`Service ${serviceName} ${action}ed successfully`);
          
          // Refresh services list
          await fetchLiveData();
        } else {
          throw new Error(`API.${action}ServiceWinRM is not available`);
        }
      } else {
        setError('API is not available. Please check if you are logged in.');
      }
      
      setServiceActionLoading(false);
    } catch (error) {
      console.error(`Error ${action}ing service:`, error);
      setError(`Error ${action}ing service: ` + error.message);
      setServiceActionLoading(false);
    }
  };
  
  // Reboot server
  const rebootServer = async () => {
    if (!server || !server.ip) {
      setError('Server IP is required to reboot server');
      return;
    }
    
    if (!confirm(`Are you sure you want to reboot ${server.name} (${server.ip})?`)) {
      return;
    }
    
    try {
      setIsLoading(true);
      setError(null);
      
      // Check if API is available
      if (window.API && typeof window.API.rebootServer === 'function') {
        await window.API.rebootServer(server.ip);
        alert(`Server ${server.name} is rebooting`);
      } else {
        setError('API is not available. Please check if you are logged in.');
      }
      
      setIsLoading(false);
    } catch (error) {
      console.error('Error rebooting server:', error);
      setError('Failed to reboot server: ' + error.message);
      setIsLoading(false);
    }
  };
  
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-4xl max-h-[90vh] overflow-hidden flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
          <h2 className="text-xl font-semibold text-gray-800 dark:text-white">
            {server.name} ({server.ip})
          </h2>
          <button 
            onClick={onClose}
            className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
          >
            <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>
        
        {/* Tabs */}
        <div className="flex border-b border-gray-200 dark:border-gray-700">
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'overview' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('overview')}
          >
            Overview
          </button>
          <button 
            className={`px-4 py-2 font-medium ${activeTab === 'services' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
            onClick={() => setActiveTab('services')}
          >
            Services
          </button>
          {winrmAvailable && (
            <button 
              className={`px-4 py-2 font-medium ${activeTab === 'live-data' ? 'text-primary border-b-2 border-primary' : 'text-gray-500 dark:text-gray-400'}`}
              onClick={() => setActiveTab('live-data')}
            >
              Live Data
            </button>
          )}
        </div>
        
        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6">
          {activeTab === 'overview' && (
            <div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                  <h3 className="text-lg font-medium text-gray-800 dark:text-white mb-2">Server Information</h3>
                  <div className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">Name</p>
                        <p className="font-medium">{server.name}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">IP Address</p>
                        <p className="font-medium">{server.ip}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">Uptime</p>
                        <p className="font-medium">{server.uptime || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">Last Reboot</p>
                        <p className="font-medium">{server.lastReboot || 'Unknown'}</p>
                      </div>
                    </div>
                  </div>
                </div>
                
                <div>
                  <h3 className="text-lg font-medium text-gray-800 dark:text-white mb-2">Specifications</h3>
                  <div className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">CPU</p>
                        <p className="font-medium">{server.specs?.cpu || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">Cores</p>
                        <p className="font-medium">{server.specs?.cores || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">RAM</p>
                        <p className="font-medium">{server.specs?.ram || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">Storage</p>
                        <p className="font-medium">{server.specs?.storage || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-500 dark:text-gray-400">OS</p>
                        <p className="font-medium">{server.specs?.os || 'Unknown'}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="flex justify-end mt-4">
                {winrmAvailable && (
                  <button 
                    onClick={fetchLiveData}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark mr-2"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Fetching...' : 'Fetch Live Data'}
                  </button>
                )}
                
                <button 
                  onClick={rebootServer}
                  className="bg-danger text-white px-4 py-2 rounded hover:bg-danger-dark"
                  disabled={isLoading}
                >
                  Reboot Server
                </button>
              </div>
            </div>
          )}
          
          {activeTab === 'services' && (
            <div>
              <h3 className="text-lg font-medium text-gray-800 dark:text-white mb-4">Services</h3>
              
              {error && (
                <div className="bg-danger/20 text-danger p-3 rounded mb-4">
                  {error}
                </div>
              )}
              
              <div className="overflow-x-auto">
                <table className="min-w-full bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700">
                  <thead>
                    <tr className="bg-gray-100 dark:bg-gray-700">
                      <th className="py-2 px-4 border-b text-left">Name</th>
                      <th className="py-2 px-4 border-b text-left">Status</th>
                      <th className="py-2 px-4 border-b text-left">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {services && services.length > 0 ? (
                      services.map((service, index) => (
                        <tr key={index} className="border-b border-gray-200 dark:border-gray-700">
                          <td className="py-2 px-4">{service.name}</td>
                          <td className="py-2 px-4">
                            <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                              service.status === 'online' ? 'bg-success/20 text-success' : 
                              service.status === 'offline' ? 'bg-danger/20 text-danger' : 
                              'bg-warning/20 text-warning'
                            }`}>
                              {service.status === 'online' ? 'Online' : 
                               service.status === 'offline' ? 'Offline' : 
                               'Warning'}
                            </span>
                          </td>
                          <td className="py-2 px-4">
                            {winrmAvailable && (
                              <div className="flex space-x-2">
                                {service.status !== 'online' && (
                                  <button 
                                    onClick={() => controlService('start', service)}
                                    className="bg-success text-white px-2 py-1 rounded text-xs"
                                    disabled={serviceActionLoading}
                                  >
                                    Start
                                  </button>
                                )}
                                {service.status === 'online' && (
                                  <button 
                                    onClick={() => controlService('stop', service)}
                                    className="bg-danger text-white px-2 py-1 rounded text-xs"
                                    disabled={serviceActionLoading}
                                  >
                                    Stop
                                  </button>
                                )}
                                <button 
                                  onClick={() => controlService('restart', service)}
                                  className="bg-warning text-white px-2 py-1 rounded text-xs"
                                  disabled={serviceActionLoading}
                                >
                                  Restart
                                </button>
                                <button 
                                  onClick={() => removeService(service)}
                                  className="bg-danger text-white px-2 py-1 rounded text-xs"
                                  disabled={serviceActionLoading}
                                >
                                  Remove
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="3" className="py-4 text-center text-gray-500 dark:text-gray-400">
                          No services found for this server.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              
              {winrmAvailable && (
                <div className="flex justify-end mt-4">
                  <button 
                    onClick={fetchLiveData}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark"
                    disabled={isLoading}
                  >
                    {isLoading ? 'Fetching...' : 'Refresh Services'}
                  </button>
                  <button 
                    onClick={openAddServiceModal}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark ml-2"
                  >
                    Add Service
                  </button>
                </div>
              )}
            </div>
          )}
          
          {activeTab === 'live-data' && winrmAvailable && (
            <div>
              <h3 className="text-lg font-medium text-gray-800 dark:text-white mb-4">Live Server Data</h3>
              
              {error && (
                <div className="bg-danger/20 text-danger p-3 rounded mb-4">
                  {error}
                </div>
              )}
              
              {isLoading ? (
                <div className="text-center py-8">
                  <div className="inline-block animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
                  <p className="mt-2 text-gray-600 dark:text-gray-400">Fetching live data...</p>
                </div>
              ) : liveData ? (
                <div>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
                    <div className="bg-gray-100 dark:bg-gray-700 p-4 rounded">
                      <div className="text-sm text-gray-500 dark:text-gray-400">CPU Usage</div>
                      <div className="text-xl font-semibold">{liveData.cpuUsage !== null ? `${liveData.cpuUsage}%` : 'N/A'}</div>
                      <div className="w-full bg-gray-300 dark:bg-gray-600 h-2 rounded-full mt-2">
                        <div 
                          className="bg-primary h-2 rounded-full" 
                          style={{ width: `${liveData.cpuUsage || 0}%` }}
                        ></div>
                      </div>
                    </div>
                    <div className="bg-gray-100 dark:bg-gray-700 p-4 rounded">
                      <div className="text-sm text-gray-500 dark:text-gray-400">Memory Usage</div>
                      <div className="text-xl font-semibold">{liveData.memoryUsage !== null ? `${liveData.memoryUsage}%` : 'N/A'}</div>
                      <div className="w-full bg-gray-300 dark:bg-gray-600 h-2 rounded-full mt-2">
                        <div 
                          className="bg-primary h-2 rounded-full" 
                          style={{ width: `${liveData.memoryUsage || 0}%` }}
                        ></div>
                      </div>
                    </div>
                    <div className="bg-gray-100 dark:bg-gray-700 p-4 rounded">
                      <div className="text-sm text-gray-500 dark:text-gray-400">Uptime</div>
                      <div className="text-xl font-semibold">{liveData.uptime || 'N/A'}</div>
                    </div>
                    <div className="bg-gray-100 dark:bg-gray-700 p-4 rounded">
                      <div className="text-sm text-gray-500 dark:text-gray-400">Disk Usage</div>
                      {liveData.diskUsage && Array.isArray(liveData.diskUsage) ? (
                        liveData.diskUsage.map((disk, index) => (
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
                  
                  {liveData.serverInfo && (
                    <div className="mt-6">
                      <h4 className="text-md font-semibold mb-2 text-gray-800 dark:text-white">Server Information</h4>
                      <div className="bg-gray-100 dark:bg-gray-700 rounded-lg p-4">
                        <div className="grid grid-cols-2 gap-4">
                          {Object.entries(liveData.serverInfo).map(([key, value]) => (
                            <div key={key}>
                              <p className="text-sm text-gray-500 dark:text-gray-400">{key}</p>
                              <p className="font-medium">{value}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                  
                  <div className="flex justify-end mt-4">
                    <button 
                      onClick={fetchLiveData}
                      className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark"
                      disabled={isLoading}
                    >
                      Refresh Data
                    </button>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  <p>No live data available. Click the button below to fetch live data from the server.</p>
                  <button 
                    onClick={fetchLiveData}
                    className="bg-primary text-white px-4 py-2 rounded hover:bg-primary-dark mt-4"
                    disabled={isLoading}
                  >
                    Fetch Live Data
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
      
      {/* Add Service Modal */}
      {showAddServiceModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl w-full max-w-2xl max-h-[90vh] overflow-hidden flex flex-col">
            {/* Modal Header */}
            <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700 flex justify-between items-center">
              <h3 className="text-lg font-semibold text-gray-800 dark:text-white">
                Add Service to {server.name}
              </h3>
              <button 
                onClick={closeAddServiceModal}
                className="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200"
              >
                <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            {/* Modal Body */}
            <div className="p-6 flex-1 overflow-auto">
              {error && (
                <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded mb-4">
                  {error}
                </div>
              )}
              
              {/* Search Box */}
              <div className="mb-4">
                <input
                  type="text"
                  placeholder="Search services..."
                  className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-primary"
                  value={serviceSearchTerm}
                  onChange={(e) => setServiceSearchTerm(e.target.value)}
                />
              </div>
              
              {/* Services List */}
              <div className="overflow-y-auto max-h-[50vh]">
                {fetchingAvailableServices ? (
                  <div className="flex justify-center items-center p-4">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary"></div>
                  </div>
                ) : (
                  <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
                    <thead className="bg-gray-50 dark:bg-gray-700">
                      <tr>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                          Name
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                          Status
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                          Start Type
                        </th>
                        <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                          Actions
                        </th>
                      </tr>
                    </thead>
                    <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                      {availableServices
                        .filter(service => {
                          // Filter by search term
                          if (!serviceSearchTerm) return true;
                          return (
                            service.name.toLowerCase().includes(serviceSearchTerm.toLowerCase()) ||
                            service.winrmName.toLowerCase().includes(serviceSearchTerm.toLowerCase())
                          );
                        })
                        .map((service, index) => (
                          <tr key={index} className={index % 2 === 0 ? 'bg-white dark:bg-gray-800' : 'bg-gray-50 dark:bg-gray-700'}>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-200">
                              {service.name}
                              <div className="text-xs text-gray-500 dark:text-gray-400">
                                {service.winrmName}
                              </div>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">
                              <span className={`px-2 py-1 rounded-full text-xs ${
                                service.status === 'online' ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200' :
                                service.status === 'offline' ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200' :
                                'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                              }`}>
                                {service.status === 'online' ? 'Running' :
                                 service.status === 'offline' ? 'Stopped' : 'Unknown'}
                              </span>
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-200">
                              {service.startType || 'Unknown'}
                            </td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-gray-200">
                              <button 
                                onClick={() => addService(service)}
                                className="bg-primary text-white px-3 py-1 rounded hover:bg-primary-dark"
                                disabled={serviceActionLoading}
                              >
                                Add
                              </button>
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                )}
                
                {availableServices.length === 0 && !fetchingAvailableServices && (
                  <div className="text-center p-4 text-gray-500 dark:text-gray-400">
                    No services found
                  </div>
                )}
              </div>
            </div>
            
            {/* Modal Footer */}
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
};
