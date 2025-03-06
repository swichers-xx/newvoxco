window.ServiceManagementPanel = function ServiceManagementPanel({ servers, setServers, isAuthenticated, api }) {
  const [selectedServer, setSelectedServer] = React.useState(null);
  const [selectedService, setSelectedService] = React.useState(null);
  const [actionInProgress, setActionInProgress] = React.useState(false);
  const [actionError, setActionError] = React.useState(null);
  const [actionHistory, setActionHistory] = React.useState([
    {
      id: 1698153456789,
      timestamp: "15:32:45",
      server: "VXDIAL1",
      service: "Voxco Telephone Gateway",
      action: "restart",
      result: "Success",
      date: "2023-10-24"
    },
    {
      id: 1698143456789,
      timestamp: "12:48:16",
      server: "VXSERVNO",
      service: "Windows Search",
      action: "restart",
      result: "Success",
      date: "2023-10-24"
    },
    {
      id: 1698023456789,
      timestamp: "09:15:52",
      server: "VXCATI2",
      service: "Voxco CATI Engine",
      action: "restart",
      result: "Success",
      date: "2023-10-23"
    }
  ]);

  const handleServerSelect = (serverName) => {
    const server = servers.find(s => s.name === serverName);
    setSelectedServer(server);
    setSelectedService(null);
    setActionError(null);
  };

  const handleServiceSelect = (service) => {
    setSelectedService(service);
    setActionError(null);
  };

  const performServiceAction = async (action) => {
    if (!selectedServer || !selectedService || actionInProgress) return;
    
    // Clear any previous errors
    setActionError(null);
    setActionInProgress(true);
    
    try {
      let result;
      
      if (isAuthenticated && api) {
        // Use the API for authenticated actions
        switch(action) {
          case 'start':
            result = await api.startService(selectedServer.name, selectedService.name);
            break;
          case 'stop':
            result = await api.stopService(selectedServer.name, selectedService.name);
            break;
          case 'restart':
            result = await api.restartService(selectedServer.name, selectedService.name);
            break;
          default:
            throw new Error('Invalid action');
        }
      } else {
        // Simulate API call with a delay for demo mode
        await new Promise(resolve => setTimeout(resolve, 1500));
        
        // Update service status based on action
        const updatedServers = servers.map(server => {
          if (server.name === selectedServer.name) {
            const services = server.services.map(service => {
              if (service.name === selectedService.name) {
                // Update service status based on action
                let newStatus;
                switch(action) {
                  case 'start':
                    newStatus = 'online';
                    break;
                  case 'stop':
                    newStatus = 'offline';
                    break;
                  case 'restart':
                    newStatus = 'warning'; // Temporarily set to warning during restart
                    break;
                  default:
                    newStatus = service.status;
                }
                
                return { ...service, status: newStatus };
              }
              return service;
            });
            
            return { ...server, services };
          }
          return server;
        });
        
        setServers(updatedServers);
        
        // If action was restart, set it back to online after a delay
        if (action === 'restart') {
          setTimeout(() => {
            const restartedServers = updatedServers.map(server => {
              if (server.name === selectedServer.name) {
                const services = server.services.map(service => {
                  if (service.name === selectedService.name) {
                    return { ...service, status: 'online' };
                  }
                  return service;
                });
                return { ...server, services };
              }
              return server;
            });
            setServers(restartedServers);
          }, 3000);
        }
        
        result = { message: `Service ${selectedService.name} ${action}ed successfully` };
      }
      
      // Add to action history
      const historyItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        server: selectedServer.name,
        service: selectedService.name,
        action: action,
        result: 'Success',
        date: new Date().toLocaleDateString()
      };
      
      setActionHistory([historyItem, ...actionHistory.slice(0, 9)]); // Keep last 10 items
    } catch (error) {
      console.error(`Error performing ${action} action:`, error);
      setActionError(`Failed to ${action} service: ${error.message}`);
      
      // Add to action history as failed
      const historyItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        server: selectedServer.name,
        service: selectedService.name,
        action: action,
        result: 'Failed',
        date: new Date().toLocaleDateString()
      };
      
      setActionHistory([historyItem, ...actionHistory.slice(0, 9)]); // Keep last 10 items
    } finally {
      setActionInProgress(false);
    }
  };

  const getServiceTypeIcon = (serviceName) => {
    if (serviceName.includes('SQL')) {
      return (
        <svg className="h-4 w-4 text-blue-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20 16V7a2 2 0 00-2-2H6a2 2 0 00-2 2v9m16 0H4m16 0l-2-5H6l-2 5M9 4h6"></path>
        </svg>
      );
    } else if (serviceName.includes('Email') || serviceName.includes('DLR')) {
      return (
        <svg className="h-4 w-4 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"></path>
          <polyline points="22,6 12,13 2,6"></polyline>
        </svg>
      );
    } else if (serviceName.includes('Telephone') || serviceName.includes('Call')) {
      return (
        <svg className="h-4 w-4 text-green-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M22 16.92v3a2 2 0 01-2.18 2 19.79 19.79 0 01-8.63-3.07 19.5 19.5 0 01-6-6 19.79 19.79 0 01-3.07-8.67A2 2 0 014.11 2h3a2 2 0 012 1.72 12.84 12.84 0 00.7 2.81 2 2 0 01-.45 2.11L8.09 9.91a16 16 0 006 6l1.27-1.27a2 2 0 012.11-.45 12.84 12.84 0 002.81.7A2 2 0 0122 16.92z"></path>
        </svg>
      );
    } else if (serviceName.includes('Web') || serviceName.includes('IIS')) {
      return (
        <svg className="h-4 w-4 text-yellow-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
          <line x1="8" y1="21" x2="16" y2="21"></line>
          <line x1="12" y1="17" x2="12" y2="21"></line>
        </svg>
      );
    }

    return (
      <svg className="h-4 w-4 text-gray-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
    );
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* Server List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
          <h3 className="text-lg font-medium">Servers</h3>
          <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
            Select a server to manage its services
          </p>
        </div>
        <div className="p-1">
          <ul className="divide-y divide-gray-200 dark:divide-gray-700">
            {servers.map(server => {
              const offlineCount = server.services.filter(s => s.status === 'offline').length;
              const warningCount = server.services.filter(s => s.status === 'warning').length;
              let statusIndicator;

              if (offlineCount > 0) {
                statusIndicator = <ServiceStatus status="offline" />;
              } else if (warningCount > 0) {
                statusIndicator = <ServiceStatus status="warning" />;
              } else {
                statusIndicator = <ServiceStatus status="online" />;
              }

              return (
                <li 
                  key={server.name}
                  onClick={() => handleServerSelect(server.name)}
                  className={`px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors ${
                    selectedServer?.name === server.name ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div>
                      <h4 className="font-medium">{server.name}</h4>
                      <div className="flex items-center text-sm text-gray-600 dark:text-gray-400">
                        <span>{server.ip || 'No IP address'}</span>
                        {server.specs && (
                          <span className="ml-2 text-xs bg-gray-100 dark:bg-gray-700 px-1.5 py-0.5 rounded">
                            {server.specs.os}
                          </span>
                        )}
                      </div>
                    </div>
                    {statusIndicator}
                  </div>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* Services List */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
          <h3 className="text-lg font-medium">Services {selectedServer ? `on ${selectedServer.name}` : ''}</h3>
        </div>
        {selectedServer ? (
          <div className="p-1">
            <ul className="divide-y divide-gray-200 dark:divide-gray-700">
              {selectedServer.services.map((service, index) => (
                <li 
                  key={index}
                  onClick={() => handleServiceSelect(service)}
                  className={`px-4 py-3 hover:bg-gray-50 dark:hover:bg-gray-700 cursor-pointer transition-colors ${
                    selectedService?.name === service.name ? 'bg-blue-50 dark:bg-blue-900/20' : ''
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center">
                      {getServiceTypeIcon(service.name)}
                      <h4 className="font-medium ml-2">{service.name}</h4>
                    </div>
                    <ServiceStatus status={service.status} />
                  </div>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="p-6 text-center text-gray-500 dark:text-gray-400">
            <svg className="h-12 w-12 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 6v6m0 0v6m0-6h6m-6 0H6"></path>
            </svg>
            <p>Select a server to view services</p>
          </div>
        )}
      </div>

      {/* Action Panel */}
      <div>
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden mb-6">
          <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
            <h3 className="text-lg font-medium">Service Actions</h3>
            {!isAuthenticated && (
              <p className="text-xs text-warning mt-1">Demo Mode - Actions are simulated</p>
            )}
          </div>
          {selectedService ? (
            <div className="p-6">
              <div className="mb-4">
                <h4 className="font-medium mb-1">Selected Service:</h4>
                <div className="flex items-center justify-between p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                  <div className="flex items-center">
                    {getServiceTypeIcon(selectedService.name)}
                    <span className="ml-2">{selectedService.name}</span>
                  </div>
                  <ServiceStatus status={selectedService.status} />
                </div>
              </div>

              {actionError && (
                <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-md text-sm">
                  {actionError}
                </div>
              )}

              <div className="grid grid-cols-3 gap-3">
                <button
                  onClick={() => performServiceAction('start')}
                  disabled={actionInProgress || selectedService.status === 'online'}
                  className={`py-2 px-4 rounded-lg font-medium text-white bg-success hover:bg-green-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors`}
                >
                  Start
                </button>
                <button
                  onClick={() => performServiceAction('restart')}
                  disabled={actionInProgress || selectedService.status === 'offline'}
                  className={`py-2 px-4 rounded-lg font-medium text-white bg-warning hover:bg-amber-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors`}
                >
                  Restart
                </button>
                <button
                  onClick={() => performServiceAction('stop')}
                  disabled={actionInProgress || selectedService.status === 'offline'}
                  className={`py-2 px-4 rounded-lg font-medium text-white bg-danger hover:bg-red-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors`}
                >
                  Stop
                </button>
              </div>

              {actionInProgress && (
                <div className="mt-4 flex justify-center">
                  <div className="flex items-center space-x-3">
                    <svg className="animate-spin h-5 w-5 text-primary" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>Processing action...</span>
                  </div>
                </div>
              )}

              <div className="mt-6 pt-4 border-t border-gray-200 dark:border-gray-600">
                <h4 className="text-sm font-medium mb-2">Service Details</h4>
                <table className="w-full text-sm">
                  <tbody>
                    <tr>
                      <td className="py-1 text-gray-600 dark:text-gray-400">Status</td>
                      <td className="py-1 font-medium">
                        {selectedService.status === 'online' ? 'Running' : 
                         selectedService.status === 'warning' ? 'Warning' : 'Stopped'}
                      </td>
                    </tr>
                    <tr>
                      <td className="py-1 text-gray-600 dark:text-gray-400">Type</td>
                      <td className="py-1 font-medium">Windows Service</td>
                    </tr>
                    <tr>
                      <td className="py-1 text-gray-600 dark:text-gray-400">Host Server</td>
                      <td className="py-1 font-medium">{selectedServer.name}</td>
                    </tr>
                    <tr>
                      <td className="py-1 text-gray-600 dark:text-gray-400">Auto Restart</td>
                      <td className="py-1 font-medium">Enabled</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-gray-500 dark:text-gray-400">
              <svg className="h-12 w-12 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
              </svg>
              <p>Select a service to perform actions</p>
            </div>
          )}
        </div>

        {/* Action History */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
          <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
            <h3 className="text-lg font-medium">Recent Activity</h3>
          </div>
          <div className="overflow-y-auto" style={{ maxHeight: '250px' }}>
            {actionHistory.length > 0 ? (
              <ul className="divide-y divide-gray-200 dark:divide-gray-700">
                {actionHistory.map(item => (
                  <li key={item.id} className="px-4 py-3">
                    <div className="flex items-center">
                      <span className="w-16 text-xs text-gray-500">{item.timestamp}</span>
                      <span className="ml-2 text-sm flex-1">
                        <span className="font-medium capitalize">{item.action}</span> {item.service} on {item.server}
                      </span>
                      <span className={`text-xs ${
                        item.result === 'Success' ? 'text-success' : 'text-danger'
                      }`}>
                        {item.result}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="p-4 text-center text-gray-500 dark:text-gray-400">
                <p>No recent actions</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}