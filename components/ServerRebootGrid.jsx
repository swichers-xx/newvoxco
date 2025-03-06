window.ServerRebootGrid = function ServerRebootGrid({ servers, isAuthenticated, api }) {
  const [rebootStatus, setRebootStatus] = React.useState({});
  const [confirmDialog, setConfirmDialog] = React.useState(null);
  const [rebootError, setRebootError] = React.useState(null);
  const [rebootHistory, setRebootHistory] = React.useState([
    {
      id: 1698123456789,
      timestamp: "10:15:32",
      server: "VXCATI2",
      action: "Reboot",
      status: "Completed",
      date: "2023-10-24"
    },
    {
      id: 1698123123789,
      timestamp: "08:45:12",
      server: "VXDIAL1",
      action: "Force Reboot",
      status: "Completed",
      date: "2023-10-24"
    },
    {
      id: 1698033456789,
      timestamp: "23:12:45",
      server: "VXSERVNO",
      action: "Reboot",
      status: "Completed",
      date: "2023-10-23"
    }
  ]);

  const initiateReboot = (server) => {
    setConfirmDialog({
      server: server,
      type: 'regular'
    });
    setRebootError(null);
  };

  const initiateForceReboot = (server) => {
    setConfirmDialog({
      server: server,
      type: 'force'
    });
    setRebootError(null);
  };

  const confirmReboot = async () => {
    const { server, type } = confirmDialog;
    setConfirmDialog(null);
    setRebootError(null);

    // Update status to rebooting
    setRebootStatus(prev => ({
      ...prev,
      [server.name]: {
        status: 'rebooting',
        startTime: Date.now(),
        type: type
      }
    }));

    // Log to history as initiated
    const historyItem = {
      id: Date.now(),
      timestamp: new Date().toLocaleTimeString(),
      server: server.name,
      action: type === 'force' ? 'Force Reboot' : 'Reboot',
      status: 'Initiated',
      date: new Date().toLocaleDateString()
    };
    setRebootHistory([historyItem, ...rebootHistory.slice(0, 9)]);

    try {
      if (isAuthenticated && api) {
        // Use the API for authenticated reboot
        await api.rebootServer(server.name, type === 'force');
        
        // The actual status updates will come through WebSocket events
        // We don't need to manually update the server status here
      } else {
        // Simulate reboot completion after random time (3-8 seconds) for demo mode
        const rebootTime = 3000 + Math.random() * 5000;
        await new Promise(resolve => setTimeout(resolve, rebootTime));
        
        // Update status to completed
        setRebootStatus(prev => ({
          ...prev,
          [server.name]: {
            ...prev[server.name],
            status: 'completed',
            completeTime: Date.now()
          }
        }));
        
        // Clear status after 5 seconds
        setTimeout(() => {
          setRebootStatus(prev => {
            const newStatus = { ...prev };
            delete newStatus[server.name];
            return newStatus;
          });
        }, 5000);
      }
      
      // Log completion to history
      const completionItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        server: server.name,
        action: type === 'force' ? 'Force Reboot' : 'Reboot',
        status: 'Completed',
        date: new Date().toLocaleDateString()
      };
      setRebootHistory([completionItem, ...rebootHistory.slice(0, 9)]);
    } catch (error) {
      console.error('Reboot error:', error);
      setRebootError(`Failed to reboot server: ${error.message}`);
      
      // Update status to failed
      setRebootStatus(prev => ({
        ...prev,
        [server.name]: {
          ...prev[server.name],
          status: 'failed',
          completeTime: Date.now()
        }
      }));
      
      // Log failure to history
      const failureItem = {
        id: Date.now(),
        timestamp: new Date().toLocaleTimeString(),
        server: server.name,
        action: type === 'force' ? 'Force Reboot' : 'Reboot',
        status: 'Failed',
        date: new Date().toLocaleDateString()
      };
      setRebootHistory([failureItem, ...rebootHistory.slice(0, 9)]);
      
      // Clear status after 5 seconds
      setTimeout(() => {
        setRebootStatus(prev => {
          const newStatus = { ...prev };
          delete newStatus[server.name];
          return newStatus;
        });
      }, 5000);
    }
  };

  const cancelReboot = () => {
    setConfirmDialog(null);
  };

  const getStatusBadge = (serverName) => {
    const status = rebootStatus[serverName];
    if (!status) {
      return <span className="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded-full">Ready</span>;
    }

    if (status.status === 'rebooting') {
      return (
        <div className="flex items-center space-x-1">
          <span className="w-2 h-2 bg-warning rounded-full animate-pulse"></span>
          <span className="text-xs px-2 py-1 bg-warning-light text-warning rounded-full">Rebooting...</span>
        </div>
      );
    }

    if (status.status === 'completed') {
      return (
        <div className="flex items-center space-x-1">
          <span className="w-2 h-2 bg-success rounded-full"></span>
          <span className="text-xs px-2 py-1 bg-success-light text-success rounded-full">Rebooted</span>
        </div>
      );
    }
    
    if (status.status === 'failed') {
      return (
        <div className="flex items-center space-x-1">
          <span className="w-2 h-2 bg-danger rounded-full"></span>
          <span className="text-xs px-2 py-1 bg-danger-light text-danger rounded-full">Failed</span>
        </div>
      );
    }

    return null;
  };

  // Group servers by status for better organization
  const serversWithStatus = React.useMemo(() => {
    const grouped = {
      warning: [],
      healthy: []
    };

    servers.forEach(server => {
      const hasOffline = server.services.some(s => s.status === 'offline');
      const hasWarning = server.services.some(s => s.status === 'warning');

      if (hasOffline || hasWarning) {
        grouped.warning.push(server);
      } else {
        grouped.healthy.push(server);
      }
    });

    return { ...grouped, all: [...grouped.warning, ...grouped.healthy] };
  }, [servers]);

  return (
    <>
      {rebootError && (
        <div className="mb-6 p-4 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-md">
          {rebootError}
        </div>
      )}
      
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
            <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
              <h3 className="text-lg font-medium">Server Reboot Controls</h3>
              <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
                Manage server reboots and monitor real-time status
              </p>
              {!isAuthenticated && (
                <p className="text-xs text-warning mt-1">Demo Mode - Actions are simulated</p>
              )}
            </div>
            <div className="p-4">
              {/* Alert/Problem servers section */}
              {serversWithStatus.warning.length > 0 && (
                <div className="mb-6">
                  <h4 className="text-sm font-medium mb-3 text-danger flex items-center">
                    <svg className="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
                      <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                    </svg>
                    Servers with Warnings or Offline Services
                  </h4>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {serversWithStatus.warning.map(server => (
                      <div key={server.name} className="bg-danger-light dark:bg-red-900/20 rounded-lg p-4 border border-danger/30">
                        <div className="flex justify-between items-start mb-3">
                          <div>
                            <h4 className="font-bold">{server.name}</h4>
                            <p className="text-xs text-gray-500 dark:text-gray-400">{server.ip || 'No IP address'}</p>
                          </div>
                          {getStatusBadge(server.name)}
                        </div>

                        <div className="flex flex-col space-y-2">
                          <button
                            onClick={() => initiateReboot(server)}
                            disabled={rebootStatus[server.name] !== undefined}
                            className="w-full py-1.5 bg-blue-500 text-white rounded text-sm font-medium hover:bg-blue-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                          >
                            Reboot
                          </button>
                          <button
                            onClick={() => initiateForceReboot(server)}
                            disabled={rebootStatus[server.name] !== undefined}
                            className="w-full py-1.5 bg-red-500 text-white rounded text-sm font-medium hover:bg-red-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                          >
                            Force Reboot
                          </button>
                        </div>

                        <div className="mt-3">
                          <h5 className="text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Services:</h5>
                          <div className="flex flex-wrap gap-1">
                            {server.services.map((service, idx) => {
                              let dotClass = '';
                              if (service.status === 'online') dotClass = 'bg-success';
                              else if (service.status === 'warning') dotClass = 'bg-warning';
                              else dotClass = 'bg-danger';

                              return (
                                <div key={idx} className="flex items-center text-xs">
                                  <span className={`h-1.5 w-1.5 rounded-full ${dotClass} mr-1`}></span>
                                  <span className="truncate max-w-[100px]">{service.name}</span>
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Healthy servers section */}
              <div>
                <h4 className="text-sm font-medium mb-3 text-success flex items-center">
                  <svg className="h-4 w-4 mr-1" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                  Healthy Servers
                </h4>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  {serversWithStatus.healthy.map(server => (
                    <div key={server.name} className="bg-gray-50 dark:bg-gray-700 rounded-lg p-4 border border-gray-200 dark:border-gray-600">
                      <div className="flex justify-between items-start mb-3">
                        <div>
                          <h4 className="font-bold">{server.name}</h4>
                          <p className="text-xs text-gray-500 dark:text-gray-400">{server.ip || 'No IP address'}</p>
                        </div>
                        {getStatusBadge(server.name)}
                      </div>

                      <div className="flex flex-col space-y-2">
                        <button
                          onClick={() => initiateReboot(server)}
                          disabled={rebootStatus[server.name] !== undefined}
                          className="w-full py-1.5 bg-blue-500 text-white rounded text-sm font-medium hover:bg-blue-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                        >
                          Reboot
                        </button>
                        <button
                          onClick={() => initiateForceReboot(server)}
                          disabled={rebootStatus[server.name] !== undefined}
                          className="w-full py-1.5 bg-red-500 text-white rounded text-sm font-medium hover:bg-red-600 disabled:bg-gray-300 dark:disabled:bg-gray-600 disabled:cursor-not-allowed transition-colors"
                        >
                          Force Reboot
                        </button>
                      </div>

                      <div className="mt-3">
                        <h5 className="text-xs font-medium text-gray-500 dark:text-gray-400 mb-1">Services:</h5>
                        <div className="flex flex-wrap gap-1">
                          {server.services.map((service, idx) => {
                            let dotClass = '';
                            if (service.status === 'online') dotClass = 'bg-success';
                            else if (service.status === 'warning') dotClass = 'bg-warning';
                            else dotClass = 'bg-danger';

                            return (
                              <div key={idx} className="flex items-center text-xs">
                                <span className={`h-1.5 w-1.5 rounded-full ${dotClass} mr-1`}></span>
                                <span className="truncate max-w-[100px]">{service.name}</span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </div>

        <div>
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
            <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
              <h3 className="text-lg font-medium">Reboot History</h3>
            </div>
            <div className="p-4">
              {rebootHistory.length > 0 ? (
                <ul className="space-y-3">
                  {rebootHistory.map(item => (
                    <li key={item.id} className="flex items-center justify-between text-sm border-b border-gray-100 dark:border-gray-700 pb-2">
                      <div>
                        <span className="font-medium">{item.server}</span>
                        <span className="text-gray-500 dark:text-gray-400 mx-1">-</span>
                        <span>{item.action}</span>
                      </div>
                      <div className="flex items-center">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          item.status === 'Completed'
                            ? 'bg-success-light text-success'
                            : item.status === 'Failed'
                              ? 'bg-danger-light text-danger'
                              : 'bg-warning-light text-warning'
                        }`}>
                          {item.status}
                        </span>
                        <span className="text-xs text-gray-500 dark:text-gray-400 ml-2" title={item.date || ''}>
                          {item.timestamp}
                        </span>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-center text-gray-500 dark:text-gray-400 py-4">No reboot history</p>
              )}
            </div>
          </div>

          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden mt-6">
            <div className="bg-gray-50 dark:bg-gray-700 py-3 px-4 border-b border-gray-200 dark:border-gray-600">
              <h3 className="text-lg font-medium">Information</h3>
            </div>
            <div className="p-4">
              <ul className="space-y-2 text-sm">
                <li className="flex items-start">
                  <svg className="h-5 w-5 text-primary mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                  </svg>
                  <span><strong>Reboot</strong> - Gracefully shuts down all services before restarting the server</span>
                </li>
                <li className="flex items-start">
                  <svg className="h-5 w-5 text-warning mr-2 flex-shrink-0" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                  </svg>
                  <span><strong>Force Reboot</strong> - Immediately restarts the server without graceful shutdown (use only when necessary)</span>
                </li>
              </ul>

              <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
                <h4 className="text-sm font-medium mb-2">Server Maintenance Schedule</h4>
                <ul className="space-y-2 text-sm">
                  <li className="flex justify-between">
                    <span>VXSQL1, VXDIRSRV</span>
                    <span className="text-primary">Every 1st Sunday, 2:00 AM</span>
                  </li>
                  <li className="flex justify-between">
                    <span>VXCATI1, VXCATI2</span>
                    <span className="text-primary">Every 2nd Sunday, 2:00 AM</span>
                  </li>
                  <li className="flex justify-between">
                    <span>Other servers</span>
                    <span className="text-primary">Every 3rd Sunday, 2:00 AM</span>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Confirmation Dialog */}
      {confirmDialog && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg max-w-md w-full p-6">
            <h3 className="text-xl font-bold mb-4">Confirm Reboot</h3>
            <p className="mb-6">
              Are you sure you want to {confirmDialog.type === 'force' ? 'force reboot' : 'reboot'} server <strong>{confirmDialog.server.name}</strong>?
              {confirmDialog.type === 'force' && (
                <span className="block mt-2 text-warning">
                  Warning: Force reboot may cause data loss or service corruption.
                </span>
              )}
            </p>
            <div className="flex justify-end space-x-3">
              <button
                onClick={cancelReboot}
                className="px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-sm font-medium"
              >
                Cancel
              </button>
              <button
                onClick={confirmReboot}
                className={`px-4 py-2 rounded-lg text-sm font-medium text-white ${
                  confirmDialog.type === 'force' ? 'bg-danger hover:bg-red-600' : 'bg-blue-500 hover:bg-blue-600'
                }`}
              >
                Confirm Reboot
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}