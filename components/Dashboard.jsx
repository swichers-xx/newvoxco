window.Dashboard = function Dashboard() {
  const [servers, setServers] = React.useState([]);
  const [activeAlerts, setActiveAlerts] = React.useState(0);
  const [refreshTime, setRefreshTime] = React.useState(new Date());
  const [theme, setTheme] = React.useState('light');
  const [activeTab, setActiveTab] = React.useState('overview');
  const [isAuthenticated, setIsAuthenticated] = React.useState(window.API.isAuthenticated());
  const [isLoading, setIsLoading] = React.useState(true);
  const [error, setError] = React.useState(null);
  const [showAdminInterface, setShowAdminInterface] = React.useState(window.location.pathname === '/admin');
  const [stats, setStats] = React.useState({
    total_servers: 0,
    total_services: 0,
    online_services: 0,
    warning_services: 0,
    offline_services: 0,
    uptime_percentage: 0,
    avg_cpu_usage: 0,
    avg_memory_usage: 0,
    avg_disk_usage: 0
  });
  const [connectionStatus, setConnectionStatus] = React.useState({ connected: false });
  const [config, setConfig] = React.useState(window.FRONTEND_CONFIG || {});
  const [winrmStatus, setWinrmStatus] = React.useState({
    enabled: false,
    connected: false,
    lastChecked: null
  });

  // Check if URL is /admin to show admin interface
  React.useEffect(() => {
    console.log("Current pathname:", window.location.pathname);
    console.log("Is authenticated:", isAuthenticated);
    
    if (window.location.pathname === '/admin') {
      setShowAdminInterface(true);
      console.log("Setting showAdminInterface to true");
    }
  }, [isAuthenticated]);

  // Add event listener for URL changes
  React.useEffect(() => {
    const handleUrlChange = () => {
      console.log("URL changed to:", window.location.pathname);
      if (window.location.pathname === '/admin') {
        setShowAdminInterface(true);
      }
    };

    window.addEventListener('popstate', handleUrlChange);
    
    return () => {
      window.removeEventListener('popstate', handleUrlChange);
    };
  }, []);

  // Load servers on initial render if authenticated
  React.useEffect(() => {
    if (isAuthenticated) {
      fetchServers();
      fetchStats();
    } else {
      // If not authenticated, use demo data for preview
      setServers(window.serversData || []);
      setIsLoading(false);
      
      // Calculate alerts from demo data
      if (window.serversData) {
        let alerts = 0;
        window.serversData.forEach(server => {
          server.services.forEach(service => {
            if (service.status === 'warning' || service.status === 'offline') {
              alerts++;
            }
          });
        });
        setActiveAlerts(alerts);
      }
    }
  }, [isAuthenticated]);

  // Set up event listeners for real-time updates
  React.useEffect(() => {
    if (isAuthenticated) {
      // Listen for authentication changes
      window.API.addEventListener('auth-change', handleAuthChange);
      
      // Listen for server updates
      window.API.addEventListener('server-update', handleServerUpdate);
      
      // Listen for service updates
      window.API.addEventListener('service-update', handleServiceUpdate);
      
      // Listen for server reboots
      window.API.addEventListener('server-reboot', handleServerReboot);
      
      // Listen for connection status changes
      window.API.addEventListener('connection-status', handleConnectionStatus);
      
      // Check WinRM status
      checkWinRMStatus();
      
      // Set up interval to check WinRM status every 5 minutes
      const winrmStatusInterval = setInterval(() => {
        checkWinRMStatus();
      }, 5 * 60 * 1000);
      
      return () => {
        // Clean up event listeners
        window.API.removeEventListener('auth-change', handleAuthChange);
        window.API.removeEventListener('server-update', handleServerUpdate);
        window.API.removeEventListener('service-update', handleServiceUpdate);
        window.API.removeEventListener('server-reboot', handleServerReboot);
        window.API.removeEventListener('connection-status', handleConnectionStatus);
        clearInterval(winrmStatusInterval);
      };
    }
  }, [isAuthenticated, servers]);

  // Event handlers for real-time updates
  const handleAuthChange = (data) => {
    setIsAuthenticated(data.authenticated);
    if (!data.authenticated) {
      // Reset state if logged out
      setServers([]);
      setActiveAlerts(0);
      setStats({
        total_servers: 0,
        total_services: 0,
        online_services: 0,
        warning_services: 0,
        offline_services: 0,
        uptime_percentage: 0,
        avg_cpu_usage: 0,
        avg_memory_usage: 0,
        avg_disk_usage: 0
      });
    }
  };

  const handleServerUpdate = (data) => {
    if (data.servers) {
      // Full server list update
      setServers(data.servers);
      setRefreshTime(new Date());
      
      // Count alerts
      let alerts = 0;
      data.servers.forEach(server => {
        server.services.forEach(service => {
          if (service.status === 'warning' || service.status === 'offline') {
            alerts++;
          }
        });
      });
      setActiveAlerts(alerts);
      
      // Fetch updated stats
      fetchStats();
    }
  };

  const handleServiceUpdate = (data) => {
    // Single service update
    if (data.server && data.service && data.status) {
      setServers(prevServers => {
        const updatedServers = prevServers.map(server => {
          if (server.name === data.server) {
            const updatedServices = server.services.map(service => {
              if (service.name === data.service) {
                return { ...service, status: data.status };
              }
              return service;
            });
            return { ...server, services: updatedServices };
          }
          return server;
        });
        
        // Count alerts
        let alerts = 0;
        updatedServers.forEach(server => {
          server.services.forEach(service => {
            if (service.status === 'warning' || service.status === 'offline') {
              alerts++;
            }
          });
        });
        setActiveAlerts(alerts);
        
        return updatedServers;
      });
      
      setRefreshTime(new Date());
    }
  };

  const handleServerReboot = (data) => {
    // Server reboot notification
    if (data.server) {
      setServers(prevServers => {
        const updatedServers = prevServers.map(server => {
          if (server.name === data.server) {
            // Set all services to offline during reboot
            const updatedServices = server.services.map(service => ({
              ...service,
              status: 'offline'
            }));
            return { ...server, services: updatedServices };
          }
          return server;
        });
        
        // Count alerts
        let alerts = 0;
        updatedServers.forEach(server => {
          server.services.forEach(service => {
            if (service.status === 'warning' || service.status === 'offline') {
              alerts++;
            }
          });
        });
        setActiveAlerts(alerts);
        
        return updatedServers;
      });
      
      setRefreshTime(new Date());
    }
  };

  const handleConnectionStatus = (status) => {
    setConnectionStatus(status);
  };

  const checkWinRMStatus = async () => {
    try {
      // Check if API is available
      if (window.API && typeof window.API.getWinRMStatus === 'function') {
        const status = await window.API.getWinRMStatus();
        setWinrmStatus({
          enabled: status?.enabled || false,
          connected: status?.connected || false,
          lastChecked: new Date().toISOString()
        });
      } else {
        console.error("API.getWinRMStatus is not available");
        setWinrmStatus({
          enabled: false,
          connected: false,
          lastChecked: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Error checking WinRM status:', error);
      setWinrmStatus({
        enabled: false,
        connected: false,
        lastChecked: new Date().toISOString(),
        error: error.message
      });
    }
  };

  // Fetch servers from API
  const fetchServers = async () => {
    try {
      setIsLoading(true);
      
      const data = await window.API.getServers();
      setServers(data);
      
      // Count alerts
      let alerts = 0;
      data.forEach(server => {
        server.services.forEach(service => {
          if (service.status === 'warning' || service.status === 'offline') {
            alerts++;
          }
        });
      });
      setActiveAlerts(alerts);
      
      setIsLoading(false);
      setRefreshTime(new Date());
    } catch (error) {
      console.error('Error fetching servers:', error);
      setError('Failed to load server data. Please try again.');
      setIsLoading(false);
    }
  };

  // Fetch stats from API
  const fetchStats = async () => {
    if (!isAuthenticated) return;
    
    try {
      const data = await window.API.getStats();
      setStats(data);
    } catch (error) {
      console.error('Error fetching stats:', error);
    }
  };

  // Handle server updates from admin interface
  const handleUpdateServers = (updatedServers) => {
    setServers(updatedServers);
    
    // Count alerts
    let alerts = 0;
    updatedServers.forEach(server => {
      server.services.forEach(service => {
        if (service.status === 'warning' || service.status === 'offline') {
          alerts++;
        }
      });
    });
    setActiveAlerts(alerts);
    
    setRefreshTime(new Date());
  };

  // Handle config updates from admin interface
  const handleUpdateConfig = (updatedConfig) => {
    setConfig(updatedConfig);
    window.FRONTEND_CONFIG = updatedConfig;
  };

  // Login is now handled in the LoginScreen component

  // Handle logout
  const handleLogout = () => {
    window.API.logout();
    setIsAuthenticated(false);
  };

  // Toggle theme
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    document.body.classList.toggle('dark');
  };

  // Calculate stats for demo mode
  const totalServers = isAuthenticated ? stats.total_servers : servers.length;
  const totalServices = isAuthenticated ? stats.total_services : servers.reduce((acc, server) => acc + server.services.length, 0);
  const onlineServices = isAuthenticated ? stats.online_services : servers.reduce((acc, server) => {
    return acc + server.services.filter(s => s.status === 'online').length;
  }, 0);
  const warningServices = isAuthenticated ? stats.warning_services : servers.reduce((acc, server) => {
    return acc + server.services.filter(s => s.status === 'warning').length;
  }, 0);
  const offlineServices = isAuthenticated ? stats.offline_services : servers.reduce((acc, server) => {
    return acc + server.services.filter(s => s.status === 'offline').length;
  }, 0);
  const uptime = isAuthenticated ? stats.uptime_percentage : Math.round((onlineServices / totalServices) * 100) || 0;

  // We've moved the login form to a separate component: LoginScreen.jsx

  // Main dashboard UI
  return (
    <div className="min-h-screen bg-gray-100 dark:bg-gray-900 transition-colors duration-300">
      {/* Admin Interface Modal */}
      {(showAdminInterface || window.location.pathname === '/admin') && (
        <AdminInterface 
          onClose={() => {
            setShowAdminInterface(false);
            if (window.location.pathname === '/admin') {
              window.history.pushState({}, '', '/');
            }
          }} 
          servers={servers}
          onUpdateServers={handleUpdateServers}
          config={config}
          onUpdateConfig={handleUpdateConfig}
        />
      )}
      
      {/* Login Screen */}
      {!isAuthenticated && !window.location.pathname.includes('/admin') && (
        <LoginScreen onLogin={(result) => setIsAuthenticated(true)} />
      )}
      
      {/* Header */}
      <header className="bg-white dark:bg-gray-800 shadow-md">
        <div className="container mx-auto px-4 py-4 flex justify-between items-center">
          <div className="flex items-center">
            <svg className="h-8 w-8 text-primary mr-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
              <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
              <line x1="6" y1="6" x2="6" y2="6"></line>
              <line x1="6" y1="18" x2="6" y2="18"></line>
            </svg>
            <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Voxco Server Dashboard</h1>
          </div>
          
          <div className="flex items-center space-x-4">
            {isAuthenticated && (
              <div className="mr-4">
                <ConnectionStatus status={connectionStatus} />
              </div>
            )}
            
            <p className="text-sm text-gray-600 dark:text-gray-300">
              Last Updated: {refreshTime.toLocaleTimeString()}
            </p>
            
            <button 
              onClick={toggleTheme} 
              className="p-2 rounded-full hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
            >
              {theme === 'light' ? (
                <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z"></path>
                </svg>
              ) : (
                <svg className="h-5 w-5" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" fillRule="evenodd" clipRule="evenodd"></path>
                </svg>
              )}
            </button>
            
            {isAuthenticated && (
              <>
                <button
                  onClick={() => setShowAdminInterface(true)}
                  className="bg-primary text-white px-3 py-1 rounded hover:bg-blue-600 text-sm"
                >
                  Admin
                </button>
                <button
                  onClick={handleLogout}
                  className="text-sm font-medium text-gray-700 dark:text-gray-300 hover:text-gray-900 dark:hover:text-white"
                >
                  Logout
                </button>
              </>
            )}
          </div>
        </div>
      </header>
      
      {/* Navigation Tabs */}
      <div className="bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700">
        <div className="container mx-auto px-4">
          <nav className="flex space-x-6">
            <button 
              onClick={() => setActiveTab('overview')}
              className={`py-4 px-2 font-medium text-sm border-b-2 ${
                activeTab === 'overview' 
                  ? 'border-primary text-primary dark:text-primary'
                  : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              Overview
            </button>
            <button 
              onClick={() => setActiveTab('service-management')}
              className={`py-4 px-2 font-medium text-sm border-b-2 ${
                activeTab === 'service-management' 
                  ? 'border-primary text-primary dark:text-primary'
                  : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              Service Management
            </button>
            <button 
              onClick={() => setActiveTab('server-reboot')}
              className={`py-4 px-2 font-medium text-sm border-b-2 ${
                activeTab === 'server-reboot' 
                  ? 'border-primary text-primary dark:text-primary'
                  : 'border-transparent text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white'
              }`}
            >
              Server Reboot Controls
            </button>
          </nav>
        </div>
      </div>
      
      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {isLoading ? (
          <div className="flex justify-center items-center h-64">
            <div className="flex flex-col items-center">
              <svg className="animate-spin h-10 w-10 text-primary mb-4" xmlns="http://www.w3.org/2000/svg" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                <polyline points="12 6 12 12 16 14"></polyline>
              </svg>
              <p className="text-gray-600 dark:text-gray-400">Loading server data...</p>
            </div>
          </div>
        ) : error ? (
          <div className="bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 p-4 rounded-md mb-6">
            <p className="font-medium">{error}</p>
            <button
              onClick={fetchServers}
              className="mt-2 text-sm font-medium text-red-700 dark:text-red-300 underline"
            >
              Try Again
            </button>
          </div>
        ) : (
          <>
            {activeTab === 'overview' && (
              <>
                {/* Stats Overview */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                  <StatsCard 
                    title="Total Servers" 
                    value={totalServers} 
                    icon={
                      <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                        <line x1="6" y1="6" x2="6" y2="6"></line>
                        <line x1="6" y1="18" x2="6" y2="18"></line>
                      </svg>
                    }
                  />
                  <StatsCard 
                    title="Services" 
                    value={totalServices} 
                    icon={
                      <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                        <path d="M2 17l10 5 10-5"></path>
                        <path d="M2 12l10 5 10-5"></path>
                      </svg>
                    }
                  />
                  <StatsCard 
                    title="Uptime" 
                    value={`${uptime}%`} 
                    icon={
                      <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <polyline points="12 6 12 12 16 14"></polyline>
                      </svg>
                    }
                    color={uptime > 90 ? 'success' : uptime > 75 ? 'warning' : 'danger'}
                  />
                  <StatsCard 
                    title="Active Alerts" 
                    value={activeAlerts} 
                    icon={
                      <svg className="h-8 w-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                        <line x1="12" y1="9" x2="12" y2="13"></line>
                        <line x1="12" y1="17" x2="12.01" y2="17"></line>
                      </svg>
                    }
                    color={activeAlerts === 0 ? 'success' : 'danger'}
                  />
                </div>
                
                {/* Status Charts */}
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
                  <StatusChart 
                    title="Service Status Overview" 
                    servers={servers} 
                  />
                  <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
                    <h2 className="text-xl font-bold mb-4">Service Status Distribution</h2>
                    <div className="flex items-center justify-around py-4">
                      <div className="text-center">
                        <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-green-100 dark:bg-green-900 text-success text-xl font-bold mb-2">
                          {onlineServices}
                        </div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Online</p>
                      </div>
                      <div className="text-center">
                        <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-yellow-100 dark:bg-yellow-900 text-warning text-xl font-bold mb-2">
                          {warningServices}
                        </div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Warning</p>
                      </div>
                      <div className="text-center">
                        <div className="inline-flex items-center justify-center h-16 w-16 rounded-full bg-red-100 dark:bg-red-900 text-danger text-xl font-bold mb-2">
                          {offlineServices}
                        </div>
                        <p className="text-sm font-medium text-gray-600 dark:text-gray-400">Offline</p>
                      </div>
                    </div>
                  </div>
                </div>
                
                {/* Servers Grid */}
                <div className="mb-8">
                  <h2 className="text-xl font-bold mb-4">Server Overview</h2>
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
                    {servers.map(server => (
                      <ServerCard 
                        key={server.name} 
                        server={server} 
                      />
                    ))}
                  </div>
                </div>
                
                {/* Detailed Table */}
                <div>
                  <h2 className="text-xl font-bold mb-4">Detailed Server Information</h2>
                  <ServerTable servers={servers} />
                </div>
              </>
            )}
            
            {activeTab === 'service-management' && (
              <ServiceManagementPanel 
                servers={servers} 
                setServers={setServers} 
                isAuthenticated={isAuthenticated}
                api={window.API}
              />
            )}
            
            {activeTab === 'server-reboot' && (
              <ServerRebootGrid 
                servers={servers} 
                isAuthenticated={isAuthenticated}
                api={window.API}
              />
            )}
          </>
        )}
      </main>
      
      {/* Footer */}
      <footer className="bg-white dark:bg-gray-800 shadow-inner py-6">
        <div className="container mx-auto px-4 text-center text-gray-600 dark:text-gray-400 text-sm">
          <p>&copy; {new Date().getFullYear()} Voxco Server Monitoring Dashboard</p>
          <p className="mt-1 text-xs">
            Version 1.0.0 | Last server check: {refreshTime.toLocaleTimeString()}
          </p>
        </div>
      </footer>
    </div>
  );
}