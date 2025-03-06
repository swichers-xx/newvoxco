window.ServerCard = function ServerCard({ server }) {
  const [expanded, setExpanded] = React.useState(false);
  
  // Calculate status metrics
  const totalServices = server.services.length;
  const onlineServices = server.services.filter(s => s.status === 'online').length;
  const warningServices = server.services.filter(s => s.status === 'warning').length;
  const offlineServices = server.services.filter(s => s.status === 'offline').length;
  
  let cardStatus = 'success';
  let statusClass = 'border-success';
  let statusBgClass = 'bg-success-light';
  let statusTextClass = 'text-success';
  
  if (offlineServices > 0) {
    cardStatus = 'danger';
    statusClass = 'border-danger';
    statusBgClass = 'bg-danger-light';
    statusTextClass = 'text-danger';
  } else if (warningServices > 0) {
    cardStatus = 'warning';
    statusClass = 'border-warning';
    statusBgClass = 'bg-warning-light';
    statusTextClass = 'text-warning';
  }

  return (
    <div className={`bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden border-l-4 ${statusClass} transition-all duration-300`}>
      <div className="p-4">
        <div className="flex justify-between items-center mb-2">
          <h3 className="font-bold text-lg">{server.name}</h3>
          <span className={`px-2 py-1 rounded-full text-xs font-medium ${statusBgClass} ${statusTextClass}`}>
            {offlineServices > 0 ? 'Critical' : warningServices > 0 ? 'Warning' : 'Healthy'}
          </span>
        </div>
        
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
          {server.ip || 'No IP address'}
        </p>
        
        <p className="text-xs text-gray-500 dark:text-gray-400 mb-3">
          Last Reboot: {server.lastReboot || 'Unknown'}
        </p>
        
        <div className="grid grid-cols-3 gap-2 mb-4">
          <div className="text-center">
            <div className="text-lg font-semibold text-success">{onlineServices}</div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Online</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-warning">{warningServices}</div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Warning</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-danger">{offlineServices}</div>
            <div className="text-xs text-gray-500 dark:text-gray-400">Offline</div>
          </div>
        </div>
        
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full py-2 px-3 bg-gray-100 dark:bg-gray-700 rounded text-sm font-medium flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
        >
          {expanded ? 'Hide' : 'Show'} Services
          <svg
            className={`ml-2 h-4 w-4 transform transition-transform ${expanded ? 'rotate-180' : ''}`}
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <polyline points="6 9 12 15 18 9"></polyline>
          </svg>
        </button>
      </div>
      
      {expanded && (
        <div className="border-t border-gray-200 dark:border-gray-700 p-4 bg-gray-50 dark:bg-gray-700">
          <h4 className="font-medium text-sm mb-2">Running Services</h4>
          <ul className="space-y-2">
            {server.services.map((service, index) => (
              <li key={index} className="flex justify-between items-center">
                <span className="text-sm truncate">{service.name}</span>
                <ServiceStatus status={service.status} />
              </li>
            ))}
          </ul>
          
          {server.specs && (
            <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
              <h4 className="font-medium text-sm mb-2">Specifications</h4>
              <ul className="space-y-1 text-xs text-gray-600 dark:text-gray-400">
                <li className="flex justify-between">
                  <span>CPU:</span>
                  <span className="font-medium">{server.specs.cpu}</span>
                </li>
                <li className="flex justify-between">
                  <span>Cores:</span>
                  <span className="font-medium">{server.specs.cores}</span>
                </li>
                <li className="flex justify-between">
                  <span>RAM:</span>
                  <span className="font-medium">{server.specs.ram}</span>
                </li>
                <li className="flex justify-between">
                  <span>Storage:</span>
                  <span className="font-medium">{server.specs.storage}</span>
                </li>
                <li className="flex justify-between">
                  <span>OS:</span>
                  <span className="font-medium">{server.specs.os}</span>
                </li>
              </ul>
            </div>
          )}
          
          <div className="mt-4 pt-4 border-t border-gray-200 dark:border-gray-600">
            <div className="flex justify-between items-center text-sm">
              <span>Uptime:</span>
              <span className={`font-medium ${
                parseFloat(server.uptime) > 99.9 ? 'text-success' : 
                parseFloat(server.uptime) > 99.0 ? 'text-warning' : 'text-danger'
              }`}>{server.uptime || 'Unknown'}</span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

