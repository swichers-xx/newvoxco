window.ServerTable = function ServerTable({ servers }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-700">
          <thead className="bg-gray-50 dark:bg-gray-700">
            <tr>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Server
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                IP Address
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Services
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Status
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Uptime
              </th>
              <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-400 uppercase tracking-wider">
                Last Reboot
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
            {servers.map((server) => (
              <tr key={server.name} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="font-medium">{server.name}</div>
                  <div className="text-xs text-gray-500">{server.specs?.os || 'N/A'}</div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-600 dark:text-gray-400">{server.ip || 'Not available'}</div>
                </td>
                <td className="px-6 py-4">
                  <div className="flex flex-wrap gap-2">
                    {server.services.map((service, index) => {
                      let dotClass = '';
                      if (service.status === 'online') dotClass = 'bg-success';
                      else if (service.status === 'warning') dotClass = 'bg-warning';
                      else dotClass = 'bg-danger';
                      
                      return (
                        <div key={index} className="flex items-center space-x-1">
                          <span className={`h-2 w-2 rounded-full ${dotClass}`}></span>
                          <span className="text-sm">{service.name}</span>
                        </div>
                      );
                    })}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  {(() => {
                    const offlineCount = server.services.filter(s => s.status === 'offline').length;
                    const warningCount = server.services.filter(s => s.status === 'warning').length;
                    
                    if (offlineCount > 0) {
                      return <ServiceStatus status="offline" />;
                    } else if (warningCount > 0) {
                      return <ServiceStatus status="warning" />;
                    } else {
                      return <ServiceStatus status="online" />;
                    }
                  })()}
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className={`text-sm font-medium ${
                    parseFloat(server.uptime) > 99.9 ? 'text-success' : 
                    parseFloat(server.uptime) > 99.0 ? 'text-warning' : 'text-danger'
                  }`}>
                    {server.uptime || 'N/A'}
                  </div>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <div className="text-sm text-gray-600 dark:text-gray-400">
                    {server.lastReboot || 'Unknown'}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

