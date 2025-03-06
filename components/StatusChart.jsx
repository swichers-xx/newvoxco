// StatusChart Component
window.StatusChart = function StatusChart({ title, servers }) {
  const chartRef = React.useRef(null);
  const chartInstance = React.useRef(null);
  
  React.useEffect(() => {
    // Calculate data for chart
    const statusCounts = {
      online: 0,
      warning: 0,
      offline: 0
    };
    
    servers.forEach(server => {
      server.services.forEach(service => {
        statusCounts[service.status]++;
      });
    });
    
    const data = {
      labels: ['Online', 'Warning', 'Offline'],
      datasets: [
        {
          data: [statusCounts.online, statusCounts.warning, statusCounts.offline],
          backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
          borderWidth: 0,
        }
      ]
    };
    
    // Destroy previous chart if it exists
    if (chartInstance.current) {
      chartInstance.current.destroy();
    }
    
    // Create new chart
    const ctx = chartRef.current.getContext('2d');
    chartInstance.current = new Chart(ctx, {
      type: 'doughnut',
      data: data,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              usePointStyle: true,
              padding: 20,
              color: document.body.classList.contains('dark') ? '#f8fafc' : '#1e293b'
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const value = context.raw;
                const percentage = Math.round((value / total) * 100);
                return `${context.label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
    
    return () => {
      if (chartInstance.current) {
        chartInstance.current.destroy();
      }
    };
  }, [servers]);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
      <h2 className="text-xl font-bold mb-4">{title}</h2>
      <div className="h-80">
        <canvas ref={chartRef}></canvas>
      </div>
    </div>
  );
}