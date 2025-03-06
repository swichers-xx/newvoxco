window.StatsCard = function StatsCard({ title, value, icon, color = 'primary' }) {
  let bgColorClass, textColorClass;
  
  switch (color) {
    case 'success':
      bgColorClass = 'bg-success-light';
      textColorClass = 'text-success';
      break;
    case 'warning':
      bgColorClass = 'bg-warning-light';
      textColorClass = 'text-warning';
      break;
    case 'danger':
      bgColorClass = 'bg-danger-light';
      textColorClass = 'text-danger';
      break;
    default: // primary
      bgColorClass = 'bg-primary-light';
      textColorClass = 'text-primary';
  }

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-md p-6">
      <div className="flex items-center">
        <div className={`flex-shrink-0 rounded-full p-3 ${bgColorClass} ${textColorClass}`}>
          {icon}
        </div>
        <div className="ml-4">
          <h3 className="text-sm font-medium text-gray-500 dark:text-gray-400">{title}</h3>
          <div className="text-2xl font-bold">{value}</div>
        </div>
      </div>
    </div>
  );
}