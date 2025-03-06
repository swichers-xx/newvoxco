window.ServiceStatus = function ServiceStatus({ status }) {
  let styleClass, label;
  
  switch (status) {
    case 'online':
      styleClass = 'bg-success-light text-success';
      label = 'Online';
      break;
    case 'warning':
      styleClass = 'bg-warning-light text-warning';
      label = 'Warning';
      break;
    case 'offline':
      styleClass = 'bg-danger-light text-danger';
      label = 'Offline';
      break;
    default:
      styleClass = 'bg-gray-200 text-gray-600 dark:bg-gray-700 dark:text-gray-400';
      label = 'Unknown';
  }

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${styleClass}`}>
      {label}
    </span>
  );
}