window.ConnectionStatus = function ConnectionStatus({ status }) {
  // Determine the appropriate styling based on connection status
  const getStatusStyles = () => {
    if (status.connected) {
      return {
        dotClass: "bg-success animate-pulse",
        textClass: "text-success",
        text: "Connected"
      };
    } else if (status.connecting) {
      return {
        dotClass: "bg-primary animate-pulse",
        textClass: "text-primary",
        text: "Connecting..."
      };
    } else if (status.reconnecting) {
      return {
        dotClass: "bg-warning animate-pulse",
        textClass: "text-warning",
        text: `Reconnecting (${status.attempts || 1})`
      };
    } else {
      return {
        dotClass: "bg-danger",
        textClass: "text-danger",
        text: "Disconnected"
      };
    }
  };
window.ConnectionStatus = function ConnectionStatus({ status, serverIp }) {
  const [winrmStatus, setWinrmStatus] = React.useState(null);

  React.useEffect(() => {
    async function fetchWinRMStatus() {
      try {
        const status = await window.API.getWinRMStatus(serverIp);
        setWinrmStatus(status);
      } catch (error) {
        setWinrmStatus('Error');
      }
    }
    fetchWinRMStatus();
  }, [serverIp]);

  const getStatusStyles = () => {
    if (status.connected) {
      return {
        dotClass: "bg-success animate-pulse",
        textClass: "text-success",
        text: "Connected"
      };
    } else if (status.connecting) {
      return {
        dotClass: "bg-primary animate-pulse",
        textClass: "text-primary",
        text: "Connecting..."
      };
    } else if (status.reconnecting) {
      return {
        dotClass: "bg-warning animate-pulse",
        textClass: "text-warning",
        text: `Reconnecting (${status.attempts || 1})`
      };
    } else {
      return {
        dotClass: "bg-danger",
        textClass: "text-danger",
        text: "Disconnected"
      };
    }
  };

  const styles = getStatusStyles();

  return (
    <div className="flex items-center">
      <span className={`h-2 w-2 rounded-full mr-2 ${styles.dotClass}`}></span>
      <span className={`text-sm ${styles.textClass}`}>
        {styles.text} (WINRM: {winrmStatus})
      </span>
      {status.error && (
        <span className="ml-2 text-xs text-gray-500 dark:text-gray-400" title={status.error.message || status.error}>
          <svg className="h-4 w-4 inline-block" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zm-1 9a1 1 0 102 0v-5a1 1 0 10-2 0v5z" clipRule="evenodd" />
          </svg>
        </span>
      )}
    </div>
  );
}

  const styles = getStatusStyles();

  return (
    <div className="flex items-center">
      <span className={`h-2 w-2 rounded-full mr-2 ${styles.dotClass}`}></span>
      <span className={`text-sm ${styles.textClass}`}>
        {styles.text}
      </span>
      {status.error && (
        <span className="ml-2 text-xs text-gray-500 dark:text-gray-400" title={status.error.message || status.error}>
          <svg className="h-4 w-4 inline-block" viewBox="0 0 20 20" fill="currentColor">
            <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zm-1 9a1 1 0 102 0v-5a1 1 0 10-2 0v5z" clipRule="evenodd" />
          </svg>
        </span>
      )}
    </div>
  );
}