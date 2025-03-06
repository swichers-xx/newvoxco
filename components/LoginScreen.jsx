window.LoginScreen = function LoginScreen({ onLogin }) {
  const [loginForm, setLoginForm] = React.useState({ 
    username: '', 
    password: '', 
    isLoading: false, 
    error: null 
  });
  const [theme, setTheme] = React.useState(
    document.body.classList.contains('dark') ? 'dark' : 'light'
  );

  // Handle login form submission
  const handleLogin = async (e) => {
    e.preventDefault();
    
    try {
      setLoginForm(prev => ({ ...prev, isLoading: true, error: null }));
      
      const result = await window.API.login(loginForm.username, loginForm.password);
      
      if (result.success) {
        if (onLogin) {
          onLogin(result);
        }
      } else {
        setLoginForm(prev => ({ ...prev, isLoading: false, error: result.error }));
      }
    } catch (error) {
      setLoginForm(prev => ({ 
        ...prev, 
        isLoading: false, 
        error: 'Login failed. Please check if the server is running and try again.' 
      }));
    }
  };

  // Toggle theme
  const toggleTheme = () => {
    const newTheme = theme === 'light' ? 'dark' : 'light';
    setTheme(newTheme);
    document.body.classList.toggle('dark');
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-100 dark:bg-gray-900 px-4">
      <div className="max-w-md w-full bg-white dark:bg-gray-800 rounded-lg shadow-md overflow-hidden">
        <div className="p-6">
          <div className="flex justify-center mb-8">
            <div className="flex items-center">
              <svg className="h-10 w-10 text-primary mr-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
                <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
                <line x1="6" y1="6" x2="6" y2="6"></line>
                <line x1="6" y1="18" x2="6" y2="18"></line>
              </svg>
              <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Voxco Server Dashboard</h1>
            </div>
          </div>
          
          <h2 className="text-xl font-bold text-center mb-6 text-gray-800 dark:text-white">Login</h2>
          
          {loginForm.error && (
            <div className="mb-4 p-3 bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300 rounded-md text-sm">
              {loginForm.error}
            </div>
          )}
          
          <form onSubmit={handleLogin}>
            <div className="mb-4">
              <label className="block text-gray-700 dark:text-gray-300 text-sm font-medium mb-2" htmlFor="username">
                Username
              </label>
              <input
                id="username"
                type="text"
                value={loginForm.username}
                onChange={(e) => setLoginForm(prev => ({ ...prev, username: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary dark:bg-gray-700 dark:text-white"
                required
                autoFocus
              />
            </div>
            
            <div className="mb-6">
              <label className="block text-gray-700 dark:text-gray-300 text-sm font-medium mb-2" htmlFor="password">
                Password
              </label>
              <input
                id="password"
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm(prev => ({ ...prev, password: e.target.value }))}
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md shadow-sm focus:outline-none focus:ring-primary focus:border-primary dark:bg-gray-700 dark:text-white"
                required
              />
            </div>
            
            <button
              type="submit"
              disabled={loginForm.isLoading}
              className="w-full py-2 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-primary hover:bg-blue-600 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary disabled:bg-blue-400 disabled:cursor-not-allowed"
            >
              {loginForm.isLoading ? (
                <span className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-2 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Logging in...
                </span>
              ) : 'Login'}
            </button>
          </form>
          
          <div className="mt-6 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Demo credentials: admin / admin
            </p>
          </div>
          
          <div className="mt-8 pt-6 border-t border-gray-200 dark:border-gray-700 text-center">
            <button
              onClick={toggleTheme}
              className="text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white"
            >
              {theme === 'light' ? 'Switch to Dark Mode' : 'Switch to Light Mode'}
            </button>
          </div>

          <div className="mt-4 text-center">
            <p className="text-xs text-gray-500 dark:text-gray-400">
              Version 1.0.0 | &copy; 2025 Voxco
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}