const winrm = require('nodejs-winrm');
require('dotenv').config();

// Get credentials from environment variables
const userName = process.env.WINRM_USERNAME || 'your_username';
const password = process.env.WINRM_PASSWORD || 'your_password';
const host = process.env.WINRM_HOST || 'localhost';
const port = parseInt(process.env.WINRM_PORT || '5985', 10);
const auth = 'Basic ' + Buffer.from(`${userName}:${password}`).toString('base64');
const params = {
    host: host,
    port: port,
    path: '/wsman'
};
params.auth = auth;

// Function to execute a PowerShell command via WinRM
async function executeCommand(server, command) {
    try {
        console.log(`Executing command on ${server.ip || server}: ${command}`);
        
        // Create connection parameters for the specific server
        const serverParams = {
            ...params,
            host: server.ip || server
        };
        
        // Execute the command
        const client = new winrm.Client(serverParams);
        const result = await client.powershell(command);
        
        console.log(`Command result: ${JSON.stringify(result)}`);
        return result;
    } catch (error) {
        console.error(`Error executing command on ${server.ip || server}:`, error);
        throw error;
    }
}

// Get server CPU usage
async function getCpuUsage(server) {
    try {
        const command = `Get-WmiObject Win32_Processor | Measure-Object -Property LoadPercentage -Average | Select-Object -ExpandProperty Average`;
        const result = await executeCommand(server, command);
        return parseFloat(result.stdout.trim()) || 0;
    } catch (error) {
        console.error('Error getting CPU usage:', error);
        return null;
    }
}

// Get server memory usage
async function getMemoryUsage(server) {
    try {
        const command = `
            $os = Get-WmiObject Win32_OperatingSystem
            $totalMemory = $os.TotalVisibleMemorySize
            $freeMemory = $os.FreePhysicalMemory
            $usedMemory = $totalMemory - $freeMemory
            $percentUsed = [math]::Round(($usedMemory / $totalMemory) * 100, 2)
            Write-Output $percentUsed
        `;
        const result = await executeCommand(server, command);
        return parseFloat(result.stdout.trim()) || 0;
    } catch (error) {
        console.error('Error getting memory usage:', error);
        return null;
    }
}

// Get server disk usage
async function getDiskUsage(server) {
    try {
        const command = `
            Get-WmiObject Win32_LogicalDisk -Filter "DriveType=3" | 
            Select-Object DeviceID, @{Name="Size";Expression={[math]::Round($_.Size/1GB, 2)}}, @{Name="FreeSpace";Expression={[math]::Round($_.FreeSpace/1GB, 2)}}, @{Name="PercentUsed";Expression={[math]::Round(($_.Size - $_.FreeSpace) / $_.Size * 100, 2)}} | 
            ConvertTo-Json
        `;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error('Error getting disk usage:', error);
        return null;
    }
}

// Get server uptime
async function getUptime(server) {
    try {
        const command = `
            $os = Get-WmiObject Win32_OperatingSystem
            $uptime = (Get-Date) - $os.ConvertToDateTime($os.LastBootUpTime)
            Write-Output "$($uptime.Days) days, $($uptime.Hours) hours, $($uptime.Minutes) minutes"
        `;
        const result = await executeCommand(server, command);
        return result.stdout.trim();
    } catch (error) {
        console.error('Error getting uptime:', error);
        return null;
    }
}

// Get server information (OS, CPU, RAM)
async function getServerInfo(server) {
    try {
        const command = `
            $os = Get-WmiObject Win32_OperatingSystem
            $cpu = Get-WmiObject Win32_Processor
            $cs = Get-WmiObject Win32_ComputerSystem
            
            $info = @{
                OSName = $os.Caption
                OSVersion = $os.Version
                CPUName = $cpu.Name
                CPUCores = $cpu.NumberOfCores
                TotalRAM = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
                Hostname = $env:COMPUTERNAME
            }
            
            ConvertTo-Json $info
        `;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error('Error getting server info:', error);
        return null;
    }
}

// Get service status
async function getServiceStatus(server, serviceName) {
    try {
        const command = `Get-Service -Name "${serviceName}" | Select-Object -Property Name, DisplayName, Status | ConvertTo-Json`;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error(`Error getting status for service ${serviceName}:`, error);
        return null;
    }
}

// Get all services
async function getAllServices(server) {
    try {
        const command = `Get-Service | Select-Object -Property Name, DisplayName, Status | ConvertTo-Json`;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error('Error getting all services:', error);
        return null;
    }
}

// Start a service
async function startService(server, serviceName) {
    try {
        const command = `Start-Service -Name "${serviceName}" -PassThru | Select-Object -Property Name, Status | ConvertTo-Json`;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error(`Error starting service ${serviceName}:`, error);
        return null;
    }
}

// Stop a service
async function stopService(server, serviceName) {
    try {
        const command = `Stop-Service -Name "${serviceName}" -PassThru | Select-Object -Property Name, Status | ConvertTo-Json`;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error(`Error stopping service ${serviceName}:`, error);
        return null;
    }
}

// Restart a service
async function restartService(server, serviceName) {
    try {
        const command = `Restart-Service -Name "${serviceName}" -PassThru | Select-Object -Property Name, Status | ConvertTo-Json`;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error(`Error restarting service ${serviceName}:`, error);
        return null;
    }
}

// Get server performance metrics (CPU, Memory, Disk)
async function getServerMetrics(server) {
    try {
        const cpuUsage = await getCpuUsage(server);
        const memoryUsage = await getMemoryUsage(server);
        const diskUsage = await getDiskUsage(server);
        const uptime = await getUptime(server);
        
        return {
            cpuUsage,
            memoryUsage,
            diskUsage,
            uptime
        };
    } catch (error) {
        console.error('Error getting server metrics:', error);
        return null;
    }
}

// Test WinRM connection to a server
async function testConnection(server) {
    try {
        const command = 'Get-ComputerInfo | Select-Object -Property CsName | ConvertTo-Json';
        const result = await executeCommand(server, command);
        return {
            success: true,
            data: JSON.parse(result.stdout.trim())
        };
    } catch (error) {
        console.error('Error testing connection:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Get all services from a server
async function getServices(server) {
    try {
        const command = `
            Get-Service | 
            Select-Object -Property Name, DisplayName, Status, StartType |
            Sort-Object -Property DisplayName |
            ConvertTo-Json -Depth 1
        `;
        const result = await executeCommand(server, command);
        return JSON.parse(result.stdout.trim());
    } catch (error) {
        console.error('Error getting services:', error);
        return [];
    }
}

// Reboot a server
async function rebootServer(server) {
    try {
        const command = 'Restart-Computer -Force';
        await executeCommand(server, command);
        return true;
    } catch (error) {
        console.error('Error rebooting server:', error);
        return false;
    }
}

// Connect to WinRM and test connection
async function connectToWinRM() {
    console.log('Connecting to WINRM server...');
    console.log('Connection parameters:', {
        host: params.host,
        port: params.port,
        username: userName
    });
    const result = await testConnection(params.host);
    if (result.success) {
        console.log('Connection successful:', result.data);
    } else {
        console.error('Connection failed:', result.error);
    }
}

// Only connect if this file is run directly
if (require.main === module) {
    connectToWinRM();
}

// Export the connection parameters and functions for use in other modules
module.exports = {
    params,
    connectToWinRM,
    executeCommand,
    getCpuUsage,
    getMemoryUsage,
    getDiskUsage,
    getUptime,
    getServerInfo,
    getServiceStatus,
    getAllServices,
    startService,
    stopService,
    restartService,
    getServerMetrics,
    testConnection,
    getServices,
    rebootServer
};