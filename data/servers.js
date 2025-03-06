// Server data with real-world information
window.serversData = [
  {
    name: "VXSQL1",
    ip: "172.16.1.150",
    services: [
      { name: "SQL Server", status: "online" },
      { name: "SQL Server Agent", status: "online" },
      { name: "SQL Browser", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2690 v4",
      cores: 14,
      ram: "64GB DDR4",
      storage: "4TB SSD RAID-10",
      os: "Windows Server 2019"
    },
    uptime: "99.98%",
    lastReboot: "2023-09-15 02:00:00"
  },
  {
    name: "VXDIRSRV",
    ip: "172.16.1.151",
    services: [
      { name: "VoxcoDirectoryService", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Active Directory Services", status: "online" },
      { name: "DNS Server", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2680 v3",
      cores: 12,
      ram: "32GB DDR4",
      storage: "2TB SSD RAID-1",
      os: "Windows Server 2016"
    },
    uptime: "99.95%",
    lastReboot: "2023-10-02 01:30:00"
  },
  {
    name: "VXOADMIN",
    ip: "172.16.1.160",
    services: [
      { name: "Voxco A4S Task Server", status: "online" },
      { name: "Voxco Email Server", status: "online" },
      { name: "Voxco Integration Service", status: "online" },
      { name: "Voxco Task Server", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2690 v4",
      cores: 14,
      ram: "64GB DDR4",
      storage: "2TB SSD RAID-5",
      os: "Windows Server 2019"
    },
    uptime: "99.90%",
    lastReboot: "2023-10-08 03:15:00"
  },
  {
    name: "VXSERVNO",
    ip: "172.16.1.27",
    services: [
      { name: "ServNoServer", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Windows Search", status: "warning" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2670 v3",
      cores: 12,
      ram: "32GB DDR4",
      storage: "1TB SSD RAID-1",
      os: "Windows Server 2016"
    },
    uptime: "98.75%",
    lastReboot: "2023-09-28 04:45:00"
  },
  {
    name: "VXCATI1",
    ip: "172.16.1.156",
    services: [
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "VoxcoBridgeService", status: "online" },
      { name: "Voxco CATI Engine", status: "online" },
      { name: "IIS Admin Service", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2680 v4",
      cores: 14,
      ram: "48GB DDR4",
      storage: "2TB SSD RAID-1",
      os: "Windows Server 2019"
    },
    uptime: "99.92%",
    lastReboot: "2023-09-20 02:30:00"
  },
  {
    name: "VXCATI2",
    ip: "172.16.1.157",
    services: [
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "VoxcoBridgeService", status: "online" },
      { name: "Voxco CATI Engine", status: "warning" },
      { name: "IIS Admin Service", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2680 v4",
      cores: 14,
      ram: "48GB DDR4",
      storage: "2TB SSD RAID-1",
      os: "Windows Server 2019"
    },
    uptime: "99.85%",
    lastReboot: "2023-09-25 01:15:00"
  },
  {
    name: "VXREPORT",
    ip: "172.16.1.153",
    services: [
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Voxco Reporting Engine", status: "online" },
      { name: "SQL Reporting Services", status: "online" },
      { name: "IIS Admin Service", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2690 v3",
      cores: 12,
      ram: "64GB DDR4",
      storage: "4TB SSD RAID-5",
      os: "Windows Server 2019"
    },
    uptime: "99.96%",
    lastReboot: "2023-09-18 03:45:00"
  },
  {
    name: "VXDIAL1",
    ip: "172.16.1.161",
    services: [
      { name: "ProntoServer", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Voxco Dialer Service", status: "online" },
      { name: "Voxco Telephone Gateway", status: "offline" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2670 v4",
      cores: 12,
      ram: "32GB DDR4",
      storage: "1TB SSD RAID-1",
      os: "Windows Server 2016"
    },
    uptime: "97.55%",
    lastReboot: "2023-10-05 02:00:00"
  },
  {
    name: "VXDIAL2",
    ip: "172.16.1.162",
    services: [
      { name: "ProntoServer", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Voxco Dialer Service", status: "online" },
      { name: "Voxco Telephone Gateway", status: "online" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2670 v4",
      cores: 12,
      ram: "32GB DDR4",
      storage: "1TB SSD RAID-1",
      os: "Windows Server 2016"
    },
    uptime: "99.82%",
    lastReboot: "2023-09-30 01:30:00"
  },
  {
    name: "VXDLR1",
    ip: "172.16.1.163",
    services: [
      { name: "ProntoServer", status: "online" },
      { name: "Voxco.InstallationService.exe", status: "online" },
      { name: "Voxco DLR Manager", status: "online" },
      { name: "Voxco Call Distribution", status: "warning" }
    ],
    specs: {
      cpu: "Intel Xeon E5-2660 v3",
      cores: 10,
      ram: "32GB DDR4",
      storage: "1TB SSD RAID-1",
      os: "Windows Server 2016"
    },
    uptime: "99.60%",
    lastReboot: "2023-10-01 04:15:00"
  }
];