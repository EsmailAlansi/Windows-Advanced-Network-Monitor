# 🌐 Windows Advanced Network Monitor

[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-1.0.0-brightgreen.svg)](https://github.com/EsmailAlansi/Windows-Advanced-Network-Monitor/releases)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-brightgreen.svg)](https://github.com/EsmailAlansi/Windows-Advanced-Network-Monitor/graphs/commit-activity)

A comprehensive PowerShell tool for professional Windows network activity monitoring, analysis, and reporting. Provides deep visibility into all network connections with process mapping, service correlation, IP intelligence, and bandwidth monitoring.

---

## 📑 Table of Contents

- [✨ Features](#-features)
- [📸 Screenshots](#-screenshots)
- [🔧 Prerequisites](#-prerequisites)
- [🚀 Quick Start](#-quick-start)
- [📖 Usage Guide](#-usage-guide)
  - [Report Mode](#-report-mode)
  - [Monitor Mode](#-monitor-mode)
  - [Command Parameters](#-command-parameters)
- [📊 Report Contents](#-report-contents)
- [🔍 IP Classification](#-ip-classification)
- [💡 Use Cases](#-use-cases)
- [⚙️ Advanced Configuration](#️-advanced-configuration)
- [🛡️ Security Analysis](#️-security-analysis)
- [🔧 Troubleshooting](#-troubleshooting)
- [📈 Performance Benchmarks](#-performance-benchmarks)
- [🤝 Contributing](#-contributing)
- [📝 Changelog](#-changelog)
- [📄 License](#-license)
- [📞 Support](#-support)
- [🙏 Acknowledgments](#-acknowledgments)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Process Visibility** | All processes using network with full executable paths |
| 🔗 **Service Mapping** | Windows services associated with each network process |
| 📊 **Connection Stats** | Connection count per process with protocol breakdown |
| 🌍 **IP Intelligence** | Automatic classification (Private/Public/Loopback/APIPA) |
| 🔎 **DNS Resolution** | Hostname lookup for all remote IP addresses |
| 📈 **Bandwidth Monitor** | Real-time send/receive rates per network interface |
| 📝 **Change Logging** | Real-time detection and logging of new/closed connections |
| 📄 **Multiple Formats** | Export to comprehensive HTML or CSV reports |
| 🛡️ **Security Focus** | IP classification helps identify suspicious connections |
| ⚡ **Performance** | Efficient processing of 1000+ simultaneous connections |

---

## 📸 Screenshots

### HTML Report - Network Adapter Throughput
*Real-time bandwidth monitoring per network interface*

### HTML Report - Process Summary
*Complete process list with connection counts and services*

### HTML Report - Active Connections
*Detailed connection table with IP classification and DNS resolution*

### Real-Time Monitor - Console Output
*Live change detection with instant logging*

*(Add your screenshots in the `docs/screenshots/` folder)*

---

## 🔧 Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Operating System** | Windows 7 / Server 2012 | Windows 10/11 / Server 2019+ |
| **PowerShell** | 5.1 | 5.1+ |
| **Privileges** | Standard User | **Administrator** |
| **Network** | Active connection | Active connection |

> ⚠️ **Important:** Running as Administrator provides complete process paths and service information. Standard users will see limited data for system processes.

---

## 🚀 Quick Start

### Method 1: Clone and Run

```powershell
# Clone the repository
git clone https://github.com/EsmailAlansi/Windows-Advanced-Network-Monitor.git
cd Windows-Advanced-Network-Monitor

# Generate an HTML report
.\NetworkMonitor.ps1 -Mode Report -OutputFormat HTML -OutputPath "C:\Reports\network.html"

# Generate a CSV report
.\NetworkMonitor.ps1 -Mode Report -OutputFormat CSV -OutputPath "C:\Reports\network.csv"

# Start real-time monitoring
.\NetworkMonitor.ps1 -Mode Monitor -MonitorLogPath "C:\Logs\network_changes.log" -MonitorInterval 5