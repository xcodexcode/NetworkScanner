
# NetworkScanner


---

# Network Scanner App

A simple network scanning tool built using Python's `tkinter` for the graphical interface and `scapy` for network scanning. This application allows users to scan a network for devices, display basic information about the devices (like IP, MAC address, hostname, and OS guess), and perform detailed scans on selected hosts.

## Features
- **Network Interface Selection**: Choose the network interface to scan.
- **Basic Network Scan**: Discover devices on the local network, showing IP address, MAC address, hostname, and an OS guess.
- **Detailed Host Scan**: Perform a port scan on selected hosts to identify open ports (HTTP, HTTPS, FTP, SSH, etc.).
- **Cross-platform Support**: Works on Windows, Linux, and macOS.

## Requirements
- Python 3.x
- `scapy` (for network scanning)
- `tkinter` (for the graphical interface)

### Installation
1. Install Python 3.x from [python.org](https://www.python.org/).
2. Install the required libraries by running:

   ```bash
   pip install scapy
   ```

3. Download or clone this repository.

### Running the Application
1. After downloading or cloning the repository, navigate to the project directory in the terminal.
2. Run the following command:

   ```bash
   python network_scanner.py
   ```

3. The GUI will open, allowing you to:
   - Select a network interface (Ethernet, Wi-Fi, etc.)
   - Scan the network for devices.
   - Perform a detailed port scan on any selected host.

### How to Use
1. **Select Network Interface**: From the dropdown at the top, select the network interface you want to scan.
2. **Scan Network**: Click the "Scan Network" button to discover devices on the network.
3. **Stop Scan**: If you wish to stop a running scan, click the "Stop Scan" button.
4. **Detailed Scan**: After scanning, select a device from the list and click the "Detailed Scan" button to perform a port scan on that device.
5. **View Results**: Scan results will be displayed in a table with information about each device. Detailed results will appear in a scrollable text area.

### Example Use Case
1. **Scan for Devices**: Select the interface, click "Scan Network," and the app will show a list of active devices on the local network.
2. **Detailed Scan**: After selecting a device, click "Detailed Scan" to check open ports on that device (useful for detecting services like HTTP, SSH, FTP, etc.).

### Code Overview
- **`NetworkScannerApp` Class**: The main class that handles the GUI and network scanning logic.
  - `get_network_interfaces()`: Retrieves available network interfaces.
  - `start_scan()`: Starts a network scan by sending ARP requests to detect active hosts.
  - `perform_scan()`: Executes the ARP scan and populates the results.
  - `detailed_scan()`: Performs a basic port scan on a selected host.
    ![image](https://github.com/user-attachments/assets/7648d513-9ea4-4352-a213-ce648f763db7)

  
- **`scapy`**: Used for sending ARP requests, scanning the network, and performing ICMP pings to guess the OS.
- **`tkinter`**: Used to create the GUI components, such as buttons, labels, and the treeview for displaying scan results.

### License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### Credits
- **Python**: Core programming language.
- **scapy**: Powerful Python library used for network packet manipulation.
- **tkinter**: Python's built-in library for creating graphical user interfaces.
-    OWNER NABIL MISKI


