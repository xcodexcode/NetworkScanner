import tkinter as tk
from tkinter import ttk, scrolledtext
import socket
import threading
import subprocess
import queue
import ipaddress


class NetworkTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Powerful Network Tool")

        # Queue for communication between threads and GUI
        self.results_queue = queue.Queue()

        # Flag to indicate if the scan is running
        self.scan_running = False

        # Network Information Section
        self.info_label = tk.Label(root, text="Network Information", font=("Arial", 14, "bold"))
        self.info_label.grid(row=0, column=0, columnspan=2, pady=5)

        self.ip_label = tk.Label(root, text="Your Current IP Address:")
        self.ip_label.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.ip_entry = tk.Entry(root)
        self.ip_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        self.ip_entry.insert(0, self.get_current_ip())
        self.ip_entry.config(state="readonly")

        # Network Range Section
        self.range_label = tk.Label(root, text="Enter Network Range (e.g., 192.168.1.0/24):")
        self.range_label.grid(row=2, column=0, padx=5, pady=5, sticky="w")

        self.range_entry = tk.Entry(root)
        self.range_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
        self.range_entry.insert(0, f"{self.get_current_subnet()}/24")

        # Scan Button
        self.scan_button = ttk.Button(root, text="Scan Network", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Stop Button
        self.stop_button = ttk.Button(root, text="Stop Scan", command=self.stop_scan, state=tk.DISABLED)
        self.stop_button.grid(row=3, column=1, pady=10)

        # Log Area
        self.log_area = scrolledtext.ScrolledText(root, height=20, wrap=tk.WORD)
        self.log_area.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.log_area.config(state="disabled")

    def log(self, message):
        """Append a message to the log area."""
        self.log_area.config(state="normal")
        self.log_area.insert(tk.END, message + "\n")
        self.log_area.see(tk.END)
        self.log_area.config(state="disabled")

    def get_current_ip(self):
        """Retrieve the current IP address."""
        try:
            hostname = socket.gethostname()
            return socket.gethostbyname(hostname)
        except Exception as e:
            return f"Error: {e}"

    def get_current_subnet(self):
        """Get the current subnet of the network."""
        ip = self.get_current_ip()
        try:
            ip_parts = ip.split(".")
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0"
        except IndexError:
            return "0.0.0.0"

    def start_scan(self):
        """Start the network scan in a separate thread."""
        network_range = self.range_entry.get()
        try:
            ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            self.log("Error: Invalid network range. Please enter a valid CIDR (e.g., 192.168.1.0/24).")
            return

        self.log(f"Starting scan for network range: {network_range}")
        self.scan_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_area.config(state="normal")
        self.log_area.delete(1.0, tk.END)
        self.log_area.config(state="disabled")

        self.scan_running = True  # Set flag to True indicating the scan is running
        scan_thread = threading.Thread(target=self.scan_network, args=(network_range,))
        scan_thread.start()
        self.root.after(100, self.process_results)

    def stop_scan(self):
        """Stop the network scan."""
        self.scan_running = False
        self.stop_button.config(state=tk.DISABLED)
        self.scan_button.config(state=tk.NORMAL)
        self.log("Scan stopped.")

    def scan_network(self, network_range):
        """Scan the network for active hosts, open ports, and hostnames."""
        try:
            net = ipaddress.ip_network(network_range, strict=False)
        except ValueError:
            self.results_queue.put("Error: Invalid network range.")
            self.results_queue.put("DONE")
            return

        for ip in net.hosts():
            if not self.scan_running:
                break  # Exit loop if scan is stopped

            ip_str = str(ip)
            if self.is_host_alive(ip_str):
                hostname = self.get_hostname(ip_str)
                self.results_queue.put(f"Host found: {ip_str} ({hostname}) - Scanning ports...")
                self.scan_ports(ip_str)
            else:
                self.results_queue.put(f"Host {ip_str} is down.")

        self.results_queue.put("Scan finished.")
        self.results_queue.put("DONE")

    def is_host_alive(self, ip):
        """Ping a host to check if it is alive."""
        try:
            subprocess.check_call(["ping", "-n", "1", "-w", "1000", ip],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except subprocess.CalledProcessError:
            return False

    def get_hostname(self, ip):
        """Retrieve the hostname of a host."""
        try:
            return socket.gethostbyaddr(ip)[0]
        except socket.herror:
            return "Unknown"

    def scan_ports(self, ip):
        """Scan the most common ports of a host."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
        for port in common_ports:
            if not self.scan_running:
                break  # Exit if scan is stopped
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)  # Set a more reasonable timeout
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        self.results_queue.put(f"\tPort {port} is open on {ip}")
            except Exception as e:
                self.results_queue.put(f"\tError scanning port {port} on {ip}: {e}")

    def process_results(self):
        """Update the GUI with results from the queue."""
        try:
            while True:
                result = self.results_queue.get_nowait()
                if result == "DONE":
                    self.scan_button.config(state=tk.NORMAL)
                    self.stop_button.config(state=tk.DISABLED)
                    break
                self.log(result)
        except queue.Empty:
            pass
        self.root.after(100, self.process_results)


if __name__ == "__main__":
    root = tk.Tk()
    tool = NetworkTool(root)
    root.mainloop()
