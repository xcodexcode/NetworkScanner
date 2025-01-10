import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from scapy.all import (ARP, Ether, srp, IP, ICMP, sr1)
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, ICMP

import socket
import platform
import subprocess
import threading


class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner")
        self.root.geometry("800x600")

        self.status_var = None
        self.interface_combo = None
        self.detail_scan_button = None
        self.tree = None
        self.detail_text = None
        self.scan_results = []
        self.selected_host = None
        self.interfaces = self.get_network_interfaces()
        self.stop_scan = False

        self.create_widgets()

    def create_widgets(self):
        # Interface selection
        ttk.Label(self.root, text="Select Network Interface:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.interface_combo = ttk.Combobox(self.root, values=self.interfaces, state="readonly")
        self.interface_combo.grid(row=0, column=1, padx=5, pady=5, sticky="we")
        if self.interfaces:
            self.interface_combo.current(0)
        else:
            self.interface_combo.set("No interfaces found")
            self.interface_combo.config(state="disabled")

        # Status label
        self.status_var = tk.StringVar()
        self.status_label = ttk.Label(self.root, textvariable=self.status_var)
        self.status_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5, sticky="w")
        self.status_var.set("Ready to scan...")

        # Scan button
        self.scan_button = ttk.Button(self.root, text="Scan Network", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, pady=10)

        # Stop Scan button
        self.stop_scan_button = ttk.Button(self.root, text="Stop Scan", command=self.stop_scanning, state="disabled")
        self.stop_scan_button.grid(row=2, column=1, pady=10)

        # Detailed scan button
        self.detail_scan_button = ttk.Button(self.root, text="Detailed Scan", command=self.detailed_scan,
                                             state="disabled")
        self.detail_scan_button.grid(row=3, column=0, columnspan=2, pady=10)

        # Treeview for results
        self.tree = ttk.Treeview(self.root, columns=("IP", "MAC", "Hostname", "OS (Guess)"), show="headings")
        self.tree.heading("IP", text="IP Address")
        self.tree.heading("MAC", text="MAC Address")
        self.tree.heading("Hostname", text="Hostname")
        self.tree.heading("OS (Guess)", text="OS (Guess)")
        self.tree.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        self.tree.bind("<ButtonRelease-1>", self.select_host)
        self.tree.column("IP", width=100)
        self.tree.column("MAC", width=150)
        self.tree.column("Hostname", width=150)
        self.tree.column("OS (Guess)", width=100)
        self.root.grid_rowconfigure(4, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        # Detail text area
        self.detail_text = scrolledtext.ScrolledText(self.root, height=10)
        self.detail_text.grid(row=5, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")

    def get_network_interfaces(self):
        """Get a list of network interfaces."""
        if platform.system() == "Windows":
            try:
                output = subprocess.check_output(["ipconfig", "/all"], text=True)
                interfaces = []
                for line in output.splitlines():
                    if "Description" in line:
                        interfaces.append(line.split(": ")[1])
                return interfaces
            except Exception:
                return []

        elif platform.system() in ["Linux", "Darwin"]:
            try:
                output = subprocess.check_output(["ifconfig"], text=True)
                interfaces = []
                lines = output.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and ":" in line and line[0].isalpha():
                        interfaces.append(line.split(":")[0])
                return interfaces
            except Exception:
                return []
        else:
            return []

    def start_scan(self):
        self.stop_scan = False
        self.scan_results = []
        self.tree.delete(*self.tree.get_children())
        self.status_var.set("Scanning network...")
        self.scan_button.config(state="disabled")
        self.stop_scan_button.config(state="normal")
        self.detail_scan_button.config(state="disabled")
        self.detail_text.delete("1.0", tk.END)

        threading.Thread(target=self.scan_network).start()

    def stop_scanning(self):
        self.stop_scan = True
        self.status_var.set("Stopping scan...")

    def scan_network(self):
        if not self.interface_combo.get() or self.interface_combo.get() == "No interfaces found":
            messagebox.showerror("Error", "Select a valid Network interface")
            return

        try:
            self.perform_scan(self.interface_combo.get())
        except Exception as e:
            messagebox.showerror("Error during Scan Process", str(e))
        finally:
            self.scan_button.config(state="normal")
            self.stop_scan_button.config(state="disabled")
            self.status_var.set("Scan complete.")

    def perform_scan(self, interface):
        """Main network scan logic."""
        network_range = self.get_network_range(interface)
        if not network_range:
            self.status_var.set("Error: Could not determine network range.")
            return

        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network_range))
        answered_list, _ = srp(arp_request, timeout=2, verbose=False)

        for sent, received in answered_list:
            if self.stop_scan:
                break

            ip_address = received.psrc
            mac_address = received.hwsrc
            hostname = self.get_hostname(ip_address)
            os_guess = self.guess_os(ip_address)
            self.scan_results.append({
                "IP": ip_address,
                "MAC": mac_address,
                "Hostname": hostname,
                "OS (Guess)": os_guess
            })
            self.tree.insert("", "end", values=(ip_address, mac_address, hostname, os_guess))

    def get_network_range(self, interface):
        """Gets IP network range based on the interface selected."""
        if platform.system() == "Windows":
            try:
                output = subprocess.check_output(["ipconfig"], text=True)
                return "192.168.1.0/24"  # Example range
            except Exception:
                return None
        elif platform.system() in ["Linux", "Darwin"]:
            return "192.168.1.0/24"  # Example range

    def get_hostname(self, ip_address):
        """Get hostname from IP address."""
        try:
            return socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            return "Unknown"

    def guess_os(self, ip_address):
        """Guess OS based on IP."""
        try:
            response = sr1(IP(dst=ip_address) / ICMP(), verbose=0, timeout=1)
            if response:
                if response.ttl <= 64:
                    return "Linux"
                elif response.ttl <= 128:
                    return "Windows"
                else:
                    return "Unknown"
        except Exception:
            return "Unknown"
        return "Unknown"

    def select_host(self, event):
        """Selects a host from treeview and enables detailed scan button."""
        selected_item = self.tree.selection()
        if selected_item:
            item_values = self.tree.item(selected_item, "values")
            self.selected_host = item_values[0]
            self.detail_scan_button.config(state="normal")
        else:
            self.selected_host = None
            self.detail_scan_button.config(state="disabled")

    def detailed_scan(self):
        """Perform a detail scan on a host and display results."""
        if not self.selected_host:
            return

        self.detail_text.delete("1.0", tk.END)
        self.status_var.set(f"Performing detailed scan on {self.selected_host}...")
        self.detail_scan_button.config(state="disabled")
        self.root.update()

        scan_results_str = ""
        try:
            ports = [20, 21, 22, 80, 443, 8080]
            scan_results_str += f"Detailed scan results for: {self.selected_host}\n\n"

            for port in ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.selected_host, port))
                    if result == 0:
                        scan_results_str += f"Port {port}: Open\n"
                    else:
                        scan_results_str += f"Port {port}: Closed\n"
                    sock.close()
                except Exception:
                    scan_results_str += f"Error scanning port {port}.\n"

            self.detail_text.insert(tk.END, scan_results_str)
            self.status_var.set(f"Detailed scan on {self.selected_host} finished")

        except Exception as e:
            self.detail_text.insert(tk.END, f"Error during detailed scan: {str(e)}")
            self.status_var.set(f"Error during detailed scan on {self.selected_host}")
        finally:
            self.detail_scan_button.config(state="normal")


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()