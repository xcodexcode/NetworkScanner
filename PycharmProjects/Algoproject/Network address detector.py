import psutil
import tkinter as tk
from tkinter import ttk
import socket
import ipaddress


def get_network_info():
    """Gather network interface data."""
    network_info = []
    for interface, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family == socket.AF_INET:  # Filter for IPv4 addresses
                try:
                    netmask_str = address.netmask
                    ip_str = address.address
                    if netmask_str is not None and ip_str is not None:
                       network_addr = ipaddress.ip_interface(f"{address.address}/{address.netmask}").network
                       network_info.append({
                        "Interface": interface,
                        "IP Address": ip_str,
                        "Netmask":  netmask_str,
                        "Network Address": str(network_addr),
                        "Is Wireless": "Yes" if "wlan" in interface.lower() or "wi-fi" in interface.lower() else "No"
                    })
                except ValueError:
                   pass # ignore the interfaces that do not have IPV4 addresses


    return network_info


def update_network_display():
    """Updates the GUI treeview with network information."""
    for item in tree.get_children():
        tree.delete(item)  # Clear existing data

    info = get_network_info()
    for row in info:
        tree.insert('', tk.END, values=(
            row["Interface"],
            row["IP Address"],
            row["Netmask"],
            row["Network Address"],
            row["Is Wireless"]
        ))


# GUI Setup
root = tk.Tk()
root.title("Network Address Detector")

# Create the Treeview widget with styling
tree = ttk.Treeview(root, columns=("Interface", "IP Address", "Netmask", "Network Address", "Wireless"),
                    show="headings")
tree.heading("Interface", text="Interface")
tree.heading("IP Address", text="IP Address")
tree.heading("Netmask", text="Netmask")
tree.heading("Network Address", text="Network Address")
tree.heading("Wireless", text="Wireless")

tree.column("Interface", width=100, anchor=tk.W)
tree.column("IP Address", width=100, anchor=tk.W)
tree.column("Netmask", width=100, anchor=tk.W)
tree.column("Network Address", width=150, anchor=tk.W)
tree.column("Wireless", width=80, anchor=tk.CENTER)

tree.pack(padx=10, pady=10, expand=True, fill="both")


# Refresh Button
refresh_button = tk.Button(root, text="Refresh", command=update_network_display)
refresh_button.pack(pady=5)

# Initialize the display
update_network_display()

root.mainloop()