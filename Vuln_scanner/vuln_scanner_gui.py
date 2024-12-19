import os
import nmap
import shodan
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import configparser
from datetime import datetime
import json
import requests

# Function to read the Shodan API key from config.ini
def get_shodan_api_key():
    config = configparser.ConfigParser()
    try:
        config_path = os.path.join(os.getcwd(), 'config.ini')
        config.read(config_path)
        return config['shodan']['api_key']
    except KeyError:
        messagebox.showerror("Error", "API Key not found in config.ini")
        return None
    except FileNotFoundError:
        messagebox.showerror("Error", "config.ini not found. Place it in the same directory as this script.")
        return None

# Function to scan open ports using nmap with advanced options
def scan_ports(target_ip):
    nm = nmap.PortScanner()
    open_ports = []
    update_progress(20)

    log_message("Starting advanced scan on target...")
    try:
        # Advanced nmap scan
        nm.scan(hosts=target_ip, arguments='-O -sV -p- -T4')
        host_data = {"host": target_ip, "ports": [], "os": {}, "state": ""}

        for host in nm.all_hosts():
            host_data["state"] = nm[host].state()
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_info = {
                        "port": port,
                        "state": nm[host][proto][port]["state"],
                        "service": nm[host][proto][port].get("name", "Unknown"),
                        "product": nm[host][proto][port].get("product", "Unknown"),
                    }
                    if port_info["state"] == "open":
                        open_ports.append(port)
                    host_data["ports"].append(port_info)

            if "osclass" in nm[host]:
                host_data["os"] = nm[host]["osclass"]

        display_host_status(host_data)
        update_progress(50)
        return open_ports, host_data
    except Exception as e:
        log_message(f"Error during scanning: {e}")
    return open_ports, {}

# Function to fetch vulnerabilities using Shodan
def check_vulnerabilities(target_ip, open_ports, shodan_key):
    try:
        api = shodan.Shodan(shodan_key)
        result = api.host(target_ip)
        vulnerabilities = []

        update_progress(70)
        for port in open_ports:
            for item in result['data']:
                if item['port'] == port:
                    vulnerabilities.append({
                        "port": port,
                        "product": item.get('product', 'Unknown'),
                        "vulnerabilities": item.get('vulns', 'No known vulnerabilities')
                    })
        display_vulnerabilities(vulnerabilities)
        update_progress(100)
    except shodan.APIError as e:
        log_message(f"Shodan API Error: {e}")
    except Exception as e:
        log_message(f"Error during Shodan query: {e}")

# Function to retrieve host location
def fetch_location(ip):
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        if response.status_code == 200:
            location_data = response.json()
            display_location(location_data)
    except Exception as e:
        log_message(f"Error fetching location: {e}")

# Function to display host status
def display_host_status(host_data):
    host_status_tab.delete('1.0', tk.END)
    host_status_tab.insert(tk.END, f"Host: {host_data['host']}\n")
    host_status_tab.insert(tk.END, f"State: {host_data['state']}\n")
    host_status_tab.insert(tk.END, "Ports:\n")
    for port in host_data["ports"]:
        host_status_tab.insert(
            tk.END,
            f"  Port: {port['port']} | State: {port['state']} | Service: {port['service']} | Product: {port['product']}\n"
        )
    host_status_tab.insert(tk.END, f"OS: {host_data['os']}\n")

# Function to display vulnerabilities
def display_vulnerabilities(vulnerabilities):
    vulnerabilities_tab.delete('1.0', tk.END)
    vulnerabilities_tab.insert(tk.END, "--- Vulnerabilities ---\n")
    for vuln in vulnerabilities:
        vulnerabilities_tab.insert(
            tk.END,
            f"Port {vuln['port']}: {vuln['product']} - {vuln['vulnerabilities']}\n"
        )

# Function to display location
def display_location(location_data):
    location_tab.delete('1.0', tk.END)
    location_tab.insert(tk.END, "--- Location Information ---\n")
    for key, value in location_data.items():
        location_tab.insert(tk.END, f"{key.capitalize()}: {value}\n")

# Function to log messages in real-time
def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    progress_tab.insert(tk.END, f"{timestamp} {message}\n")
    progress_tab.see(tk.END)

# Function to update progress bar
def update_progress(value):
    progress_bar["value"] = value
    app.update_idletasks()

# Main function triggered by the Scan button
def start_scan():
    target_ip = ip_entry.get()
    shodan_key = get_shodan_api_key()

    if not target_ip:
        messagebox.showerror("Input Error", "Please enter the Target IP address.")
        return

    if not shodan_key:
        return

    progress_bar["value"] = 0
    progress_tab.delete('1.0', tk.END)

    log_message("Starting scan...")
    open_ports, host_data = scan_ports(target_ip)
    fetch_location(target_ip)
    if open_ports:
        check_vulnerabilities(target_ip, open_ports, shodan_key)
    else:
        log_message("No open ports found.")

# GUI Design
app = tk.Tk()
app.title("Advanced Vulnerability Scanner")
app.geometry("900x700")
app.config(bg="black")

style = ttk.Style()
style.configure("TNotebook", background="black")
style.configure("TNotebook.Tab", background="black", foreground="green", font=("Courier", 12))
style.configure("TFrame", background="black")
style.configure("TButton", background="black", foreground="green", font=("Courier", 12))

# Tabs
tabs = ttk.Notebook(app)
tabs.pack(expand=1, fill="both")

host_status_tab = scrolledtext.ScrolledText(app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10))
tabs.add(host_status_tab, text="Host Status")

vulnerabilities_tab = scrolledtext.ScrolledText(app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10))
tabs.add(vulnerabilities_tab, text="Vulnerabilities")

location_tab = scrolledtext.ScrolledText(app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10))
tabs.add(location_tab, text="Host Location")

progress_tab = scrolledtext.ScrolledText(app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10))
tabs.add(progress_tab, text="Logs")

# Input and Progress Bar
input_frame = ttk.Frame(app)
input_frame.pack(pady=10)

tk.Label(input_frame, text="Target IP:", bg="black", fg="green", font=("Courier", 12)).grid(row=0, column=0, padx=5)
ip_entry = tk.Entry(input_frame, width=50, bg="black", fg="green", font=("Courier", 12))
ip_entry.grid(row=0, column=1, padx=5)

scan_button = ttk.Button(input_frame, text="Start Scan", command=start_scan)
scan_button.grid(row=0, column=2, padx=5)

progress_bar = ttk.Progressbar(app, orient="horizontal", length=700, mode="determinate")
progress_bar.pack(pady=10)

# Run the Application
app.mainloop()
