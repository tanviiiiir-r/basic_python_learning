import os
import nmap
import shodan
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import configparser
import threading
from datetime import datetime
import json
import requests
import ipaddress

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

def update_tab_content(tab, content):
    tab.config(state="normal")  # Temporarily enable editing
    tab.delete('1.0', tk.END)  # Clear existing content
    tab.insert(tk.END, content)  # Insert new content
    tab.config(state="disabled")  # Disable editing again

# Function to validate IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

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
                for os_class in nm[host]["osclass"]:
                    os_info = f"OS: {os_class.get('osfamily', 'Unknown')} {os_class.get('osgen', '')} | Accuracy: {os_class.get('accuracy', 'N/A')}%"
                    host_data["os"].append(os_info)
        

        display_host_status(host_data)
        update_progress(50)
        return open_ports, host_data
    except Exception as e:
        log_message(f"Error during scanning: {e}")
    return open_ports, {}

# Function to scan using Nmap scripts
def nmap_script_scan(target_ip):
    nm = nmap.PortScanner()
    script_results = []
    log_message("Running Nmap script scan...")
    try:
        nm.scan(hosts=target_ip, arguments='--script vuln -T4')
        for host in nm.all_hosts():
            if "hostscript" in nm[host]:
                for script in nm[host]["hostscript"]:
                    script_results.append({
                        "id": script.get("id", "Unknown"),
                        "output": script.get("output", "No output")
                    })
        display_script_results(script_results)
    except Exception as e:
        log_message(f"Error during Nmap script scan: {e}")

# Function to display script results
def display_script_results(script_results):
    vulnerabilities_tab.insert(tk.END, "--- Script Results ---\n")
    for result in script_results:
        vulnerabilities_tab.insert(
            tk.END,
            f"Script ID: {result['id']}\nOutput: {result['output']}\n\n"
        )

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
    content = f"Host: {host_data['host']}\n"
    content += f"State: {host_data['state']}\n"
    content += "Ports:\n"
    for port in host_data["ports"]:
        content += f"  Port: {port['port']} | State: {port['state']} | Service: {port['service']} | Product: {port['product']}\n"
    content += f"OS: {host_data['os']}\n"
    update_tab_content(host_status_tab, content)

# Function to save results to a JSON file
def export_results(data):
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
    if file_path:
        try:
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
            log_message(f"Results exported to {file_path}")
        except Exception as e:
            log_message(f"Error exporting results: {e}")

# Function to display vulnerabilities
def display_vulnerabilities(vulnerabilities):
    content = "--- Vulnerabilities ---\n"
    for vuln in vulnerabilities:
        content += f"Port {vuln['port']}: {vuln['product']} - {vuln['vulnerabilities']}\n"
    update_tab_content(vulnerabilities_tab, content)

# Function to display location
def display_location(location_data):
    content = "--- Location Information ---\n"
    for key, value in location_data.items():
        content += f"{key.capitalize()}: {value}\n"
    update_tab_content(location_tab, content)

# Function to log messages in real-time
def log_message(message):
    timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    content = f"{timestamp} {message}\n"
    update_tab_content(progress_tab, content)

# Function to update progress bar
def update_progress(value):
    progress_bar["value"] = value
    app.update_idletasks()


# Threaded function for starting the scan
def start_scan_thread():
    threading.Thread(target=start_scan, daemon=True).start()

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

# Style for Tabs
style.configure("TNotebook", background="black")
style.configure("TNotebook.Tab", background="black", foreground="green", font=("Courier", 12))

# Style for Frames
style.configure("TFrame", background="black")

# Default Button Style (white background, green font)
style.configure("TButton", background="white", foreground="green", font=("Courier", 12), padding=5)
style.map("TButton", background=[("active", "lightgray")])

# Custom Style for Red Buttons (Start Scan and Export Results)
style.configure("RedButton.TButton", background="#000000", foreground="red", font=("Courier", 12), padding=5)
style.map("RedButton.TButton", background=[("active", "#1a1a1a")])  # Deep black background on hover


# Tabs
tabs = ttk.Notebook(app)
tabs.pack(expand=1, fill="both")

# Host Status Tab
host_status_tab = scrolledtext.ScrolledText(
    app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10), state="disabled"
)
tabs.add(host_status_tab, text="Host Status")

# Vulnerabilities Tab
vulnerabilities_tab = scrolledtext.ScrolledText(
    app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10), state="disabled"
)
tabs.add(vulnerabilities_tab, text="Vulnerabilities")

# Host Location Tab
location_tab = scrolledtext.ScrolledText(
    app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10), state="disabled"
)
tabs.add(location_tab, text="Host Location")

# Logs Tab
progress_tab = scrolledtext.ScrolledText(
    app, wrap=tk.WORD, bg="black", fg="green", font=("Courier", 10), state="disabled"
)
tabs.add(progress_tab, text="Logs")



# Input and Progress Bar
input_frame = ttk.Frame(app)
input_frame.pack(pady=10)

tk.Label(input_frame, text="Target IP:", bg="black", fg="green", font=("Courier", 12)).grid(row=0, column=0, padx=5)
ip_entry = tk.Entry(input_frame, width=50, bg="black", fg="green", font=("Courier", 12))
ip_entry.grid(row=0, column=1, padx=5)

scan_button = ttk.Button(input_frame, text="Start Scan", command=start_scan)
scan_button.grid(row=0, column=2, padx=5)

export_button = ttk.Button(input_frame, text="Export Results", command=lambda: export_results(host_data))
export_button.grid(row=0, column=3, padx=5)

progress_bar = ttk.Progressbar(app, orient="horizontal", length=700, mode="determinate")
progress_bar.pack(pady=10)

# Run the Application
app.mainloop()
