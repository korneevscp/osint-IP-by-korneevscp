#!/usr/bin/env python3
import subprocess
import requests
import time
import sys
from rich.console import Console
from rich.table import Table
from rich.progress import track

console = Console()

# Function to display a loading animation
def loading(message):
    console.print(f"[bold cyan]{message}...[/bold cyan]")
    for _ in track(range(3), description="[bold yellow]Chargement...[/bold yellow]"):
        time.sleep(1)
    console.print("\n")

# Function to safely get user input
def safe_input(prompt):
    try:
        return input(prompt)
    except EOFError:
        console.print("[bold red]Erreur : Impossible de lire l'entrée utilisateur.[/bold red]")
        sys.exit(1)

# Function to scan the server for open or filtered ports (TCP and UDP)
def scan_faye_server(ip, port=None):
    loading(f"Scan de tous les ports sur le serveur {ip} / Scanning all ports on the server {ip}")
    
    # Initialize a table to display port scan results
    table = Table(title=f"Scan des ports sur {ip} / Port Scan for {ip}", show_lines=True)
    table.add_column("Port", style="cyan")
    table.add_column("Statut", style="magenta")
    console.print(table)  # Print an empty table first

    # Initialize a table for SSH-related services in light blue
    ssh_table = Table(title="Services SSH / SSH Services", show_lines=True, box="ROUND", border_style="blue")
    ssh_table.add_column("Port", style="cyan")
    ssh_table.add_column("Statut", style="magenta")
    ssh_table.add_column("Service", style="magenta")
    
    try:
        # If port is not provided, scan all ports (TCP and UDP)
        if port is None:
            result_tcp = subprocess.Popen(
                ["nmap", "-sS", "-p-", "--open", "-T4", "--min-rate", "1000", "--max-retries", "1", "-Pn", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            result_udp = subprocess.Popen(
                ["nmap", "-sU", "-p-", "--open", "-T4", "--min-rate", "1000", "--max-retries", "1", "-Pn", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            result_tcp = subprocess.Popen(
                ["nmap", "-sS", "-p", str(port), "--open", "-T4", "--min-rate", "1000", "--max-retries", "1", "-Pn", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            result_udp = subprocess.Popen(
                ["nmap", "-sU", "-p", str(port), "--open", "-T4", "--min-rate", "1000", "--max-retries", "1", "-Pn", ip],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

        # Process each line of output from nmap (TCP scan)
        for line in result_tcp.stdout:
            if "/tcp" in line:  # Look for lines with TCP ports
                parts = line.split()
                port = parts[0].strip("/")  # Extract port number
                port_status = parts[1]  # Extract port status
                service = parts[2] if len(parts) > 2 else "N/A"  # Extract service name
                
                # Add to the main port scan table
                table.add_row(f"{port}/tcp", port_status.capitalize())
                
                # Check if the service is related to SSH (or similar)
                if 'ssh' in service.lower():
                    ssh_table.add_row(f"{port}/tcp", port_status.capitalize(), service)
                
                # Update the display with the latest result
                console.clear()  # Clear previous output
                console.print(table)  # Print updated main table
                console.print(ssh_table)  # Print updated SSH service table

        # Process each line of output from nmap (UDP scan)
        for line in result_udp.stdout:
            if "/udp" in line:  # Look for lines with UDP ports
                parts = line.split()
                port = parts[0].strip("/")  # Extract port number
                port_status = parts[1]  # Extract port status
                service = parts[2] if len(parts) > 2 else "N/A"  # Extract service name
                
                # Add to the main port scan table
                table.add_row(f"{port}/udp", port_status.capitalize())
                
                # Check if the service is related to SSH (or similar)
                if 'ssh' in service.lower():
                    ssh_table.add_row(f"{port}/udp", port_status.capitalize(), service)
                
                # Update the display with the latest result
                console.clear()  # Clear previous output
                console.print(table)  # Print updated main table
                console.print(ssh_table)  # Print updated SSH service table

        # If no ports found, display a message
        if table.row_count == 0:
            console.print("[bold yellow]Aucun port trouvé sur le serveur / No ports found on the server.[/bold yellow]")
        else:
            console.print("[bold green][+][/bold green] Scan terminé / Scan complete.")

    except Exception as e:
        console.print(f"[bold red][-] Erreur de scan : {e} / Scan error: {e}")
        # Continue even if the scan fails

# Function to perform a traceroute
def traceroute(ip):
    loading(f"Exécution de traceroute vers {ip} / Performing traceroute to {ip}")
    try:
        result = subprocess.run(["traceroute", ip], capture_output=True, text=True)
        console.print(f"[bold cyan]Résultats du traceroute vers {ip} : / Traceroute results to {ip} :[/bold cyan]")
        console.print(result.stdout)
    except Exception as e:
        console.print(f"[bold red][-] Erreur de traceroute : {e} / Traceroute error: {e}")
        # Continue even if the traceroute fails

# Function to search for CVEs based on the service version
def search_cve_for_version(version):
    loading(f"Recherche de CVE pour la version {version} / Searching for CVEs for version {version}")
    url = f"https://cve.circl.lu/api/search/{version}"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        if data:
            console.print(f"[bold green][+][/bold green] {len(data)} CVE trouvées pour la version {version}: / {len(data)} CVEs found for version {version}:")
            table = Table(title="Liste des CVE / CVE List", show_lines=True)
            table.add_column("ID", style="cyan", no_wrap=True)
            table.add_column("Description", style="magenta")
            for cve in data[:5]:  # Show only top 5 CVEs for brevity
                table.add_row(cve['id'], cve['summary'])
            console.print(table)
        else:
            console.print("[bold yellow][-] Aucune CVE trouvée pour cette version. / No CVEs found for this version.")
    except requests.RequestException as e:
        console.print(f"[bold red][-] Erreur de connexion : {e} / Connection error: {e}")
        # Continue even if the CVE search fails

# Function to scan the server for services and test vulnerabilities (simple example for HTTP and SSH)
def test_vulnerabilities(ip):
    loading(f"Test des vulnérabilités pour {ip} / Testing vulnerabilities for {ip}")
    try:
        # Exemple de test de vulnérabilité SSH avec nmap / Example SSH vulnerability test using nmap
        result = subprocess.run(["nmap", "--script", "ssh-brute", ip], capture_output=True, text=True)
        console.print(f"[bold cyan]Résultats du test de vulnérabilité SSH : / SSH vulnerability test results :[/bold cyan]")
        console.print(result.stdout)
        
        # Exemple de test de vulnérabilité HTTP avec nmap / Example HTTP vulnerability test using nmap
        result = subprocess.run(["nmap", "--script", "http-vuln*","-p", "80,443", ip], capture_output=True, text=True)
        console.print(f"[bold cyan]Résultats du test de vulnérabilité HTTP : / HTTP vulnerability test results :[/bold cyan]")
        console.print(result.stdout)
        
    except Exception as e:
        console.print(f"[bold red][-] Erreur lors des tests de vulnérabilité : {e} / Error during vulnerability tests: {e}")
        # Continue even if vulnerability tests fail

# Function to run WhatWeb and get system information
def whatweb_scan(ip):
    loading(f"Exécution du scan WhatWeb sur {ip} / Running WhatWeb scan on {ip}")
    try:
        result = subprocess.run(["whatweb", ip], capture_output=True, text=True)
        
        # Initialize a table for WhatWeb results
        whatweb_table = Table(title=f"Informations récupérées par WhatWeb / Information from WhatWeb", show_lines=True)
        whatweb_table.add_column("Donnée / Data", style="cyan")
        whatweb_table.add_column("Valeur / Value", style="magenta")
        
        # Extract useful data from WhatWeb output
        os_info = "Inconnu / Unknown"
        technologies = "Aucune technologie trouvée / No technologies found"
        
        # Check if WhatWeb output has information about the OS or technologies
        if "OS" in result.stdout:
            os_info = result.stdout.split("OS:")[-1].split("\n")[0].strip()
        if "Technologies" in result.stdout:
            technologies = result.stdout.split("Technologies:")[-1].split("\n")[0].strip()
        
        # Add data to the table
        whatweb_table.add_row("Système d'exploitation / Operating System", os_info)
        whatweb_table.add_row("Technologies / Technologies", technologies)
        
        console.print(f"[bold cyan]Résultats du scan WhatWeb sur {ip} : / WhatWeb scan results for {ip} :[/bold cyan]")
        console.print(whatweb_table)
    except Exception as e:
        console.print(f"[bold red][-] Erreur lors du scan WhatWeb : {e} / Error during WhatWeb scan: {e}")
        # Continue even if WhatWeb scan fails

# Main function to execute all tests
def main():
    console.print("[bold blue]=== Pentest Garry's Mod === / === Garry's Mod Pentest ===[/bold blue]", style="bold blue")
    ip = safe_input("Entrez l'IP du serveur : / Enter the server IP: ")
    
    # Ask for optional port, default to None (will scan all ports if not specified)
    port_input = safe_input("Entrez un port (optionnel, laisser vide pour scanner tous les ports) : / Enter a port (optional, leave blank to scan all ports): ")
    port = int(port_input) if port_input and port_input.isdigit() else None  # If no port is entered, None is set

    # Scan à la recherche de 'faye' sur le serveur / Scan for 'faye' on the server
    scan_faye_server(ip, port)
    
    # Exécuter un traceroute vers le serveur / Perform a traceroute to the server
    traceroute(ip)
    
    # Tester les vulnérabilités sur le serveur / Test for vulnerabilities on the server
    test_vulnerabilities(ip)

    # Scanner avec WhatWeb pour obtenir des infos sur le système / Run WhatWeb to get system information
    whatweb_scan(ip)

if __name__ == "__main__":
    main()
