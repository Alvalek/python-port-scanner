#!/usr/bin/env python3
"""
STower - Signal Tower
A high-performance, network reconnaissance tool.
Author: Alvalek
Version: 1.0.0
Description: Multi-threaded port scanner with banner grabbing and JSON export.
"""

import socket
import threading
from datetime import datetime
import argparse
import sys
import json
import csv
from tqdm import tqdm
import subprocess
import platform
import time  
import random 

# Mock Vulnerability Database (For Educational Purposes)
KNOWN_VULNS = {
    "Apache/2.4.49": {"cve": "CVE-2021-41773", "severity": "CRITICAL", "desc": "Path Traversal"},
    "Apache/2.4.50": {"cve": "CVE-2021-42013", "severity": "CRITICAL", "desc": "Path Traversal"},
    "OpenSSH/7.4":   {"cve": "CVE-2018-15919", "severity": "HIGH", "desc": "Authentication Bypass"},
    "nginx/1.18.0":  {"cve": "CVE-2021-23017", "severity": "MEDIUM", "desc": "DNS Resolver Overflow"},
    "PHP/7.2.0":     {"cve": "CVE-2019-11043", "severity": "HIGH", "desc": "RCE via CGI"},
}

class STower:
    """
    STower: Signal Tower - Network Reconnaissance Engine
    """
    def __init__(self, target, start_port=1, end_port=1024):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.results = []
        self.threads = []

        self.stealth_enabled = False
        self.discovery_enabled = True
        self.stealth_delay = 0.5

    def detect_version(self, port, banner=None):
        """
        Attempt to detect service version and check against known vulnerabilities.
        
        Args:
            port (int): The port number.
            banner (str): The initial banner string (optional).
            
        Returns:
            dict: Contains 'version', 'vuln_status', and 'details'.
        """
        result = {
            "version": "Unknown",
            "vuln_status": "Safe",
            "details": None
        }

        
        if banner:
            if "Apache/" in banner:
                
                parts = banner.split("Apache/")
                if len(parts) > 1:
                    version_str = parts[1].split()[0] 
                    result["version"] = f"Apache/{version_str}"
            elif "nginx/" in banner:
                parts = banner.split("nginx/")
                if len(parts) > 1:
                    version_str = parts[1].split()[0]
                    result["version"] = f"nginx/{version_str}"
            elif "SSH-" in banner:
                if "OpenSSH_" in banner:
                    version_str = banner.split("OpenSSH_")[1].split()[0]
                    result["version"] = f"OpenSSH/{version_str}"
            elif "Microsoft-IIS/" in banner:
                parts = banner.split("Microsoft-IIS/")
                if len(parts) > 1:
                    version_str = parts[1].split()[0]
                    result["version"] = f"IIS/{version_str}"
        
       
        if result["version"] != "Unknown" and result["version"] in KNOWN_VULNS:
            vuln_info = KNOWN_VULNS[result["version"]]
            result["vuln_status"] = "VULNERABLE"
            result["details"] = f"{vuln_info['cve']} ({vuln_info['severity']}): {vuln_info['desc']}"
            
        return result

    def is_host_alive(self, timeout=2):
        """
        Smart Host Discovery: Tries ICMP first, then TCP fallback.
        """
        # 1. Try ICMP Ping (Fast, but often blocked)
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', '-W', str(timeout), self.target]
        
        try:
            if subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                return True
        except:
            pass

        # 2. Fallback: TCP Connect to common ports 
        # We try port 80 (HTTP) and 443 (HTTPS)
        common_ports = [80, 443, 22] 
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target, port))
                sock.close()
                
                # If we got a connection (0) or even a reset (connection refused), the host is UP
                # A "Connection Refused" (RST) means the host is alive but the port is closed.
                # A "Timeout" means the host might be filtering or dead.
                if result == 0 or result == 111: # 111 is ECONNREFUSED on Linux
                    return True
            except:
                continue
        
        return False
        
    def scan_port(self, port, delay=0.0):
        """Scan a single port with enhanced logging and version detection."""
        STD_GREEN = '\033[32m'           # Standard green (readable on black)
        BRIGHT_GREEN = '\033[92m\033[1m' # Bright + Bold (Success/Highlights)
        RED = '\033[91m\033[1m'          # Bright + Bold (Errors/Vulns)
        WHITE = '\033[97m'               # White (Headers)
        CYAN = '\033[96m'                # Cyan (Accents)
        RESET = '\033[0m'                # Reset
        BOLD = '\033[1m'                 # Bold modifier
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            result = sock.connect_ex((self.target, port))
            
            service_name = "Unknown"
            banner = None
            
            if result == 0:
                try:
                    sock.send(b'GET / HTTP/1.0\r\n\r\n')
                    banner_data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                    if banner_data:
                        banner_lines = banner_data.split('\r\n')[:3]
                        banner = '\r\n'.join(banner_lines)
                        
                        # Service Detection
                        if "Apache" in banner: service_name = "Apache"
                        elif "nginx" in banner: service_name = "nginx"
                        elif "Microsoft-IIS" in banner: service_name = "IIS"
                        elif "SSH" in banner: service_name = "SSH"
                        elif "FTP" in banner: service_name = "FTP"
                        else: service_name = "HTTP" 
                except:
                    pass
                
                # NEW: Detect Version and Check Vulnerabilities
                version_info = self.detect_version(port, banner)
                
                self.open_ports.append(port)
                
                # NEW: Store extended result
                self.results.append({
                    "port": port,
                    "state": "OPEN",
                    "service": service_name,
                    "banner": banner,
                    "version": version_info["version"],
                    "vuln_status": version_info["vuln_status"],
                    "vuln_details": version_info["details"]
                })
                
                # NEW: Construct Output String
                banner_str = f" | BANNER: {banner[:40]}..." if banner else ""
                version_str = f" [{version_info['version']}]" if version_info["version"] != "Unknown" else ""
                
                # Determine Status Symbol and Color (CORRECTLY INDENTED)
                if version_info["vuln_status"] == "VULNERABLE":
                    # VULNERABLE: Bright Red (Urgent)
                    status_color = RED
                    status_symbol = "[VULN]"
                    print(f"{status_color}[+] {port:5d} | OPEN  | {service_name:10s}{version_str}{banner_str} {status_symbol}{RESET}")
                    print(f"{RED}    [-] ALERT: {version_info['details']}{RESET}")
                else:
                    # SUCCESS: Bright Bold Green (Clear)
                    status_color = BRIGHT_GREEN
                    status_symbol = "[OK]"
                    print(f"{status_color}[+] {port:5d} | OPEN  | {service_name:10s}{version_str}{banner_str} {status_symbol}{RESET}")
                
            sock.close()
            
        except socket.error:
            pass
        except Exception:
            pass
            
        # Stealth Delay (must be outside try/except to ensure it runs)
        if delay > 0:
            actual_delay = delay + random.uniform(0, delay * 0.2)
            time.sleep(actual_delay)
    
    def scan(self, num_threads=50, discover_first=None, stealth=None, delay=None):
        """Scan with progress bar and threading."""    
        if discover_first is None:
            discover_first = self.discovery_enabled
        if stealth is None:
            stealth = self.stealth_enabled
        if delay is None:
            delay = self.stealth_delay if stealth else 0.0
        
        if discover_first:
            print(f"\n🔍︎ Performing Smart Host Discovery on {self.target}...")
            print(f"   [1/2] Checking ICMP (Ping)...")
            
            if not self.is_host_alive():
                print(f"   [2/2] Checking TCP Ports (Fallback)...")
                # The function already tried TCP, so if it returns False, it's likely dead
                print(f"✖ Host {self.target} appears DOWN or heavily filtered.")
                print("Note: Some firewalls block ICMP and common ports. Try scanning without --discover.")
                return # Stop execution early
                
            print(f"✓ Host is ALIVE. Proceeding to port scan...")
                
        print(f"\n🛰 Target: {self.target}")
        print(f"🗓 Range: {self.start_port} - {self.end_port}")
        print(f"ϟ Threads: {num_threads}\n")

        effective_delay = delay
        if stealth and delay == 0.0:
            effective_delay = 0.5
            
        total_ports = self.end_port - self.start_port + 1
        
        with tqdm(total=total_ports, desc="Scanning", unit="port", colour="green") as pbar:
            for port in range(self.start_port, self.end_port + 1):
                t = threading.Thread(target=self.scan_port, args=(port, effective_delay))
                self.threads.append(t)
                t.start()
                
                
                if len(self.threads) >= num_threads:
                    for thread in self.threads[:num_threads]:
                        thread.join()
                    self.threads = self.threads[num_threads:]
                
                pbar.update(1) 
            
            
            for thread in self.threads:
                thread.join()
                pbar.update(1) 

        self._print_summary()

    def _print_summary(self):
        # DEFINE COLORS HERE (each method needs its own color definitions)
        STD_GREEN = '\033[32m'           # Standard green (readable on black)
        BRIGHT_GREEN = '\033[92m\033[1m' # Bright + Bold (Success/Highlights)
        RED = '\033[91m\033[1m'          # Bright + Bold (Errors/Vulns)
        WHITE = '\033[97m'               # White (Headers)
        CYAN = '\033[96m'                # Cyan (Accents)
        RESET = '\033[0m'                # Reset
        BOLD = '\033[1m'                 # Bold modifier

        print(f"\n{STD_GREEN}============================================================{RESET}")
        print(f"{WHITE}{BOLD}SCAN REPORT SUMMARY{RESET}")
        print(f"{STD_GREEN}============================================================{RESET}")
        
        # Use STD_GREEN for labels to make them subtle
        print(f"{STD_GREEN}Target:      {self.target}{RESET}")
        print(f"{STD_GREEN}Ports Scanned: {self.end_port - self.start_port + 1}{RESET}")
        print(f"{STD_GREEN}Open Ports:  {BRIGHT_GREEN}{len(self.open_ports)}{RESET}")
        
        vulns = [r for r in self.results if r["vuln_status"] == "VULNERABLE"]
        if vulns:
            # Red header for critical findings
            print(f"\n{RED}[!] CRITICAL FINDINGS: {len(vulns)} VULNERABLE SERVICE(S) DETECTED{RESET}")
            for v in vulns:
                print(f"{WHITE}   [+] Port {v['port']}: {v['version']}{RESET}")
                print(f"{RED}       {v['vuln_details']}{RESET}")
        
        if self.open_ports:
            print(f"\n{CYAN}DETECTED SERVICES:{RESET}")
            for res in self.results:
                banner_preview = f" ({res['banner'][:30]}...)" if res['banner'] else ""
                version_note = f" [{res['version']}]" if res['version'] != "Unknown" else ""
                
                if res["vuln_status"] == "VULNERABLE":
                    print(f"   {RED}[!] Port {res['port']:5d}: {res['service']}{version_note}{banner_preview}{RESET}")
                else:
                    # Use BRIGHT_GREEN for the port list
                    print(f"   {BRIGHT_GREEN}[+] Port {res['port']:5d}: {res['service']}{version_note}{banner_preview}{RESET}")
        
        print(f"{STD_GREEN}============================================================{RESET}\n")

    def run_menu(self):
        """Interactive menu for non-technical users."""
        STD_GREEN = '\033[32m'
        BRIGHT_GREEN = '\033[92m\033[1m'
        RED = '\033[91m\033[1m'
        WHITE = '\033[97m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        while True:
            print(f"\n{STD_GREEN}============================================================{RESET}")
            print(f"{BOLD}{STD_GREEN}   STOWER v1.0.0  //  SIGNAL TOWER RECONNAISSANCE ENGINE{RESET}")
            print(f"{STD_GREEN}============================================================{RESET}")
            
            # Show current settings
            stealth_status = f"{BRIGHT_GREEN}ON{RESET}" if self.stealth_enabled else f"{RED}OFF{RESET}"
            discover_status = f"{BRIGHT_GREEN}ON{RESET}" if self.discovery_enabled else f"{RED}OFF{RESET}"
            
            print(f"{CYAN}[1]{RESET} {STD_GREEN}Quick Scan (Ports 1-1024){RESET}")
            print(f"{CYAN}[2]{RESET} {STD_GREEN}Full Scan (Ports 1-65535){RESET}")
            print(f"{CYAN}[3]{RESET} {STD_GREEN}Custom Port Range{RESET}")
            print(f"{CYAN}[4]{RESET} {STD_GREEN}Toggle Stealth Mode (Current: {stealth_status}{STD_GREEN}){RESET}")
            print(f"{CYAN}[5]{RESET} {STD_GREEN}Toggle Host Discovery (Current: {discover_status}{STD_GREEN}){RESET}")
            print(f"{CYAN}[6]{RESET} {STD_GREEN}Exit{RESET}")
            print(f"{WHITE}------------------------------------------------------------{RESET}")
            
            choice = input(f"{BRIGHT_GREEN}Enter choice [{CYAN}1-6{RESET}]: {RESET}").strip()

            if choice == '6':
                print(f"\n{RED}[!] Shutting down STower. Stay safe!{RESET}\n")
                break
            
            elif choice == '4':
                # ACTUALLY TOGGLE STEALTH MODE
                self.stealth_enabled = not self.stealth_enabled
                status = f"{BRIGHT_GREEN}ON{RESET}" if self.stealth_enabled else f"{RED}OFF{RESET}"
                print(f"\n{STD_GREEN}[+] Stealth Mode: {status}{RESET}\n")
                continue
            
            elif choice == '5':
                # ACTUALLY TOGGLE DISCOVERY MODE
                self.discovery_enabled = not self.discovery_enabled
                status = f"{BRIGHT_GREEN}ON{RESET}" if self.discovery_enabled else f"{RED}OFF{RESET}"
                print(f"\n{STD_GREEN}[+] Host Discovery: {status}{RESET}\n")
                continue

            elif choice in ['1', '2', '3']:
                # Get Target
                target = input(f"{WHITE}Enter target IP or Hostname: {RESET}").strip()
                if not target:
                    print(f"{RED}[!] Target cannot be empty.{RESET}")
                    continue

                # Determine Port Range
                if choice == '1':
                    start, end = 1, 1024
                elif choice == '2':
                    start, end = 1, 65535
                else: # Choice 3
                    port_input = input(f"{WHITE}Enter port range (e.g., 1-1000 or 80,443): {RESET}").strip()
                    try:
                        if '-' in port_input:
                            start, end = map(int, port_input.split('-'))
                        else:
                            start = end = int(port_input)
                    except ValueError:
                        print(f"{RED}[!] Invalid port range format.{RESET}")
                        continue

                # Use stored preferences (no need to ask again)
                delay = self.stealth_delay if self.stealth_enabled else 0.0

                print(f"\n{BRIGHT_GREEN}Starting scan on {target}...{RESET}")
                print(f"{STD_GREEN}Settings: Stealth={stealth_status}, Discovery={discover_status}{RESET}\n")
                
                # Create scanner with current target
                scanner = STower(target, start, end)
                # Copy preferences to new scanner
                scanner.stealth_enabled = self.stealth_enabled
                scanner.discovery_enabled = self.discovery_enabled
                scanner.stealth_delay = self.stealth_delay
                
                scanner.scan(
                    num_threads=50, 
                    discover_first=self.discovery_enabled,
                    stealth=self.stealth_enabled,
                    delay=delay
                )
                
                # Ask to continue
                cont = input(f"\n{WHITE}Press Enter to return to menu...{RESET}")

            else:
                print(f"{RED}[!] Invalid choice. Please select 1-6.{RESET}")

    def export_results(self, filename, format_type="json"):
        """NEW: Export results to JSON or CSV."""
        try:
            if format_type == "json":
                with open(filename, 'w') as f:
                    json.dump(self.results, f, indent=4)
                print(f"Results saved to: {filename}")
            elif format_type == "csv":
                with open(filename, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
                    writer.writeheader()
                    writer.writerows(self.results)
                print(f"Results saved to: {filename}")
        except Exception as e:
            print(f"Error saving file: {e}")
    
    def get_service_info(self, port):
        
        services = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL"
        }
        return services.get(port, "Unknown")

def grab_banner(self, port):
    """Extract service banner from open port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((self.target, port))
        sock.send(b'GET / HTTP/1.0\r\n\r\n')
        banner = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()
        return banner.strip()
    except:
        return None

def banner():
    """Display the STower Retro Terminal Dashboard with new Logo."""
    STD_GREEN = '\033[32m'
    BRIGHT_GREEN = '\033[92m\033[1m'
    RED = '\033[91m\033[1m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # The New Logo
    logo = f"""
{BRIGHT_GREEN}  ░▒▓███████▓▒░▒▓████████▓▒░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░  
░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓█▓▒░         ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
 ░▒▓██████▓▒░   ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓██████▓▒░ ░▒▓███████▓▒░  
       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
       ░▒▓█▓▒░  ░▒▓█▓▒░  ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░ 
░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓██████▓▒░ ░▒▓█████████████▓▒░░▒▓████████▓▒░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                      
                                                                                      {RESET}
"""
    
    print(logo)
    
    # System Boot Sequence
    print(f"{STD_GREEN}Initializing STower v1.0.0...{RESET}")
    print(f"{STD_GREEN}Loading kernel modules... OK{RESET}")
    print(f"{STD_GREEN}Establishing connection... OK{RESET}")
    print(f"{STD_GREEN}System ready.{RESET}\n")

    # Warning Block
    print(f"{RED}[!] LEGAL NOTICE: {RESET}")
    print(f"{STD_GREEN}   This tool is meant for authorized security testing. {RESET}")
    print(f"{STD_GREEN}   Unauthorized scanning may be considered a violation of federal law.{RESET}")
    print()

    # Separator
    print(f"{STD_GREEN}─" * 60 + "{RESET}")
    print(f"{STD_GREEN}Ready for target input. Type 'help' for commands.{RESET}")
    print(f"{STD_GREEN}─" * 60 + "{RESET}\n")



def main():
    banner()
    
    # Check if arguments were provided
    if len(sys.argv) > 1:
        # --- COMMAND LINE MODE ---
        parser = argparse.ArgumentParser(prog="STower", description="STower: High-performance network reconnaissance.")
        
        parser.add_argument("-t", "--target", required=True, help="Target IP or Hostname")
        parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024)")
        parser.add_argument("-T", "--threads", type=int, default=50, help="Thread count")
        parser.add_argument("--discover", action="store_true", help="Check if host is alive first")
        parser.add_argument("--stealth", action="store_true", help="Enable stealth mode")
        parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between scans")
        
        args = parser.parse_args()
        
        # Parse ports
        try:
            if "-" in args.ports:
                start, end = map(int, args.ports.split("-"))
            else:
                start = end = int(args.ports)
        except ValueError:
            print("✖ Invalid port range format."); sys.exit(1)
            
        if start < 1 or end > 65535:
            print("✖ Ports must be 1-65535"); sys.exit(1)
            
        scanner = STower(args.target, start, end)
        scanner.scan(
            num_threads=args.threads, 
            discover_first=args.discover,
            stealth=args.stealth,
            delay=args.delay
        )
        
    else:
        # --- INTERACTIVE MENU MODE ---
        # Create a dummy scanner just to access the menu method
        # (We don't actually scan anything here, just show the menu)
        dummy_scanner = STower("127.0.0.1", 1, 1024)
        dummy_scanner.run_menu()

if __name__ == "__main__":
    main()
