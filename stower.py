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
        DIM_GREEN = '\033[90m\033[2m'      # Dim, faint green for system logs
        BRIGHT_GREEN = '\033[92m\033[1m'   # Bright, bold green for success/open
        RED = '\033[91m\033[1m'            # Bright red for errors/vulns
        WHITE = '\033[97m'                 # White for headers
        CYAN = '\033[96m'                  # Cyan for accents (optional)
        RESET = '\033[0m'                  # Reset to default
        
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
                
                # Determine Status Symbol and Color
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
                
                # Print Vulnerability Details if found
                if version_info["vuln_status"] == "VULNERABLE":
                    print(f"    [-] ALERT: {version_info['details']}")
                
                else:
                    pass
                
            sock.close()
            
        except socket.error:
            pass
        except Exception:
            pass
            
        # Stealth Delay (must be outside try/except to ensure it runs)
        if delay > 0:
            actual_delay = delay + random.uniform(0, delay * 0.2)
            time.sleep(actual_delay)
    
    def scan(self, num_threads=50, discover_first=True, stealth=False, delay=0.0):
        """Scan with progress bar and threading."""
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
        
        with tqdm(total=total_ports, desc="Scanning", unit="port", colour="white") as pbar:
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
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

        print(f"\n{WHITE}============================================================{RESET}")
        print(f"{WHITE}{BOLD}SCAN REPORT SUMMARY{RESET}")
        print(f"{WHITE}============================================================{RESET}")
        
        # Use DIM_GREEN for labels to make them subtle
        print(f"{DIM_GREEN}Target:      {self.target}{RESET}")
        print(f"{DIM_GREEN}Ports Scanned: {self.end_port - self.start_port + 1}{RESET}")
        print(f"{DIM_GREEN}Open Ports:  {BRIGHT_GREEN}{len(self.open_ports)}{RESET}")
        
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
        
        print(f"{WHITE}============================================================{RESET}\n")

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
    """Display the STower Retro Terminal Dashboard."""
    DIM_GREEN = '\033[90m\033[2m'      
    BRIGHT_GREEN = '\033[92m\033[1m'  
    RED = '\033[91m\033[1m'            
    WHITE = '\033[97m'              
    RESET = '\033[0m'
    BOLD = '\033[1m'

    # System Boot Sequence (Dim Green)
    print(f"{DIM_GREEN}Initializing STower v1.0.0...{RESET}")
    print(f"{DIM_GREEN}Loading kernel modules... OK{RESET}")
    print(f"{DIM_GREEN}Establishing connection... OK{RESET}")
    print(f"{DIM_GREEN}System ready.{RESET}\n")

    # Main Title (Bright Green)
    print(f"{BRIGHT_GREEN}╔════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BRIGHT_GREEN}║  STOWER v1.0.0  //  SIGNAL TOWER RECONNAISSANCE ENGINE       ║{RESET}")
    print(f"{BRIGHT_GREEN}╚════════════════════════════════════════════════════════════════╝{RESET}")
    print()

    # System Status (White labels, Green/Dim values)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{WHITE}[SYSTEM] Initializing core modules... {BRIGHT_GREEN}OK{RESET}")
    print(f"{WHITE}[SYSTEM] Loading port database... {BRIGHT_GREEN}OK{RESET}")
    print(f"{WHITE}[SYSTEM] Thread pool initialized: {DIM_GREEN}Dynamic{RESET}")
    print(f"{WHITE}[INFO]  Timestamp: {DIM_GREEN}{timestamp}{RESET}")
    print()

    # Warning Block (Red for urgency)
    print(f"{RED}[!] LEGAL NOTICE: {RESET}")
    print(f"{WHITE}   This tool is meant for authorized security testing. {RESET}")
    print(f"{WHITE}   Unauthorized scanning may be considered a violation of federal law.{RESET}")
    print()

    # Separator (Dim Green)
    print(f"{DIM_GREEN}─" * 60 + "{RESET}")
    print(f"{WHITE}Ready for target input. Type 'help' for commands.{RESET}")
    print(f"{DIM_GREEN}─" * 60 + "{RESET}\n")



def main():
    banner()
    
    parser = argparse.ArgumentParser(prog="STower", description="STower: High-performance network reconnaissance.")
    parser.add_argument("-t", "--target", required=True, help="Target IP or Hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024)")
    parser.add_argument("-T", "--threads", type=int, default=50, help="Thread count")
    parser.add_argument("-o", "--output", help="Output file (e.g., results.json)")
    parser.add_argument("-f", "--format", choices=["json", "csv"], default="json", help="Output format")
    parser.add_argument("--discover", action="store_true", 
                       help="Check if host is alive (ping) before scanning ports")
    parser.add_argument("--stealth", action="store_true", 
                       help="Enable stealth mode with random delays to avoid IDS detection")
    parser.add_argument("--delay", type=float, default=0.0, 
                       help="Delay in seconds between port scans (default: 0 for aggressive)")
    
    args = parser.parse_args()
    
    try:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
        else:
            start = end = int(args.ports)
    except ValueError:
        print("✖ Invalid port range."); sys.exit(1)
        
    if start < 1 or end > 65535:
        print("✖ Ports must be 1-65535"); sys.exit(1)
        
    scanner = STower(args.target, start, end)
    scanner.scan(
        num_threads=args.threads, 
        discover_first=args.discover,
        stealth=args.stealth,
        delay=args.delay
    )
    
    if args.output:
        scanner.export_results(args.output, args.format)

if __name__ == "__main__":
    main()
