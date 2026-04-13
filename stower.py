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
        
    def scan_port(self, port):
        """Scan a single port with enhanced logging."""
        GREEN = '\033[92m'
        RED = '\033[91m'
        YELLOW = '\033[93m'
        RESET = '\033[0m'
        
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
                        if "Apache" in banner: service_name = "Apache"
                        elif "nginx" in banner: service_name = "nginx"
                        elif "Microsoft-IIS" in banner: service_name = "IIS"
                        elif "SSH" in banner: service_name = "SSH"
                        elif "FTP" in banner: service_name = "FTP"
                        else: service_name = "HTTP" 
                except:
                    pass
                
                self.open_ports.append(port)
                self.results.append({
                    "port": port,
                    "state": "OPEN",
                    "service": service_name,
                    "banner": banner
                })
                
                
                banner_str = f" | BANNER: {banner[:40]}..." if banner else ""
                print(f"{GREEN}[+] {port:5d} | OPEN  | {service_name:10s}{banner_str}{RESET}")
                
            else:
               
                pass
                
            sock.close()
            
        except socket.error:
            pass
        except Exception:
            pass
    
    def scan(self, num_threads=50, discover_first=True):
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
        
        total_ports = self.end_port - self.start_port + 1
        
        with tqdm(total=total_ports, desc="Scanning", unit="port", colour="green") as pbar:
            for port in range(self.start_port, self.end_port + 1):
                t = threading.Thread(target=self.scan_port, args=(port,))
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

        print(f"\n{BLUE}════════════════════════════════════════════════════════════════{RESET}")
        print(f"{BOLD}{WHITE}SCAN REPORT SUMMARY{RESET}")
        print(f"{BLUE}════════════════════════════════════════════════════════════════{RESET}")
        print(f"{WHITE}Target:      {self.target}{RESET}")
        print(f"{WHITE}Ports Scanned: {self.end_port - self.start_port + 1}{RESET}")
        print(f"{WHITE}Open Ports:  {GREEN}{len(self.open_ports)}{RESET}")
        
        if self.open_ports:
            print(f"\n{YELLOW}DETECTED SERVICES:{RESET}")
            for res in self.results:
                banner_preview = f" ({res['banner'][:30]}...)" if res['banner'] else ""
                print(f"   • Port {res['port']:5d}: {res['service']}{banner_preview}")
        
        print(f"{BLUE}════════════════════════════════════════════════════════════════{RESET}\n")

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
    """Display the STower Terminal Dashboard."""
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

    print(f"{BLUE}{BOLD}╔════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BLUE}{BOLD}║  STOWER v1.0.0  //  SIGNAL TOWER RECONNAISSANCE ENGINE       ║{RESET}")
    print(f"{BLUE}{BOLD}╚════════════════════════════════════════════════════════════════╝{RESET}")
    print()
    
    # System Status Block
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{WHITE}[SYSTEM] Initializing core modules... {GREEN}OK{RESET}")
    print(f"{WHITE}[SYSTEM] Loading port database... {GREEN}OK{RESET}")
    print(f"{WHITE}[SYSTEM] Thread pool initialized: {YELLOW}Dynamic{RESET}")
    print(f"{WHITE}[INFO]  Timestamp: {timestamp}{RESET}")
    print()
    
    # Warning Block
    print(f"{RED}⚠  LEGAL NOTICE: {RESET}")
    print(f"{WHITE}   This tool is meant for authorized security testing. {RESET}")
    print(f"{WHITE}   Unauthorized scanning can be a violation of federal law.{RESET}")
    print()
    
    # Separator
    print(f"{BLUE}─" * 60 + "{RESET}")
    print(f"{WHITE}Ready for target input. Type 'help' for commands.{RESET}")
    print(f"{BLUE}─" * 60 + "{RESET}\n")



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
    scanner.scan(num_threads=args.threads, discover_first=args.discover)
    
    if args.output:
        scanner.export_results(args.output, args.format)

if __name__ == "__main__":
    main()
