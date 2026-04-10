#!/usr/bin/env python3
"""
Port Scanner - A cybersecurity educational tool
Author: Alvalek
Description: Scans target IP addresses for open ports using TCP connections
"""

import socket
import threading
from datetime import datetime
import argparse
import sys

class PortScanner:
    def __init__(self, target, start_port=1, end_port=1024):
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.open_ports = []
        self.threads = []
        
    def scan_port(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                print(f"[+] Port {port}: OPEN")
                self.open_ports.append(port)
            else:
                print(f"[-] Port {port}: CLOSED")
                
            sock.close()
            
        except socket.error as e:
            print(f"[*] Port {port}: ERROR - {e}")
            
        except Exception as e:
            print(f"[*] Port {port}: UNEXPECTED ERROR - {e}")
    
    def scan(self, num_threads=50):
        
        print(f"\n{'='*60}")
        print(f"Starting Port Scan on {self.target}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Port Range: {self.start_port} - {self.end_port}")
        print(f"Threads: {num_threads}")
        print(f"{'='*60}\n")
        
       
        for port in range(self.start_port, self.end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            self.threads.append(t)
            t.start()
            
            
            if len(self.threads) >= num_threads:
                for thread in self.threads[:num_threads]:
                    thread.join()
                self.threads = self.threads[num_threads:]
        
        
        for thread in self.threads:
            thread.join()
            
        print(f"\n{'='*60}")
        print(f"Scan Complete!")
        print(f"Open Ports Found: {len(self.open_ports)}")
        if self.open_ports:
            print(f"Ports: {self.open_ports}")
        print(f"{'='*60}\n")
    
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
    """Display program banner."""
    print("""
    ╔═══════════════════════════════════════════╗
    ║         PORT SCANNER - CYBERSECURITY      ║
    ║              EDUCATIONAL TOOL             ║
    ╚═══════════════════════════════════════════╝
    """)


def main():
    """Main entry point with argument parsing."""
    banner()
    
    parser = argparse.ArgumentParser(
        description="Port Scanner for cybersecurity education",
        epilog="Example: python port_scanner.py -t 192.168.1.1 -p 1-1000"
    )
    parser.add_argument("-t", "--target", required=True, 
                       help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024",
                       help="Port range (e.g., 1-1024, 80,443,8080)")
    parser.add_argument("-T", "--threads", type=int, default=50,
                       help="Number of concurrent threads (default: 50)")
    
    args = parser.parse_args()
    
    # Parse port range
    try:
        if "-" in args.ports:
            start, end = map(int, args.ports.split("-"))
        else:
            start = end = int(args.ports)
    except ValueError:
        print("Error: Invalid port range format")
        sys.exit(1)
    
    # Validate inputs
    if start < 1 or end > 65535:
        print("Error: Ports must be between 1 and 65535")
        sys.exit(1)
    
    if start > end:
        print("Error: Start port must be less than end port")
        sys.exit(1)
    
    # Create and run scanner
    scanner = PortScanner(args.target, start, end)
    scanner.scan(num_threads=args.threads)
    
    return scanner.open_ports


if __name__ == "__main__":
    main()
