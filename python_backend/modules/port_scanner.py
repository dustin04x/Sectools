"""
Port Scanner Module
Fast multi-threaded TCP port scanner with service detection
"""

import socket
import threading
import time
from typing import List, Dict, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


class PortScanner:
    """TCP Port Scanner with service detection"""
    
    # Common ports and their services
    COMMON_PORTS = {
        20: "FTP-DATA",
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        115: "SFTP",
        119: "NNTP",
        123: "NTP",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        161: "SNMP",
        194: "IRC",
        389: "LDAP",
        443: "HTTPS",
        445: "SMB",
        465: "SMTPS",
        514: "Syslog",
        587: "SMTP-Submission",
        636: "LDAPS",
        873: "RSYNC",
        902: "VMware",
        989: "FTPS-DATA",
        990: "FTPS",
        993: "IMAPS",
        995: "POP3S",
        1080: "SOCKS",
        1194: "OpenVPN",
        1433: "MSSQL",
        1521: "Oracle",
        1723: "PPTP",
        2049: "NFS",
        2082: "cPanel",
        2083: "cPanel-SSL",
        2222: "DirectAdmin",
        2375: "Docker",
        2376: "Docker-SSL",
        3000: "Grafana/Node",
        3306: "MySQL",
        3389: "RDP",
        4444: "Metasploit",
        4786: "SmartInstall",
        5000: "UPnP/Flask",
        5432: "PostgreSQL",
        5555: "Android-ADB",
        5632: "PCAnywhere",
        5900: "VNC",
        5984: "CouchDB",
        5985: "WinRM-HTTP",
        5986: "WinRM-HTTPS",
        6379: "Redis",
        6443: "Kubernetes",
        6667: "IRC",
        7001: "WebLogic",
        8000: "HTTP-Alt",
        8008: "HTTP",
        8080: "HTTP-Proxy",
        8086: "InfluxDB",
        8443: "HTTPS-Alt",
        8888: "Jupyter",
        9000: "SonarQube",
        9042: "Cassandra",
        9092: "Kafka",
        9200: "Elasticsearch",
        9300: "Elasticsearch-Node",
        9418: "Git",
        9999: "RemoteAdmin",
        10000: "Webmin",
        11211: "Memcached",
        27017: "MongoDB",
        27018: "MongoDB-Shard",
        50000: "SAP",
    }
    
    def __init__(self):
        self.results = []
        self.lock = threading.Lock()
        self.resolved_ip = None
        self.target = None
    
    def resolve_target(self, target: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            return None
    
    def grab_banner(self, sock: socket.socket, port: int) -> Optional[str]:
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2)
            # Send different probes based on port
            if port in [80, 443, 8080, 8000, 8443]:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner on connect
            elif port == 22:
                pass  # SSH sends banner on connect
            else:
                sock.send(b"\r\n")
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else None
        except:
            return None
    
    def scan_port(self, port: int, timeout: float) -> Optional[Dict[str, Any]]:
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.resolved_ip, port))
            
            if result == 0:
                service = self.COMMON_PORTS.get(port, "Unknown")
                banner = self.grab_banner(sock, port)
                sock.close()
                return {
                    "port": port,
                    "status": "open",
                    "service": service,
                    "banner": banner
                }
            sock.close()
        except Exception as e:
            pass
        return None
    
    def scan(self, target: str, start_port: int = 1, end_port: int = 1000,
             threads: int = 100, timeout: float = 1.0) -> Dict[str, Any]:
        """
        Perform TCP port scan
        
        Args:
            target: IP address or hostname
            start_port: Starting port number
            end_port: Ending port number
            threads: Number of concurrent threads
            timeout: Connection timeout in seconds
        
        Returns:
            Dictionary with scan results
        """
        self.target = target
        self.resolved_ip = self.resolve_target(target)
        
        if not self.resolved_ip:
            raise ValueError(f"Could not resolve target: {target}")
        
        start_time = time.time()
        open_ports = []
        
        # Use ThreadPoolExecutor for better performance
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port, port, timeout): port 
                for port in range(start_port, end_port + 1)
            }
            
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    open_ports.append(result)
        
        elapsed_time = time.time() - start_time
        
        # Sort results by port number
        open_ports.sort(key=lambda x: x["port"])
        
        return {
            "target": target,
            "resolved_ip": self.resolved_ip,
            "scan_time": datetime.now().isoformat(),
            "total_scanned": end_port - start_port + 1,
            "open_ports": open_ports,
            "elapsed_time": round(elapsed_time, 2)
        }
    
    def get_common_ports(self) -> Dict[int, str]:
        """Return common ports mapping"""
        return self.COMMON_PORTS


if __name__ == "__main__":
    # Test the scanner
    scanner = PortScanner()
    result = scanner.scan("127.0.0.1", 1, 1000, threads=100)
    print(f"Found {len(result['open_ports'])} open ports")
    for port in result['open_ports']:
        print(f"  Port {port['port']}: {port['service']}")
