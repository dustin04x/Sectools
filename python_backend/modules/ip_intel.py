"""
IP Intelligence Module
Geolocation, reverse DNS, and WHOIS lookups
"""

import socket
import dns.resolver
import dns.reversename
from typing import Dict, Any, Optional, List
import ipaddress
import whois as python_whois


class IPIntel:
    """IP intelligence and reconnaissance"""
    
    def __init__(self):
        # Placeholder for MaxMind GeoLite2 database
        # In production, this would load the MMDB file
        self.geo_db_loaded = False
    
    def is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def geolocation(self, ip: str) -> Dict[str, Any]:
        """
        Get IP geolocation data
        Note: This is a placeholder. In production, use MaxMind GeoLite2
        """
        if not self.is_valid_ip(ip):
            # Try to resolve hostname
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                raise ValueError(f"Invalid IP address or hostname: {ip}")
        
        # Check for private/local addresses
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.is_private:
            return {
                "ip": ip,
                "is_private": True,
                "country": "Private Network",
                "city": "N/A",
                "region": "N/A",
                "latitude": None,
                "longitude": None,
                "timezone": "N/A",
                "isp": "Private Network",
                "organization": "N/A",
                "note": "This is a private/RFC1918 address"
            }
        
        # Placeholder response - would query GeoLite2 database
        return {
            "ip": ip,
            "is_private": False,
            "country": "US",
            "country_name": "United States",
            "city": "San Francisco",
            "region": "California",
            "latitude": 37.7749,
            "longitude": -122.4194,
            "timezone": "America/Los_Angeles",
            "isp": "Example ISP",
            "organization": "Example Organization",
            "asn": "AS12345",
            "note": "Using placeholder data - install GeoLite2 for real data"
        }
    
    def reverse_dns(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup"""
        if not self.is_valid_ip(ip):
            try:
                ip = socket.gethostbyname(ip)
            except socket.gaierror:
                raise ValueError(f"Invalid IP address or hostname: {ip}")
        
        try:
            # Using socket for reverse DNS
            hostname = socket.gethostbyaddr(ip)[0]
            return {
                "ip": ip,
                "hostname": hostname,
                "success": True
            }
        except socket.herror:
            return {
                "ip": ip,
                "hostname": None,
                "success": False,
                "error": "No PTR record found"
            }
    
    def whois(self, target: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup
        """
        try:
            is_ip = self.is_valid_ip(target)
            if is_ip:
                return {
                    "query": target,
                    "is_ip": True,
                    "note": "IP WHOIS is not supported in this module yet. Use a domain for full WHOIS fields."
                }

            data = python_whois.whois(target)

            def pick_first(value: Any) -> Optional[str]:
                if value is None:
                    return None
                if isinstance(value, list):
                    if not value:
                        return None
                    return str(value[0])
                return str(value)

            def ensure_list(value: Any) -> Optional[List[str]]:
                if value is None:
                    return None
                if isinstance(value, list):
                    return [str(v) for v in value if v is not None]
                return [str(value)]

            return {
                "query": target,
                "is_ip": False,
                "registrar": pick_first(getattr(data, "registrar", None)),
                "creation_date": pick_first(getattr(data, "creation_date", None)),
                "expiration_date": pick_first(getattr(data, "expiration_date", None)),
                "updated_date": pick_first(getattr(data, "updated_date", None)),
                "name_servers": ensure_list(getattr(data, "name_servers", None)),
                "status": ensure_list(getattr(data, "status", None)),
                "admin_email": pick_first(getattr(data, "emails", None)),
                "tech_email": pick_first(getattr(data, "emails", None)),
                "org": pick_first(getattr(data, "org", None)),
                "country": pick_first(getattr(data, "country", None)),
            }
        except Exception as e:
            raise ValueError(f"WHOIS lookup failed: {str(e)}")
    
    def dns_lookup(self, domain: str, record_type: str = "A") -> Dict[str, Any]:
        """Perform DNS lookup"""
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records = [str(rdata) for rdata in answers]
            return {
                "domain": domain,
                "record_type": record_type,
                "records": records,
                "ttl": answers.rrset.ttl if answers.rrset else None
            }
        except dns.resolver.NXDOMAIN:
            return {
                "domain": domain,
                "record_type": record_type,
                "error": "Domain does not exist"
            }
        except dns.resolver.NoAnswer:
            return {
                "domain": domain,
                "record_type": record_type,
                "error": f"No {record_type} records found"
            }
        except Exception as e:
            return {
                "domain": domain,
                "record_type": record_type,
                "error": str(e)
            }

    def subnet_info(self, cidr: str) -> Dict[str, Any]:
        """Calculate subnet details from CIDR notation."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = []
            if network.num_addresses <= 4096:
                hosts = [str(h) for h in network.hosts()]

            return {
                "cidr": str(network),
                "version": network.version,
                "network_address": str(network.network_address),
                "broadcast_address": str(network.broadcast_address) if network.version == 4 else None,
                "netmask": str(network.netmask),
                "hostmask": str(network.hostmask),
                "total_ips": network.num_addresses,
                "usable_hosts": max(network.num_addresses - 2, 0) if network.version == 4 else network.num_addresses,
                "first_host": str(next(network.hosts(), network.network_address)),
                "last_host": str(list(network.hosts())[-1]) if network.num_addresses <= 4096 and hosts else None,
                "is_private": network.is_private,
                "sample_hosts": hosts[:50],
            }
        except Exception as e:
            raise ValueError(f"Invalid CIDR/network: {str(e)}")


if __name__ == "__main__":
    intel = IPIntel()
    
    # Test geolocation
    geo = intel.geolocation("8.8.8.8")
    print(f"Geolocation: {geo}")
    
    # Test reverse DNS
    rdns = intel.reverse_dns("8.8.8.8")
    print(f"Reverse DNS: {rdns}")
    
    # Test WHOIS
    whois = intel.whois("google.com")
    print(f"WHOIS: {whois}")
