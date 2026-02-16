"""
SecTools Python Backend - FastAPI Server
Local HTTP server for security tool operations
"""

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import socket
import threading
from datetime import datetime
import json

from modules.port_scanner import PortScanner
from modules.crypto_tools import CryptoTools
from modules.ip_intel import IPIntel
from modules.rev_shell import RevShellGenerator
from modules.web_tools import WebTools

app = FastAPI(
    title="SecTools Backend",
    description="Security toolkit backend API",
    version="1.0.0"
)

# CORS - restricted to localhost only
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:1420", "tauri://localhost"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request/Response Models
class PortScanRequest(BaseModel):
    target: str = Field(..., description="Target IP or hostname")
    start_port: int = Field(default=1, ge=1, le=65535)
    end_port: int = Field(default=1000, ge=1, le=65535)
    threads: int = Field(default=100, ge=1, le=500)
    timeout: float = Field(default=1.0, ge=0.1, le=10.0)

class PortScanResult(BaseModel):
    port: int
    status: str
    service: Optional[str] = None
    banner: Optional[str] = None

class PortScanResponse(BaseModel):
    target: str
    resolved_ip: Optional[str]
    scan_time: str
    total_scanned: int
    open_ports: List[PortScanResult]
    elapsed_time: float

class CryptoRequest(BaseModel):
    operation: str
    algorithm: str
    data: str
    key: Optional[str] = None

class PasswordGenerateRequest(BaseModel):
    length: int = Field(default=16, ge=4, le=256)
    uppercase: bool = True
    lowercase: bool = True
    digits: bool = True
    special: bool = True

class HmacRequest(BaseModel):
    algorithm: str
    data: str
    key: str

class JwtDecodeRequest(BaseModel):
    token: str

class RsaKeypairRequest(BaseModel):
    key_size: int = Field(default=2048, ge=2048, le=4096)

class IPIntelRequest(BaseModel):
    ip: str

class DNSLookupRequest(BaseModel):
    domain: str
    record_type: str = Field(default="A")

class SubnetRequest(BaseModel):
    cidr: str

class IOCExtractRequest(BaseModel):
    text: str

class SecurityHeadersRequest(BaseModel):
    url: str
    timeout: float = Field(default=10.0, ge=1.0, le=30.0)

class JwtInspectRequest(BaseModel):
    token: str

class SecretScanRequest(BaseModel):
    text: str

class TLSAnalyzeRequest(BaseModel):
    target: str
    port: int = Field(default=443, ge=1, le=65535)
    timeout: float = Field(default=8.0, ge=1.0, le=30.0)

class RevShellRequest(BaseModel):
    language: str
    platform: str
    attacker_ip: str
    attacker_port: int = Field(..., ge=1, le=65535)
    encode: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str

# Initialize modules
port_scanner = PortScanner()
crypto_tools = CryptoTools()
ip_intel = IPIntel()
rev_shell = RevShellGenerator()
web_tools = WebTools()

@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        version="1.0.0"
    )

@app.post("/api/portscan", response_model=PortScanResponse)
async def scan_ports(request: PortScanRequest):
    """Scan ports on target host"""
    try:
        result = port_scanner.scan(
            target=request.target,
            start_port=request.start_port,
            end_port=request.end_port,
            threads=request.threads,
            timeout=request.timeout
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/encrypt")
async def encrypt(request: CryptoRequest):
    """Encrypt data"""
    try:
        result = crypto_tools.encrypt(
            algorithm=request.algorithm,
            data=request.data,
            key=request.key
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/decrypt")
async def decrypt(request: CryptoRequest):
    """Decrypt data"""
    try:
        result = crypto_tools.decrypt(
            algorithm=request.algorithm,
            data=request.data,
            key=request.key
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/hash")
async def hash_data(request: CryptoRequest):
    """Hash data"""
    try:
        result = crypto_tools.hash(
            algorithm=request.algorithm,
            data=request.data
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/password/generate")
async def generate_password(request: PasswordGenerateRequest):
    """Generate secure password"""
    try:
        return crypto_tools.generate_password(
            length=request.length,
            uppercase=request.uppercase,
            lowercase=request.lowercase,
            digits=request.digits,
            special=request.special
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/hmac")
async def generate_hmac(request: HmacRequest):
    """Generate HMAC signature"""
    try:
        result = crypto_tools.hmac_sign(
            algorithm=request.algorithm,
            data=request.data,
            key=request.key
        )
        return {"result": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/jwt/decode")
async def decode_jwt(request: JwtDecodeRequest):
    """Decode JWT without signature verification"""
    try:
        return crypto_tools.jwt_decode(request.token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/crypto/rsa/generate")
async def generate_rsa_keypair(request: RsaKeypairRequest):
    """Generate RSA keypair"""
    try:
        return crypto_tools.generate_rsa_keypair(request.key_size)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ipintel/geolocation")
async def ip_geolocation(request: IPIntelRequest):
    """Get IP geolocation"""
    try:
        result = ip_intel.geolocation(request.ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ipintel/reversedns")
async def reverse_dns(request: IPIntelRequest):
    """Reverse DNS lookup"""
    try:
        result = ip_intel.reverse_dns(request.ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ipintel/whois")
async def whois_lookup(request: IPIntelRequest):
    """WHOIS lookup"""
    try:
        result = ip_intel.whois(request.ip)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ipintel/dns")
async def dns_lookup(request: DNSLookupRequest):
    """DNS record lookup"""
    try:
        result = ip_intel.dns_lookup(
            domain=request.domain,
            record_type=request.record_type
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/ipintel/subnet")
async def subnet_calculator(request: SubnetRequest):
    """Subnet calculator"""
    try:
        result = ip_intel.subnet_info(request.cidr)
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/webtools/ioc-extract")
async def ioc_extract(request: IOCExtractRequest):
    """Extract IOCs from free-form text"""
    try:
        return web_tools.extract_iocs(request.text)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/webtools/security-headers")
async def security_headers_audit(request: SecurityHeadersRequest):
    """Audit HTTP security headers for a target URL"""
    try:
        return web_tools.audit_security_headers(
            target_url=request.url,
            timeout=request.timeout
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/webtools/jwt-inspect")
async def jwt_inspect(request: JwtInspectRequest):
    """Inspect JWT contents and common security pitfalls"""
    try:
        return web_tools.inspect_jwt(request.token)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/webtools/secret-scan")
async def secret_scan(request: SecretScanRequest):
    """Scan text for likely leaked credentials/secrets"""
    try:
        return web_tools.scan_secrets(request.text)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/webtools/tls-analyze")
async def tls_analyze(request: TLSAnalyzeRequest):
    """Analyze TLS certificate and negotiated security settings"""
    try:
        return web_tools.analyze_tls(
            target=request.target,
            port=request.port,
            timeout=request.timeout
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/revshell/generate")
async def generate_shell(request: RevShellRequest):
    """Generate reverse shell payload"""
    try:
        result = rev_shell.generate(
            language=request.language,
            platform=request.platform,
            attacker_ip=request.attacker_ip,
            attacker_port=request.attacker_port,
            encode=request.encode
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/services/common-ports")
async def common_ports():
    """Get common ports mapping"""
    return port_scanner.get_common_ports()

@app.get("/api/system/local-ip")
async def get_local_ip():
    """Get local network IP candidates"""
    ips = set()
    try:
      hostname = socket.gethostname()
      for info in socket.getaddrinfo(hostname, None):
          ip = info[4][0]
          if "." in ip and not ip.startswith("127."):
              ips.add(ip)
    except Exception:
      pass

    # UDP trick to infer preferred outbound local IP.
    try:
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect(("8.8.8.8", 80))
      ips.add(s.getsockname()[0])
      s.close()
    except Exception:
      pass

    if not ips:
      ips.add("127.0.0.1")

    return {"ips": sorted(list(ips))}

if __name__ == "__main__":
    # Find available port
    # Use fixed port 8000 for development compatibility
    port = 8000
    
    # Write port to file for Tauri to read
    with open('.python_port', 'w') as f:
        f.write(str(port))
    
    print(f"Starting SecTools backend on port {port}")
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
