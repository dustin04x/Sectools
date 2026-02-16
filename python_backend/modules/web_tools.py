"""
Web utility tools module.
Includes IOC extraction, HTTP security header auditing,
JWT inspection, secret scanning, and TLS certificate analysis.
"""

import base64
import json
import re
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List
from urllib.parse import urlparse

import requests
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class WebTools:
    """Web-focused utility operations."""

    IOC_PATTERNS = {
        "ips": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        "urls": re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE),
        "emails": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "domains": re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b"),
        "md5": re.compile(r"\b[a-fA-F0-9]{32}\b"),
        "sha1": re.compile(r"\b[a-fA-F0-9]{40}\b"),
        "sha256": re.compile(r"\b[a-fA-F0-9]{64}\b"),
        "sha512": re.compile(r"\b[a-fA-F0-9]{128}\b"),
        "cves": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    }

    SECRET_PATTERNS = [
        {
            "name": "aws_access_key_id",
            "severity": "high",
            "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        },
        {
            "name": "aws_secret_access_key_like",
            "severity": "high",
            "pattern": re.compile(r"\b[0-9a-zA-Z/+]{40}\b"),
        },
        {
            "name": "github_personal_access_token",
            "severity": "high",
            "pattern": re.compile(r"\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b"),
        },
        {
            "name": "slack_token",
            "severity": "high",
            "pattern": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        },
        {
            "name": "stripe_live_secret_key",
            "severity": "critical",
            "pattern": re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b"),
        },
        {
            "name": "private_key_block",
            "severity": "critical",
            "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        },
        {
            "name": "jwt_token_like",
            "severity": "medium",
            "pattern": re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        },
    ]

    def extract_iocs(self, text: str) -> Dict[str, Any]:
        """Extract indicators of compromise from free-form text."""
        results: Dict[str, List[str]] = {}
        for key, pattern in self.IOC_PATTERNS.items():
            matches = pattern.findall(text or "")
            normalized = sorted(set(m.lower() if key == "cves" else m for m in matches))
            results[key] = normalized

        total = sum(len(v) for v in results.values())
        return {
            "total_iocs": total,
            "counts": {k: len(v) for k, v in results.items()},
            "results": results,
        }

    def audit_security_headers(self, target_url: str, timeout: float = 10.0) -> Dict[str, Any]:
        """Audit key HTTP security headers for a given URL."""
        if not target_url:
            raise ValueError("URL is required.")

        url = self._normalize_url(target_url)
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        raw_headers = {k.lower(): v for k, v in response.headers.items()}
        set_cookie_headers = response.headers.get("set-cookie", "")
        set_cookie = [h.strip() for h in set_cookie_headers.split(",") if h.strip()] if set_cookie_headers else []

        checks = [
            self._check_presence(raw_headers, "content-security-policy", "Content-Security-Policy"),
            self._check_presence(raw_headers, "strict-transport-security", "Strict-Transport-Security", https_only=True, url=response.url),
            self._check_presence(raw_headers, "x-frame-options", "X-Frame-Options"),
            self._check_exact(raw_headers, "x-content-type-options", "nosniff", "X-Content-Type-Options"),
            self._check_presence(raw_headers, "referrer-policy", "Referrer-Policy"),
            self._check_presence(raw_headers, "permissions-policy", "Permissions-Policy"),
            self._check_presence(raw_headers, "cross-origin-opener-policy", "Cross-Origin-Opener-Policy"),
            self._check_presence(raw_headers, "cross-origin-resource-policy", "Cross-Origin-Resource-Policy"),
            self._check_cookie_flags(set_cookie),
            self._check_cors(raw_headers),
            self._check_server_disclosure(raw_headers),
        ]

        score = 100
        findings = []
        for check in checks:
            findings.append(check)
            if check["severity"] == "high":
                score -= 15
            elif check["severity"] == "medium":
                score -= 8
            elif check["severity"] == "low":
                score -= 3

        score = max(score, 0)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"

        return {
            "target": target_url,
            "final_url": response.url,
            "status_code": response.status_code,
            "score": score,
            "grade": grade,
            "headers": raw_headers,
            "findings": findings,
        }

    def inspect_jwt(self, token: str) -> Dict[str, Any]:
        """Inspect JWT structure and common security pitfalls without signature verification."""
        if not token or token.count(".") != 2:
            raise ValueError("Token must be a JWT with 3 dot-separated segments.")

        header_segment, payload_segment, signature_segment = token.split(".")

        header = self._jwt_decode_segment(header_segment)
        payload = self._jwt_decode_segment(payload_segment)

        findings: List[Dict[str, Any]] = []
        now_ts = int(time.time())

        alg = str(header.get("alg", "")).lower()
        if alg == "none":
            findings.append({
                "name": "Algorithm",
                "severity": "critical",
                "ok": False,
                "message": "JWT uses alg=none (unsigned token).",
            })
        elif alg.startswith("hs"):
            findings.append({
                "name": "Algorithm",
                "severity": "medium",
                "ok": True,
                "message": f"Symmetric algorithm detected: {header.get('alg')}.",
            })
        elif alg:
            findings.append({
                "name": "Algorithm",
                "severity": "info",
                "ok": True,
                "message": f"Algorithm: {header.get('alg')}.",
            })
        else:
            findings.append({
                "name": "Algorithm",
                "severity": "high",
                "ok": False,
                "message": "Missing alg in JWT header.",
            })

        exp = self._safe_int(payload.get("exp"))
        nbf = self._safe_int(payload.get("nbf"))
        iat = self._safe_int(payload.get("iat"))

        if exp is not None:
            findings.append({
                "name": "Expiration",
                "severity": "high" if exp < now_ts else "info",
                "ok": exp >= now_ts,
                "message": "Token is expired." if exp < now_ts else "Token is not expired.",
                "value": exp,
            })
        else:
            findings.append({
                "name": "Expiration",
                "severity": "medium",
                "ok": False,
                "message": "exp claim is missing.",
            })

        if nbf is not None and nbf > now_ts:
            findings.append({
                "name": "Not Before",
                "severity": "medium",
                "ok": False,
                "message": "Token is not yet valid (nbf in the future).",
                "value": nbf,
            })

        if iat is not None and iat > now_ts + 300:
            findings.append({
                "name": "Issued At",
                "severity": "low",
                "ok": False,
                "message": "iat appears to be in the future.",
                "value": iat,
            })

        risk_score = 0
        for f in findings:
            if f["severity"] == "critical":
                risk_score += 40
            elif f["severity"] == "high" and not f["ok"]:
                risk_score += 20
            elif f["severity"] == "medium" and not f["ok"]:
                risk_score += 10
            elif f["severity"] == "low" and not f["ok"]:
                risk_score += 5

        risk_score = min(risk_score, 100)
        risk_level = "low" if risk_score < 20 else "medium" if risk_score < 50 else "high"

        return {
            "valid_format": True,
            "header": header,
            "payload": payload,
            "signature_length": len(signature_segment),
            "findings": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
        }

    def scan_secrets(self, text: str) -> Dict[str, Any]:
        """Scan text for likely credential/token leaks."""
        findings = []
        source = text or ""

        for spec in self.SECRET_PATTERNS:
            pattern = spec["pattern"]
            matches = list(pattern.finditer(source))
            for match in matches:
                findings.append({
                    "type": spec["name"],
                    "severity": spec["severity"],
                    "preview": self._mask_secret(match.group(0)),
                    "index": match.start(),
                })

        findings.sort(key=lambda x: x["index"])

        by_type: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for f in findings:
            by_type[f["type"]] = by_type.get(f["type"], 0) + 1
            by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1

        return {
            "total_findings": len(findings),
            "counts_by_type": by_type,
            "counts_by_severity": by_severity,
            "findings": findings[:200],
        }

    def analyze_tls(self, target: str, port: int = 443, timeout: float = 8.0) -> Dict[str, Any]:
        """Inspect TLS certificate and negotiated security settings."""
        if not target:
            raise ValueError("Target hostname or URL is required.")

        hostname = self._extract_hostname(target)
        if not hostname:
            raise ValueError("Could not resolve hostname from input.")

        context = ssl.create_default_context()

        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)
                tls_version = tls_sock.version()
                cipher = tls_sock.cipher()

        cert = x509.load_der_x509_certificate(cert_der, default_backend())

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = san_ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        now = datetime.now(timezone.utc)
        not_after = cert.not_valid_after_utc
        not_before = cert.not_valid_before_utc
        days_remaining = (not_after - now).days

        findings = []
        if days_remaining < 0:
            findings.append({"name": "Certificate Expiry", "ok": False, "severity": "critical", "message": "Certificate is expired."})
        elif days_remaining <= 30:
            findings.append({"name": "Certificate Expiry", "ok": False, "severity": "high", "message": f"Certificate expires in {days_remaining} days."})
        elif days_remaining <= 90:
            findings.append({"name": "Certificate Expiry", "ok": True, "severity": "low", "message": f"Certificate expires in {days_remaining} days."})
        else:
            findings.append({"name": "Certificate Expiry", "ok": True, "severity": "info", "message": f"Certificate expires in {days_remaining} days."})

        if tls_version in ["TLSv1", "TLSv1.1"]:
            findings.append({"name": "TLS Version", "ok": False, "severity": "high", "message": f"Weak protocol negotiated: {tls_version}."})
        else:
            findings.append({"name": "TLS Version", "ok": True, "severity": "info", "message": f"Negotiated protocol: {tls_version}."})

        score = 100
        for finding in findings:
            if finding["severity"] == "critical":
                score -= 30
            elif finding["severity"] == "high":
                score -= 15
            elif finding["severity"] == "low":
                score -= 5

        score = max(0, score)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"

        return {
            "target": target,
            "hostname": hostname,
            "port": port,
            "tls_version": tls_version,
            "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]} if cipher else None,
            "certificate": {
                "subject": cert.subject.rfc4514_string(),
                "issuer": cert.issuer.rfc4514_string(),
                "serial_number": hex(cert.serial_number),
                "not_before": not_before.isoformat(),
                "not_after": not_after.isoformat(),
                "days_remaining": days_remaining,
                "san_count": len(sans),
                "san_sample": sans[:25],
            },
            "findings": findings,
            "score": score,
            "grade": grade,
        }

    def _normalize_url(self, url: str) -> str:
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"https://{url}"
        return url

    def _check_presence(
        self,
        headers: Dict[str, str],
        key: str,
        display: str,
        https_only: bool = False,
        url: str = "",
    ) -> Dict[str, Any]:
        present = key in headers and bool(headers.get(key))
        if https_only and url and not url.lower().startswith("https://"):
            return {
                "name": display,
                "ok": True,
                "severity": "info",
                "message": "Not applicable on non-HTTPS endpoints.",
            }
        return {
            "name": display,
            "ok": present,
            "severity": "info" if present else "high",
            "message": "Present." if present else "Missing.",
        }

    def _check_exact(self, headers: Dict[str, str], key: str, expected: str, display: str) -> Dict[str, Any]:
        value = headers.get(key, "").lower().strip()
        ok = value == expected
        return {
            "name": display,
            "ok": ok,
            "severity": "info" if ok else "medium",
            "message": f"Value is '{value}'." if value else "Missing.",
        }

    def _check_cookie_flags(self, set_cookie_headers: List[str]) -> Dict[str, Any]:
        if not set_cookie_headers:
            return {
                "name": "Cookie Security Flags",
                "ok": True,
                "severity": "info",
                "message": "No Set-Cookie headers observed.",
            }

        insecure = []
        for cookie in set_cookie_headers:
            lc = cookie.lower()
            if "secure" not in lc or "httponly" not in lc:
                insecure.append(cookie)

        return {
            "name": "Cookie Security Flags",
            "ok": len(insecure) == 0,
            "severity": "info" if len(insecure) == 0 else "medium",
            "message": "All cookies contain Secure + HttpOnly." if len(insecure) == 0 else "Some cookies miss Secure/HttpOnly.",
            "details": insecure[:5],
        }

    def _check_cors(self, headers: Dict[str, str]) -> Dict[str, Any]:
        value = headers.get("access-control-allow-origin", "")
        wildcard = value.strip() == "*"
        return {
            "name": "CORS Policy",
            "ok": not wildcard,
            "severity": "info" if not wildcard else "medium",
            "message": "No wildcard ACAO detected." if not wildcard else "Access-Control-Allow-Origin is '*'.",
        }

    def _check_server_disclosure(self, headers: Dict[str, str]) -> Dict[str, Any]:
        server = headers.get("server", "")
        x_powered_by = headers.get("x-powered-by", "")
        exposed = bool(server or x_powered_by)
        return {
            "name": "Server Fingerprint Disclosure",
            "ok": not exposed,
            "severity": "low" if exposed else "info",
            "message": "Server/X-Powered-By headers exposed." if exposed else "No server fingerprint headers exposed.",
            "details": {"server": server, "x-powered-by": x_powered_by},
        }

    def _jwt_decode_segment(self, segment: str) -> Dict[str, Any]:
        padded = segment + "=" * (-len(segment) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("utf-8"))
        return json.loads(decoded.decode("utf-8"))

    def _safe_int(self, value: Any) -> Any:
        try:
            if value is None:
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    def _mask_secret(self, value: str) -> str:
        if len(value) <= 10:
            return "***"
        return f"{value[:4]}...{value[-4:]}"

    def _extract_hostname(self, target: str) -> str:
        parsed = urlparse(target if "://" in target else f"https://{target}")
        return parsed.hostname or ""
