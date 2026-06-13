"""
Security Hardening Scanner Module for Website Health Analyzer.

Handles SSL Certificate auditing (using Python socket/ssl & cryptography libraries)
and audits homepage response headers for required security configurations.
"""

import ssl
import socket
import datetime
import asyncio
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class SecurityScanner:
    """
    Scans website SSL certificates and security headers.
    """

    def __init__(self, url: str, timeout_seconds: float = 10.0):
        self.url = url
        self.timeout = timeout_seconds
        
        parsed = urlparse(url)
        self.scheme = parsed.scheme if parsed.scheme in ["http", "https"] else "https"
        self.hostname = parsed.netloc or parsed.path
        if ":" in self.hostname:
            self.hostname = self.hostname.split(":")[0]

    def _get_ssl_details_sync(self) -> Dict[str, Any]:
        """
        Synchronously establishes SSL connection and extracts the peer cert details.
        """
        result = {
            "ssl_expiry_days": None,
            "issuer": None,
            "signature_algorithm": None,
            "error": None
        }

        # If HTTP, there's no SSL certificate to scan unless we upgrade it
        if self.scheme != "https":
            result["error"] = "Website is served over unencrypted HTTP. No SSL certificate to analyze."
            result["ssl_expiry_days"] = -1  # flag as critical / expired
            return result

        context = ssl.create_default_context()
        # Allow checking expired/invalid certs too (otherwise wrap_socket throws before we can extract days)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((self.hostname, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    if not der_cert:
                        result["error"] = "Failed to retrieve peer SSL certificate"
                        return result
                    
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    
                    # 1. Extract Issuer
                    result["issuer"] = cert.issuer.rfc4514_string()

                    # 2. Extract Signature Algorithm
                    result["signature_algorithm"] = cert.signature_algorithm_oid._name

                    # 3. Extract expiration date safely (checking UTC-aware values first to prevent deprecation warnings)
                    try:
                        not_after = cert.not_valid_after_utc
                    except AttributeError:
                        not_after = cert.not_valid_after

                    # Calculate remaining days
                    if hasattr(not_after, "tzinfo") and not_after.tzinfo is not None:
                        now = datetime.datetime.now(datetime.timezone.utc)
                    else:
                        now = datetime.datetime.utcnow()

                    days_remaining = (not_after - now).days
                    result["ssl_expiry_days"] = days_remaining
        except Exception as e:
            result["error"] = f"SSL Connection failed: {str(e)}"
            result["ssl_expiry_days"] = -1  # count as failed/expired for scoring

        return result

    async def audit_ssl_certificate(self) -> Dict[str, Any]:
        """
        Asynchronously fetches and audits the target's SSL Certificate.
        """
        return await asyncio.to_thread(self._get_ssl_details_sync)

    async def audit_security_headers(self) -> List[Dict[str, Any]]:
        """
        Connects to the website's homepage and checks for security-hardening HTTP headers.
        """
        headers_to_check = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]

        report = []

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                response = await client.get(self.url, follow_redirects=True)
                
                # Check response headers case-insensitively
                resp_headers = {k.lower(): v for k, v in response.headers.items()}
                
                for header in headers_to_check:
                    header_lower = header.lower()
                    if header_lower in resp_headers:
                        val = resp_headers[header_lower]
                        report.append({
                            "header_name": header,
                            "is_present": True,
                            "value": val
                        })
                    else:
                        report.append({
                            "header_name": header,
                            "is_present": False,
                            "value": None
                        })
        except Exception as e:
            # If the request fails, report all headers as missing/failed
            for header in headers_to_check:
                report.append({
                    "header_name": header,
                    "is_present": False,
                    "value": f"Error checking header: {str(e)}"
                })

        return report
