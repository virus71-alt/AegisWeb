"""
Network & Infrastructure Module for Website Health Analyzer.

Calculates precise TTFB/RTT latencies and performs asynchronous DNS queries
using dnspython to log records (A, AAAA, MX, NS, TXT) and profile resolution speeds.
"""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import httpx
import dns.asyncresolver
import dns.resolver


class NetworkProfiler:
    """
    Profiles network latency (TTFB, RTT) and resolves DNS records asynchronously.
    """

    def __init__(self, url: str, timeout_seconds: float = 10.0):
        self.url = url
        self.timeout = timeout_seconds
        
        # Extract hostname
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        if ":" in hostname:
            hostname = hostname.split(":")[0]
        self.hostname = hostname

    async def profile_latency(self) -> Dict[str, Any]:
        """
        Profiles Time to First Byte (TTFB) and Round-Trip Time (RTT) using httpx stream.
        """
        metrics = {
            "ttfb_ms": None,
            "rtt_ms": None,
            "error": None
        }

        try:
            async with httpx.AsyncClient(verify=False, timeout=self.timeout) as client:
                start_time = asyncio.get_running_loop().time()
                
                # Initiate request using stream to get first byte (headers)
                async with client.stream("GET", self.url, follow_redirects=True) as response:
                    ttfb_time = asyncio.get_running_loop().time()
                    metrics["ttfb_ms"] = round((ttfb_time - start_time) * 1000.0, 2)
                    
                    # Read the response body to measure full RTT
                    await response.aread()
                    end_time = asyncio.get_running_loop().time()
                    metrics["rtt_ms"] = round((end_time - start_time) * 1000.0, 2)
        except Exception as e:
            metrics["error"] = str(e)
            # Fallback measurement if streaming doesn't support or fails
            metrics["ttfb_ms"] = -1.0
            metrics["rtt_ms"] = -1.0

        return metrics

    async def _resolve_record(
        self,
        resolver: dns.asyncresolver.Resolver,
        record_type: str
    ) -> Tuple[List[str], float, Optional[str]]:
        """
        Resolves a single DNS record type asynchronously and measures resolution latency.
        """
        start = time.perf_counter()
        try:
            # Query the record
            answer = await resolver.resolve(self.hostname, record_type)
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            records = [str(rdata) for rdata in answer]
            return records, duration_ms, None
        except dns.resolver.NoAnswer:
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return [], duration_ms, f"No {record_type} record found"
        except dns.resolver.NXDOMAIN:
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return [], duration_ms, "Domain does not exist (NXDOMAIN)"
        except dns.exception.Timeout:
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return [], duration_ms, "Query timed out"
        except Exception as e:
            duration_ms = round((time.perf_counter() - start) * 1000.0, 2)
            return [], duration_ms, str(e)

    async def verify_dns(self) -> Dict[str, Any]:
        """
        Queries and verifies DNS records (A, AAAA, MX, NS, TXT).
        Logs slow resolution times (> 150ms) and missing records.
        """
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout

        record_types = ["A", "AAAA", "MX", "NS", "TXT"]
        # Run queries concurrently
        tasks = [self._resolve_record(resolver, rtype) for rtype in record_types]
        results = await asyncio.gather(*tasks)

        dns_report = {
            "records": {},
            "total_resolution_time_ms": 0.0,
            "anomalies": []
        }

        total_time = 0.0
        slow_threshold_ms = 150.0

        for rtype, (records, duration, err) in zip(record_types, results):
            dns_report["records"][rtype] = {
                "values": records,
                "duration_ms": duration,
                "error": err
            }
            # Track overall latency (average or sum, let's track the resolution time of primary A record or sum)
            if rtype == "A":
                dns_report["total_resolution_time_ms"] = duration

            total_time += duration

            # Log slow resolution anomaly
            if duration > slow_threshold_ms:
                dns_report["anomalies"].append(
                    f"Slow resolution for {rtype} record: {duration}ms (exceeds {slow_threshold_ms}ms)"
                )

            # Log missing record anomaly
            if err:
                if rtype in ["A", "NS"]:
                    # A and NS records are critical for functional web domains
                    dns_report["anomalies"].append(f"Critical: {err} for {rtype}")
                else:
                    dns_report["anomalies"].append(f"Warning: {err} for {rtype}")

        return dns_report
