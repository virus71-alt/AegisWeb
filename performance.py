"""
Performance Metrics Agent Module for Website Health Analyzer.

Wraps the official Google PageSpeed Insights API to retrieve and extract Core Web Vitals
(First Contentful Paint, Cumulative Layout Shift, and Largest Contentful Paint).
"""

import logging
from typing import Dict, Any, Optional
import httpx

logger = logging.getLogger(__name__)


class PerformanceAgent:
    """
    Interfaces with Google PageSpeed Insights API to collect performance metrics.
    """

    API_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"

    def __init__(self, target_url: str, api_key: Optional[str] = None, timeout_seconds: float = 30.0):
        self.target_url = target_url
        self.api_key = api_key
        self.timeout = timeout_seconds

    async def fetch_performance_metrics(self) -> Dict[str, Any]:
        """
        Queries PageSpeed Insights API and extracts FCP, LCP, and CLS.
        Falls back gracefully if the API fails or no key is provided.
        """
        metrics = {
            "fcp": None,
            "lcp": None,
            "cls": None,
            "score": None,
            "status": "skipped",
            "error": None
        }

        # Query parameters
        params = {
            "url": self.target_url,
            "category": "performance",
            "strategy": "desktop"
        }
        if self.api_key:
            params["key"] = self.api_key

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(self.API_URL, params=params)
                
                # Check status code
                if response.status_code != 200:
                    metrics["status"] = "failed"
                    metrics["error"] = f"API returned status code {response.status_code}: {response.text[:200]}"
                    return metrics

                data = response.json()
                
                # Extract Lighthouse Audits (Lab Data)
                lh_results = data.get("lighthouseResult", {})
                audits = lh_results.get("audits", {})

                # Extract performance score (0 to 100)
                perf_category = lh_results.get("categories", {}).get("performance", {})
                raw_score = perf_category.get("score")
                if raw_score is not None:
                    metrics["score"] = round(raw_score * 100, 1)

                # First Contentful Paint
                fcp_audit = audits.get("first-contentful-paint", {})
                metrics["fcp"] = {
                    "value_ms": fcp_audit.get("numericValue"),
                    "display": fcp_audit.get("displayValue")
                }

                # Largest Contentful Paint
                lcp_audit = audits.get("largest-contentful-paint", {})
                metrics["lcp"] = {
                    "value_ms": lcp_audit.get("numericValue"),
                    "display": lcp_audit.get("displayValue")
                }

                # Cumulative Layout Shift
                cls_audit = audits.get("cumulative-layout-shift", {})
                metrics["cls"] = {
                    "value": cls_audit.get("numericValue"),
                    "display": cls_audit.get("displayValue")
                }

                metrics["status"] = "success"

        except httpx.HTTPError as e:
            metrics["status"] = "failed"
            metrics["error"] = f"HTTP request failed: {str(e)}"
        except Exception as e:
            metrics["status"] = "failed"
            metrics["error"] = f"Parsing failed: {str(e)}"

        return metrics
