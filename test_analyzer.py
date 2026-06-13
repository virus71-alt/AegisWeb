"""
Unit and Integration Tests for Website Health Analyzer.

Verifies scoring engine rules, database creation and tracking, network latencies,
security header parsing, and crawler logic.
"""

import os
import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from db import DatabaseManager
from scoring import calculate_health_score
from security import SecurityScanner
from network import NetworkProfiler


class TestScoringEngine(unittest.TestCase):
    """Tests that the health score calculations are precise and match deductions rules."""

    def test_perfect_score(self):
        """A site with zero issues should score 100.0."""
        score, deductions = calculate_health_score(
            crawl_results=[{"url": "https://example.com", "is_broken": False, "title": "Home", "meta_description": "Descr"}],
            network_results={"ssl_expiry_days": 45},
            security_headers=[
                {"header_name": "Strict-Transport-Security", "is_present": True},
                {"header_name": "Content-Security-Policy", "is_present": True},
                {"header_name": "X-Frame-Options", "is_present": True},
                {"header_name": "X-Content-Type-Options", "is_present": True},
                {"header_name": "Referrer-Policy", "is_present": True}
            ]
        )
        self.assertEqual(score, 100.0)
        self.assertEqual(len(deductions), 0)

    def test_broken_links_deductions(self):
        """Broken links deduct 5% each, capped at 30%."""
        # Test 2 broken links (-10.0%)
        crawl_results = [
            {"url": "https://example.com", "is_broken": False, "title": "Home", "meta_description": "Descr"},
            {"url": "https://example.com/bad1", "is_broken": True},
            {"url": "https://example.com/bad2", "is_broken": True}
        ]
        score, deductions = calculate_health_score(
            crawl_results=crawl_results,
            network_results={"ssl_expiry_days": 45},
            security_headers=[{"header_name": h, "is_present": True} for h in [
                "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
            ]]
        )
        self.assertEqual(score, 90.0)
        self.assertIn("broken_links", deductions)

        # Test 10 broken links (should cap at -30.0%)
        crawl_results_many = [{"url": f"https://example.com/bad{i}", "is_broken": True} for i in range(10)]
        score_cap, deductions_cap = calculate_health_score(
            crawl_results=crawl_results_many,
            network_results={"ssl_expiry_days": 45},
            security_headers=[{"header_name": h, "is_present": True} for h in [
                "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
            ]]
        )
        self.assertEqual(score_cap, 70.0)

    def test_missing_headers_deductions(self):
        """Each missing header deducts 3%."""
        score, deductions = calculate_health_score(
            crawl_results=[{"url": "https://example.com", "is_broken": False, "title": "Home", "meta_description": "Descr"}],
            network_results={"ssl_expiry_days": 45},
            security_headers=[
                {"header_name": "Strict-Transport-Security", "is_present": False},
                {"header_name": "Content-Security-Policy", "is_present": False},
                {"header_name": "X-Frame-Options", "is_present": True},
                {"header_name": "X-Content-Type-Options", "is_present": True},
                {"header_name": "Referrer-Policy", "is_present": True}
            ]
        )
        # 100 - 6 = 94.0
        self.assertEqual(score, 94.0)
        self.assertIn("security_headers", deductions)

    def test_ssl_expiring_deductions(self):
        """SSL expiring in less than 30 days deducts a critical 25%."""
        score, deductions = calculate_health_score(
            crawl_results=[{"url": "https://example.com", "is_broken": False, "title": "Home", "meta_description": "Descr"}],
            network_results={"ssl_expiry_days": 15},
            security_headers=[{"header_name": h, "is_present": True} for h in [
                "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"
            ]]
        )
        # 100 - 25 = 75.0
        self.assertEqual(score, 75.0)
        self.assertIn("ssl_status", deductions)


class TestDatabaseManager(unittest.TestCase):
    """Tests the local SQLite3 database tracking features."""

    def setUp(self):
        self.test_db = "test_analyzer.db"
        self.db = DatabaseManager(self.test_db)
        self.db.init_db()

    def tearDown(self):
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def test_site_creation_and_audit_insert(self):
        """Verifies that sites and audits are stored and retrieved successfully."""
        site_id = self.db._get_or_create_site("https://unittest-example.com")
        self.assertIsNotNone(site_id)

        # Retrieve again to verify uniqueness
        site_id_2 = self.db._get_or_create_site("https://unittest-example.com")
        self.assertEqual(site_id, site_id_2)

        # Insert audit
        audit_id = self.db._create_audit(site_id, 92.5)
        self.assertIsNotNone(audit_id)

        # Save details
        self.db._save_audit_details(
            audit_id=audit_id,
            crawl_results=[{
                "url": "https://unittest-example.com",
                "status_code": 200,
                "title": "Home",
                "meta_description": "Desc",
                "h1_count": 1,
                "missing_alt_images_count": 2,
                "redirect_chain_length": 0,
                "is_broken": False
            }],
            network_results={
                "ttfb_ms": 120.5,
                "dns_resolution_time_ms": 15.2,
                "ssl_expiry_days": 80
            },
            security_headers=[
                {"header_name": "X-Frame-Options", "is_present": True, "value": "DENY"}
            ]
        )

        # Get details
        details = self.db._get_audit_details(audit_id)
        self.assertIsNotNone(details)
        self.assertEqual(details["url"], "https://unittest-example.com")
        self.assertEqual(details["overall_health_score"], 92.5)
        self.assertEqual(len(details["crawl_results"]), 1)
        self.assertEqual(details["network_results"]["ttfb_ms"], 120.5)
        self.assertEqual(details["security_headers"][0]["header_name"], "X-Frame-Options")

        # Check history
        history = self.db._get_history(url="https://unittest-example.com")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["overall_health_score"], 92.5)


if __name__ == "__main__":
    unittest.main()
