"""
Database Module for Website Health Analyzer.

Handles SQLite3 persistence, including historical tracking for audits, crawls,
network performance, and security headers.
Uses asyncio.to_thread to run blocking SQLite3 operations on background threads,
ensuring the async event loop is not blocked.
Guarantees connections are closed using try/finally blocks.
"""

import sqlite3
import datetime
import asyncio
from typing import Dict, List, Any, Optional, Tuple


class DatabaseManager:
    """
    Manages connections and operations on the SQLite3 database.
    """

    def __init__(self, db_path: str = "analyzer.db"):
        self.db_path = db_path

    def _get_connection(self) -> sqlite3.Connection:
        """Helper to get a connection with foreign key constraints enabled."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    def init_db(self) -> None:
        """
        Synchronously initializes the SQLite3 tables if they do not exist.
        Runs on module/application startup.
        """
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                # 1. sites table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS sites (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        url TEXT UNIQUE NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)

                # 2. audits table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audits (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        site_id INTEGER NOT NULL,
                        timestamp TIMESTAMP NOT NULL,
                        overall_health_score REAL NOT NULL,
                        FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
                    );
                """)

                # 3. crawl_results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS crawl_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        audit_id INTEGER NOT NULL,
                        url TEXT NOT NULL,
                        status_code INTEGER,
                        title TEXT,
                        meta_description TEXT,
                        h1_count INTEGER,
                        missing_alt_images_count INTEGER,
                        redirect_chain_length INTEGER,
                        is_broken BOOLEAN NOT NULL,
                        FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
                    );
                """)

                # 4. network_results table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS network_results (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        audit_id INTEGER NOT NULL,
                        ttfb_ms REAL,
                        dns_resolution_time_ms REAL,
                        ssl_expiry_days INTEGER,
                        FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
                    );
                """)

                # 5. security_headers table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS security_headers (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        audit_id INTEGER NOT NULL,
                        header_name TEXT NOT NULL,
                        is_present BOOLEAN NOT NULL,
                        value TEXT,
                        FOREIGN KEY (audit_id) REFERENCES audits(id) ON DELETE CASCADE
                    );
                """)
                conn.commit()
        finally:
            conn.close()

    async def init_db_async(self) -> None:
        """Asynchronously initializes the database."""
        await asyncio.to_thread(self.init_db)

    def _get_or_create_site(self, url: str) -> int:
        """Gets or creates a site and returns its ID."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM sites WHERE url = ?", (url,))
                row = cursor.fetchone()
                if row:
                    return row["id"]
                
                cursor.execute("INSERT INTO sites (url) VALUES (?)", (url,))
                conn.commit()
                return cursor.lastrowid
        finally:
            conn.close()

    async def get_or_create_site(self, url: str) -> int:
        """Asynchronously gets or creates a site and returns its ID."""
        return await asyncio.to_thread(self._get_or_create_site, url)

    def _create_audit(self, site_id: int, overall_health_score: float) -> int:
        """Creates a new audit record and returns its ID."""
        now = datetime.datetime.now().isoformat()
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO audits (site_id, timestamp, overall_health_score) VALUES (?, ?, ?)",
                    (site_id, now, overall_health_score)
                )
                conn.commit()
                return cursor.lastrowid
        finally:
            conn.close()

    async def create_audit(self, site_id: int, overall_health_score: float) -> int:
        """Asynchronously creates a new audit record."""
        return await asyncio.to_thread(self._create_audit, site_id, overall_health_score)

    def _save_audit_details(
        self,
        audit_id: int,
        crawl_results: List[Dict[str, Any]],
        network_results: Dict[str, Any],
        security_headers: List[Dict[str, Any]]
    ) -> None:
        """Synchronous transaction to insert crawl, network, and security data."""
        conn = self._get_connection()
        try:
            with conn:
                cursor = conn.cursor()

                # Insert crawl results
                for page in crawl_results:
                    cursor.execute("""
                        INSERT INTO crawl_results (
                            audit_id, url, status_code, title, meta_description, 
                            h1_count, missing_alt_images_count, redirect_chain_length, is_broken
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        audit_id,
                        page.get("url"),
                        page.get("status_code"),
                        page.get("title"),
                        page.get("meta_description"),
                        page.get("h1_count"),
                        page.get("missing_alt_images_count"),
                        page.get("redirect_chain_length", 0),
                        1 if page.get("is_broken", False) else 0
                    ))

                # Insert network results
                cursor.execute("""
                    INSERT INTO network_results (
                        audit_id, ttfb_ms, dns_resolution_time_ms, ssl_expiry_days
                    ) VALUES (?, ?, ?, ?)
                """, (
                    audit_id,
                    network_results.get("ttfb_ms"),
                    network_results.get("dns_resolution_time_ms"),
                    network_results.get("ssl_expiry_days")
                ))

                # Insert security headers
                for header in security_headers:
                    cursor.execute("""
                        INSERT INTO security_headers (
                            audit_id, header_name, is_present, value
                        ) VALUES (?, ?, ?, ?)
                    """, (
                        audit_id,
                        header.get("header_name"),
                        1 if header.get("is_present", False) else 0,
                        header.get("value")
                    ))

                conn.commit()
        finally:
            conn.close()

    async def save_audit_details(
        self,
        audit_id: int,
        crawl_results: List[Dict[str, Any]],
        network_results: Dict[str, Any],
        security_headers: List[Dict[str, Any]]
    ) -> None:
        """Asynchronously saves all the detailed audit results in a single transaction."""
        await asyncio.to_thread(
            self._save_audit_details,
            audit_id,
            crawl_results,
            network_results,
            security_headers
        )

    def _get_history(self, url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieves audit history. If url is specified, filters by that url."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            if url:
                cursor.execute("""
                    SELECT a.id as audit_id, s.url, a.timestamp, a.overall_health_score
                    FROM audits a
                    JOIN sites s ON a.site_id = s.id
                    WHERE s.url = ?
                    ORDER BY a.timestamp DESC
                """, (url,))
            else:
                cursor.execute("""
                    SELECT a.id as audit_id, s.url, a.timestamp, a.overall_health_score
                    FROM audits a
                    JOIN sites s ON a.site_id = s.id
                    ORDER BY a.timestamp DESC
                """)
            
            history_rows = cursor.fetchall()
            history = []
            for row in history_rows:
                audit_id = row["audit_id"]
                
                # Get basic counts to summarize in history list
                # 1. Total links crawled and how many are broken
                cursor.execute("""
                    SELECT COUNT(*), SUM(is_broken) 
                    FROM crawl_results 
                    WHERE audit_id = ?
                """, (audit_id,))
                total_crawled, total_broken = cursor.fetchone()
                total_broken = total_broken or 0

                # 2. SSL expiry days
                cursor.execute("""
                    SELECT ssl_expiry_days 
                    FROM network_results 
                    WHERE audit_id = ?
                """, (audit_id,))
                net_row = cursor.fetchone()
                ssl_expiry = net_row["ssl_expiry_days"] if net_row else None

                history.append({
                    "audit_id": audit_id,
                    "url": row["url"],
                    "timestamp": row["timestamp"],
                    "overall_health_score": row["overall_health_score"],
                    "total_pages_crawled": total_crawled,
                    "broken_links_count": total_broken,
                    "ssl_expiry_days": ssl_expiry
                })
            return history
        finally:
            conn.close()

    async def get_history(self, url: Optional[str] = None) -> List[Dict[str, Any]]:
        """Asynchronously retrieves audit history."""
        return await asyncio.to_thread(self._get_history, url)

    def _get_audit_details(self, audit_id: int) -> Optional[Dict[str, Any]]:
        """Retrieves full details of a specific audit by its ID."""
        conn = self._get_connection()
        try:
            cursor = conn.cursor()
            
            # Get Audit basic info
            cursor.execute("""
                SELECT a.id as audit_id, s.url, a.timestamp, a.overall_health_score
                FROM audits a
                JOIN sites s ON a.site_id = s.id
                WHERE a.id = ?
            """, (audit_id,))
            audit_row = cursor.fetchone()
            if not audit_row:
                return None
            
            # Get Crawl results
            cursor.execute("""
                SELECT url, status_code, title, meta_description, h1_count, 
                       missing_alt_images_count, redirect_chain_length, is_broken
                FROM crawl_results
                WHERE audit_id = ?
            """, (audit_id,))
            crawl_rows = cursor.fetchall()
            crawl_results = [dict(r) for r in crawl_rows]

            # Get Network results
            cursor.execute("""
                SELECT ttfb_ms, dns_resolution_time_ms, ssl_expiry_days
                FROM network_results
                WHERE audit_id = ?
            """, (audit_id,))
            net_row = cursor.fetchone()
            network_results = dict(net_row) if net_row else {}

            # Get Security headers
            cursor.execute("""
                SELECT header_name, is_present, value
                FROM security_headers
                WHERE audit_id = ?
            """, (audit_id,))
            header_rows = cursor.fetchall()
            security_headers = [dict(r) for r in header_rows]

            return {
                "audit_id": audit_row["audit_id"],
                "url": audit_row["url"],
                "timestamp": audit_row["timestamp"],
                "overall_health_score": audit_row["overall_health_score"],
                "crawl_results": crawl_results,
                "network_results": network_results,
                "security_headers": security_headers
            }
        finally:
            conn.close()

    async def get_audit_details(self, audit_id: int) -> Optional[Dict[str, Any]]:
        """Asynchronously retrieves details for a specific audit."""
        return await asyncio.to_thread(self._get_audit_details, audit_id)
