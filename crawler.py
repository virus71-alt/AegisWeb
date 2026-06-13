"""
Web Crawler Module for Website Health Analyzer.

Uses httpx and BeautifulSoup4 to crawl internal links asynchronously,
verifies status codes, tracks redirects, and extracts SEO anomalies.
Respects robots.txt rules.
"""

import asyncio
import logging
from typing import Dict, List, Set, Any, Tuple, Optional, Callable
from urllib.parse import urlparse, urljoin
import urllib.robotparser
from bs4 import BeautifulSoup
import httpx

logger = logging.getLogger(__name__)


class AsyncWebCrawler:
    """
    An asynchronous web crawler that respects robots.txt, extracts page data,
    verifies internal links, and counts redirect chains.
    """

    def __init__(
        self,
        start_url: str,
        max_depth: int = 3,
        max_pages: int = 100,
        user_agent: str = "AegisWeb/1.0",
        timeout_seconds: float = 10.0
    ):
        self.start_url = start_url
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.user_agent = user_agent
        self.timeout = timeout_seconds

        # Parse target domain
        parsed = urlparse(start_url)
        self.scheme = parsed.scheme if parsed.scheme in ["http", "https"] else "https"
        self.domain = parsed.netloc.lower()
        self.base_domain_url = f"{self.scheme}://{self.domain}"

        # Visited and crawl track records
        self.crawled_urls: Dict[str, Dict[str, Any]] = {}  # URL -> crawl result
        self.verified_urls: Dict[str, Dict[str, Any]] = {} # URL -> simple status (for internal links not fully crawled)
        self.found_external_links: Set[str] = set()

        # Robot file parser
        self.robot_parser = urllib.robotparser.RobotFileParser()
        self.robots_loaded = False

    async def load_robots_txt(self, client: httpx.AsyncClient) -> None:
        """Fetches and parses the target domain's robots.txt."""
        robots_url = urljoin(self.base_domain_url, "/robots.txt")
        try:
            response = await client.get(robots_url, headers={"User-Agent": self.user_agent}, timeout=self.timeout)
            if response.status_code == 200:
                self.robot_parser.parse(response.text.splitlines())
            else:
                # If robots.txt does not exist or errors out, assume everything is allowed
                self.robot_parser.allow_all = True
        except Exception:
            # Fallback on network failure
            self.robot_parser.allow_all = True
        self.robots_loaded = True

    def can_fetch(self, url: str) -> bool:
        """Checks whether robots.txt rules permit crawling the given URL."""
        if not self.robots_loaded:
            return True
        return self.robot_parser.can_fetch(self.user_agent, url)

    def is_internal(self, url: str) -> bool:
        """Determines if a URL belongs to the target domain."""
        parsed = urlparse(url)
        # Empty netloc means it's a relative path, which is internal
        if not parsed.netloc:
            return True
        return parsed.netloc.lower() == self.domain

    def clean_url(self, url: str) -> str:
        """Cleans and normalizes the URL (removes fragments)."""
        parsed = urlparse(url)
        # Rebuild without fragment
        cleaned = parsed._replace(fragment="").geturl()
        return cleaned

    def _extract_seo_fields(self, html: str, result: Dict[str, Any]) -> BeautifulSoup:
        """
        Parses HTML and populates SEO fields (title, meta description, h1 count,
        canonical, missing image alts) into `result`, marking it as parsed.
        Returns the BeautifulSoup object so callers can reuse it (e.g. for links).
        """
        soup = BeautifulSoup(html, "html.parser")
        result["parsed"] = True

        title_tag = soup.find("title")
        if title_tag:
            result["title"] = title_tag.get_text()

        desc_tag = soup.find("meta", attrs={"name": "description"})
        if desc_tag:
            result["meta_description"] = desc_tag.get("content")

        result["h1_count"] = len(soup.find_all("h1"))

        canonical_tag = soup.find("link", rel="canonical")
        result["missing_canonical"] = canonical_tag is None

        missing_alts = 0
        for img in soup.find_all("img"):
            if not img.get("alt") or img.get("alt").strip() == "":
                missing_alts += 1
        result["missing_alt_images_count"] = missing_alts

        return soup

    async def verify_link(self, client: httpx.AsyncClient, url: str) -> Dict[str, Any]:
        """
        Verifies a link asynchronously (e.g. static assets, depth-exceeded pages, or PDFs).
        Checks if it's broken, records status codes and redirect chains.
        """
        url = self.clean_url(url)
        if url in self.crawled_urls:
            return self.crawled_urls[url]
        if url in self.verified_urls:
            return self.verified_urls[url]

        result = {
            "url": url,
            "final_url": url,
            "status_code": None,
            "redirect_chain_length": 0,
            "is_broken": True,
            "title": None,
            "meta_description": None,
            "h1_count": 0,
            "missing_alt_images_count": 0,
            "missing_canonical": False,
            # Set True below only if the response is HTML and gets parsed. Non-HTML
            # resources (PDFs, images) stay False so SEO checks correctly skip them.
            "parsed": False
        }

        if not self.can_fetch(url):
            result["status_code"] = 403
            result["is_broken"] = True
            self.verified_urls[url] = result
            return result

        try:
            # Send GET request but stream or request headers first to check if broken
            # For verification, we can do a GET but follow redirects to track the chain
            response = await client.get(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                follow_redirects=True
            )
            result["status_code"] = response.status_code
            result["redirect_chain_length"] = len(response.history)
            result["final_url"] = self.clean_url(str(response.url))
            result["is_broken"] = response.status_code >= 400

            # Lightweight parse so depth/page-limited pages still get real SEO data
            # instead of placeholder nulls (which would read as false "missing" findings).
            if not result["is_broken"] and "text/html" in response.headers.get("Content-Type", ""):
                self._extract_seo_fields(response.text, result)
        except httpx.TooManyRedirects:
            result["status_code"] = 310
            result["redirect_chain_length"] = 20
            result["is_broken"] = True
        except httpx.HTTPError:
            result["is_broken"] = True
        except Exception:
            result["is_broken"] = True

        self.verified_urls[url] = result
        return result

    async def crawl_page(self, client: httpx.AsyncClient, url: str) -> Tuple[Dict[str, Any], List[str]]:
        """
        Fetches, parses, and extracts details and links from a single HTML page.
        """
        result = {
            "url": url,
            # Destination after following redirects; used to dedupe pages reachable
            # under multiple URL spellings (e.g. "/" vs "/index.html" vs no trailing slash).
            "final_url": url,
            "status_code": None,
            "title": None,
            "meta_description": None,
            "h1_count": 0,
            "missing_alt_images_count": 0,
            "redirect_chain_length": 0,
            "is_broken": False,
            "missing_canonical": False,
            # Set True only once the response is confirmed HTML and parsed below.
            "parsed": False
        }
        extracted_links: List[str] = []

        if not self.can_fetch(url):
            result["status_code"] = 403
            result["is_broken"] = True
            return result, extracted_links

        try:
            response = await client.get(
                url,
                headers={"User-Agent": self.user_agent},
                timeout=self.timeout,
                follow_redirects=True
            )
            result["status_code"] = response.status_code
            result["redirect_chain_length"] = len(response.history)
            result["final_url"] = self.clean_url(str(response.url))

            # Check if it's broken
            if response.status_code >= 400:
                result["is_broken"] = True
                return result, extracted_links

            # Verify it's HTML before parsing
            content_type = response.headers.get("Content-Type", "")
            if "text/html" not in content_type:
                # We crawled it, but it's not HTML (could be image, PDF, text etc)
                return result, extracted_links

            # Parse HTML and populate SEO fields (shared with verify_link).
            soup = self._extract_seo_fields(response.text, result)

            # Extract links
            a_tags = soup.find_all("a", href=True)
            for a in a_tags:
                href = a.get("href")
                if not href:
                    continue
                # Resolve relative URL
                full_url = urljoin(url, href)
                cleaned = self.clean_url(full_url)
                
                # Check scheme
                parsed_href = urlparse(cleaned)
                if parsed_href.scheme not in ["http", "https"]:
                    continue

                if self.is_internal(cleaned):
                    extracted_links.append(cleaned)
                else:
                    self.found_external_links.add(cleaned)

        except httpx.TooManyRedirects:
            result["status_code"] = 310
            result["redirect_chain_length"] = 20
            result["is_broken"] = True
        except httpx.HTTPError as e:
            result["is_broken"] = True
            logger.debug(f"HTTPError on {url}: {e}")
        except Exception as e:
            result["is_broken"] = True
            logger.debug(f"Exception on {url}: {e}")

        return result, extracted_links

    async def crawl(
        self,
        progress_callback: Optional[Callable[[str, int, int], None]] = None
    ) -> Tuple[List[Dict[str, Any]], Set[str]]:
        """
        Asynchronously crawls the website using a BFS queue.
        Also verifies any un-crawled internal links to identify 404s/broken links.
        """
        # Create limits queue
        queue: asyncio.Queue[Tuple[str, int]] = asyncio.Queue()
        # Start queue
        start_cleaned = self.clean_url(self.start_url)
        await queue.put((start_cleaned, 0))

        # Visited sets
        visited_to_crawl: Set[str] = {start_cleaned}
        all_internal_links_discovered: Set[str] = {start_cleaned}

        # Async Client
        async with httpx.AsyncClient(verify=False) as client:
            # 1. Load robots.txt
            await self.load_robots_txt(client)

            # Check if robots.txt blocks start URL
            if not self.can_fetch(start_cleaned):
                logger.warning("Robots.txt blocks access to start URL.")

            # BFS crawl loop
            while not queue.empty() and len(self.crawled_urls) < self.max_pages:
                current_url, depth = await queue.get()

                # Call progress callback if available
                if progress_callback:
                    progress_callback("Crawling", queue.qsize(), len(self.crawled_urls))

                # Crawl page
                result, links = await self.crawl_page(client, current_url)
                self.crawled_urls[current_url] = result

                # Stop if depth reached max
                if depth < self.max_depth:
                    for link in links:
                        all_internal_links_discovered.add(link)
                        if link not in visited_to_crawl:
                            visited_to_crawl.add(link)
                            if len(visited_to_crawl) <= self.max_pages * 2: # heuristic cap on queue
                                await queue.put((link, depth + 1))

                queue.task_done()

            # 2. Verify all internal links that were discovered but not crawled
            # This is crucial for verifying internal links for 404s/etc.
            uncrawled_internals = all_internal_links_discovered - set(self.crawled_urls.keys())
            
            if uncrawled_internals:
                # We can verify them concurrently with semaphores
                sem = asyncio.Semaphore(10)  # limit concurrency for safety
                
                async def verify_task(url_to_verify: str):
                    async with sem:
                        if progress_callback:
                            progress_callback("Verifying links", 0, len(self.crawled_urls))
                        res = await self.verify_link(client, url_to_verify)
                        return res

                tasks = [verify_task(url) for url in uncrawled_internals]
                await asyncio.gather(*tasks)

        # Merge crawl results and verified results
        # A fully crawled result is already in self.crawled_urls
        # An un-crawled verified link is in self.verified_urls
        final_crawl_results = list(self.crawled_urls.values())
        for url, details in self.verified_urls.items():
            if url not in self.crawled_urls:
                final_crawl_results.append(details)

        return final_crawl_results, self.found_external_links
