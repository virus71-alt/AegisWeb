"""
Remediation & Actionable Suggestions Module for AegisWeb.

Analyzes website audit data and generates concrete, prioritized fix recommendations
complete with code snippets and configurations (Nginx, Apache, HTML).
"""

from typing import List, Dict, Any, Optional


def generate_suggestions(
    crawl_results: List[Dict[str, Any]],
    network_results: Dict[str, Any],
    security_headers: List[Dict[str, Any]],
    ssl_profile: Dict[str, Any],
    perf_profile: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Analyzes website health and security findings to generate step-by-step
    remediation suggestions.

    Each recommendation dictionary contains:
    - category: (Security, SEO, Performance, Infrastructure)
    - severity: (High, Medium, Low)
    - title: Brief summary of what to fix
    - issue: AegisWeb diagnostic summary
    - remediation: Detailed step-by-step fix instructions
    - snippet: Optional code configuration block
    """
    suggestions = []

    # 1. SSL Certificate Checks
    ssl_days = ssl_profile.get("ssl_expiry_days")
    if ssl_days is not None:
        if ssl_days < 0:
            suggestions.append({
                "category": "Security",
                "severity": "High",
                "title": "SSL Certificate Has Expired",
                "issue": "Your SSL certificate is invalid, causing browser security warnings and blocking traffic.",
                "remediation": (
                    "Your certificate is expired. You must renew it immediately to restore HTTPS traffic. "
                    "If you use Certbot (Let's Encrypt), run the renewal command on your server."
                ),
                "snippet": "sudo certbot renew --force-renewal"
            })
        elif ssl_days < 30:
            suggestions.append({
                "category": "Security",
                "severity": "High",
                "title": f"SSL Certificate Expires in {ssl_days} Days",
                "issue": f"Your SSL certificate expires in less than 30 days ({ssl_days} days remaining).",
                "remediation": (
                    "Renew the SSL certificate before it expires to prevent service interruptions. "
                    "Set up an automated cron job on your server to run Certbot automatically."
                ),
                "snippet": "0 0,12 * * * python -c 'import random; import time; time.sleep(random.random() * 3600)' && sudo certbot renew"
            })
    elif ssl_profile.get("error") and ssl_profile.get("scheme") == "https":
        suggestions.append({
            "category": "Security",
            "severity": "High",
            "title": "SSL Connection Handshake Failed",
            "issue": f"Failed to verify SSL certificate: {ssl_profile.get('error')}",
            "remediation": (
                "Ensure your SSL certificate is configured correctly, verify intermediate CA chain certs "
                "are loaded, and check that the server is serving on port 443."
            ),
            "snippet": None
        })

    # 2. Security Headers Checks
    missing_headers = [h for h in security_headers if not h.get("is_present", False)]
    for header in missing_headers:
        name = header["header_name"]
        
        if name == "Strict-Transport-Security":
            suggestions.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Implement HTTP Strict Transport Security (HSTS)",
                "issue": "Strict-Transport-Security header was not found in the response.",
                "remediation": (
                    "HSTS forces browsers to connect only via HTTPS. Add this header to your server configuration.\n"
                    "For Nginx:"
                ),
                "snippet": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;'
            })
        elif name == "Content-Security-Policy":
            suggestions.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Configure Content Security Policy (CSP)",
                "issue": "Content-Security-Policy header is missing on your website.",
                "remediation": (
                    "CSP prevents cross-site scripting (XSS) and data injection attacks by restricting resources "
                    "(scripts, images, styles) to trusted origins. Implement a secure base policy.\n"
                    "For Nginx (Standard safe base policy):"
                ),
                "snippet": 'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:;" always;'
            })
        elif name == "X-Frame-Options":
            suggestions.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Configure X-Frame-Options to Prevent Clickjacking",
                "issue": "X-Frame-Options header is missing.",
                "remediation": (
                    "This header tells the browser whether your site is allowed to be framed inside an iframe. "
                    "Setting it to SAMEORIGIN prevents clickjacking attacks on other domains.\n"
                    "For Nginx:"
                ),
                "snippet": 'add_header X-Frame-Options "SAMEORIGIN" always;'
            })
        elif name == "X-Content-Type-Options":
            suggestions.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Configure X-Content-Type-Options to Prevent MIME Sniffing",
                "issue": "X-Content-Type-Options header is missing.",
                "remediation": (
                    "Prevents browsers from MIME-sniffing a response away from the declared content-type, protecting "
                    "against malicious script execution. Set this header to 'nosniff'.\n"
                    "For Nginx:"
                ),
                "snippet": 'add_header X-Content-Type-Options "nosniff" always;'
            })
        elif name == "Referrer-Policy":
            suggestions.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Configure Referrer Policy Header",
                "issue": "Referrer-Policy header is missing.",
                "remediation": (
                    "Controls how much referrer information is sent along with requests. Setting it to "
                    "'strict-origin-when-cross-origin' provides a good balance of utility and privacy.\n"
                    "For Nginx:"
                ),
                "snippet": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
            })

    # 3. Broken Links Checks
    broken_links = [p for p in crawl_results if p.get("is_broken", False)]
    if broken_links:
        broken_urls = [p["url"] for p in broken_links]
        suggestions.append({
            "category": "SEO",
            "severity": "High",
            "title": f"Fix {len(broken_links)} Broken Internal Links",
            "issue": f"Detected broken pages/links returning 4xx/5xx errors: {', '.join(broken_urls[:3])}",
            "remediation": (
                "Broken links harm user experience and SEO crawls. Update or remove the anchor tags (`<a href='...'>`) "
                "pointing to these dead paths. If the files have moved, implement 301 redirects in your server config."
            ),
            "snippet": f"# Sample Nginx 301 redirect\nrewrite ^/old-path$ /new-path permanent;"
        })

    # 4. Latency & Infrastructure Checks
    ttfb = network_results.get("ttfb_ms")
    if ttfb is not None:
        if ttfb > 600.0:
            suggestions.append({
                "category": "Infrastructure",
                "severity": "Medium",
                "title": "Optimize Server Response Time (TTFB)",
                "issue": f"Time to First Byte (TTFB) is slow: {ttfb:.1f}ms (recommended is < 200ms).",
                "remediation": (
                    "Slow TTFB points to slow backend processing, database query overhead, or network delays. "
                    "Implement server-side page caching (e.g. Nginx FastCGI cache, Redis), optimize database indexes, "
                    "and utilize a Content Delivery Network (CDN) like Cloudflare to cache static assets closer to users."
                ),
                "snippet": None
            })
        elif ttfb > 200.0:
            suggestions.append({
                "category": "Infrastructure",
                "severity": "Low",
                "title": "Improve Server Latency (TTFB)",
                "issue": f"Time to First Byte (TTFB) is {ttfb:.1f}ms (operational baseline is < 200ms).",
                "remediation": (
                    "Optimize server software configuration, upgrade script resources, and verify server resource usage (CPU/RAM)."
                ),
                "snippet": None
            })

    # DNS check
    dns_time = network_results.get("dns_resolution_time_ms")
    if dns_time is not None and dns_time > 150.0:
        suggestions.append({
            "category": "Infrastructure",
            "severity": "Medium",
            "title": "Accelerate DNS Resolution Speed",
            "issue": f"DNS resolution took {dns_time:.1f}ms (should be < 150ms).",
            "remediation": (
                "Your domain nameservers are slow to resolve queries. Migrate your DNS management to a high-performance, "
                "distributed DNS provider (like Cloudflare, AWS Route 53, or Google Cloud DNS) for faster initial lookups."
            ),
            "snippet": None
        })

    # 5. Core Web Vitals Performance Checks
    if perf_profile.get("status") == "success":
        fcp = perf_profile.get("fcp", {}).get("value_ms")
        lcp = perf_profile.get("lcp", {}).get("value_ms")
        cls = perf_profile.get("cls", {}).get("value")

        if lcp and lcp > 2500.0:
            suggestions.append({
                "category": "Performance",
                "severity": "Medium",
                "title": "Optimize Largest Contentful Paint (LCP)",
                "issue": f"Largest Contentful Paint takes {lcp/1000.0:.2f}s (should load under 2.5 seconds).",
                "remediation": (
                    "LCP measures when the main content of a page has loaded. Optimize it by compressing large hero images, "
                    "using modern formats (WebP/AVIF), deferring non-critical JS/CSS, and preloading critical layout assets."
                ),
                "snippet": '<link rel="preload" href="/images/hero.webp" as="image" type="image/webp">'
            })

        if cls and cls > 0.1:
            suggestions.append({
                "category": "Performance",
                "severity": "Medium",
                "title": "Minimize Cumulative Layout Shift (CLS)",
                "issue": f"Cumulative Layout Shift is high: {cls:.3f} (recommended target is < 0.1).",
                "remediation": (
                    "CLS measures visual stability. Layout shifts occur when elements shift positions. "
                    "Ensure all image and video tags have explicit width and height attributes, reserve spaces for dynamic "
                    "ad insertions, and avoid inserting content above existing content."
                ),
                "snippet": '<img src="photo.webp" width="800" height="600" alt="Description" style="max-width: 100%; height: auto;">'
            })

    # 6. SEO & HTML Structure Checks
    titles = []
    descriptions = []
    
    missing_title_pages = []
    missing_desc_pages = []
    missing_canonical_pages = []
    total_missing_alts = 0
    pages_with_alt_issues = []
    h1_anomalies_pages = []

    for page in crawl_results:
        if page.get("is_broken", False):
            continue

        url = page.get("url")
        title = page.get("title")
        desc = page.get("meta_description")
        h1_count = page.get("h1_count", 0)
        missing_alts = page.get("missing_alt_images_count", 0)

        if not title or title.strip() == "":
            missing_title_pages.append(url)
        else:
            titles.append(title.strip())

        if not desc or desc.strip() == "":
            missing_desc_pages.append(url)
        else:
            descriptions.append(desc.strip())

        if page.get("missing_canonical", False):
            missing_canonical_pages.append(url)

        if missing_alts > 0:
            total_missing_alts += missing_alts
            pages_with_alt_issues.append((url, missing_alts))

        if h1_count == 0 or h1_count > 1:
            h1_anomalies_pages.append((url, h1_count))

    # Add suggestions for SEO
    if missing_title_pages:
        suggestions.append({
            "category": "SEO",
            "severity": "High",
            "title": f"Add Missing Title Tags on {len(missing_title_pages)} Pages",
            "issue": f"The following pages are missing a `<title>` tag: {', '.join(missing_title_pages[:3])}",
            "remediation": (
                "Title tags are critical for search engine results page (SERP) snippets and browser tab labels. "
                "Add a descriptive `<title>` tag inside the `<head>` section. Ideal length is 50-60 characters."
            ),
            "snippet": "<title>Descriptive Keywords - Brand Name</title>"
        })

    if missing_desc_pages:
        suggestions.append({
            "category": "SEO",
            "severity": "Medium",
            "title": f"Add Missing Meta Descriptions on {len(missing_desc_pages)} Pages",
            "issue": f"The following pages are missing a `<meta name=\"description\">` tag: {', '.join(missing_desc_pages[:3])}",
            "remediation": (
                "Meta descriptions provide search engine users with a summary of the page contents in SERPs. "
                "Add `<meta name='description' content='...'>` inside `<head>`. Ideal length is 150-160 characters."
            ),
            "snippet": '<meta name="description" content="Write a compelling 155-character summary of your page.">'
        })

    if missing_canonical_pages:
        suggestions.append({
            "category": "SEO",
            "severity": "Low",
            "title": f"Add Canonical Tags on {len(missing_canonical_pages)} Pages",
            "issue": f"Canonical links are missing on: {', '.join(missing_canonical_pages[:3])}",
            "remediation": (
                "Canonical tags protect your website from duplicate content indexing penalties by indicating the primary "
                "original source URL of the page. Add `<link rel='canonical' href='...'>` inside the `<head>`."
            ),
            "snippet": '<link rel="canonical" href="https://example.com/canonical-page-url">'
        })

    if total_missing_alts > 0:
        suggestions.append({
            "category": "SEO",
            "severity": "Low",
            "title": f"Define Alt Attributes for {total_missing_alts} Images",
            "issue": f"Images are missing descriptive alternative text attributes.",
            "remediation": (
                "Alternative text (alt attributes) improves accessibility for screen readers and allows search engines "
                "to understand and index image contents. Add the `alt` attribute describing the image context."
            ),
            "snippet": '<img src="/assets/logo.png" alt="Company Logo in blue styling">'
        })

    if h1_anomalies_pages:
        anom_urls = [item[0] for item in h1_anomalies_pages]
        suggestions.append({
            "category": "SEO",
            "severity": "Low",
            "title": f"Fix H1 Tag Structure Anomalies on {len(h1_anomalies_pages)} Pages",
            "issue": f"Pages with either zero or multiple `<h1>` tags: {', '.join(anom_urls[:3])}",
            "remediation": (
                "Correct semantic HTML document structure requires exactly one `<h1>` header tag per page to represent "
                "the primary title. Demote secondary titles to `<h2>` or `<h3>` tags."
            ),
            "snippet": "<h1>Primary Page Title</h1>\n<h2>Sub-Heading Section</h2>"
        })

    # Duplicate titles check
    title_counts = {}
    for t in titles:
        title_counts[t] = title_counts.get(t, 0) + 1
    dup_titles_count = sum(c - 1 for c in title_counts.values() if c > 1)
    if dup_titles_count > 0:
        suggestions.append({
            "category": "SEO",
            "severity": "Medium",
            "title": f"Resolve {dup_titles_count} Duplicate Title Tags",
            "issue": "Identical `<title>` tags were found across multiple pages.",
            "remediation": (
                "Search engines require unique title tags for each indexed page to accurately represent content differences. "
                "Rewrite duplicate titles to include distinct keywords specific to each page context."
            ),
            "snippet": None
        })

    # Duplicate descriptions check
    desc_counts = {}
    for d in descriptions:
        desc_counts[d] = desc_counts.get(d, 0) + 1
    dup_descs_count = sum(c - 1 for c in desc_counts.values() if c > 1)
    if dup_descs_count > 0:
        suggestions.append({
            "category": "SEO",
            "severity": "Low",
            "title": f"Resolve {dup_descs_count} Duplicate Meta Descriptions",
            "issue": "Identical `<meta name=\"description\">` tags were found across multiple pages.",
            "remediation": (
                "Ensure each crawled page has a distinct meta description tag summarizing its unique purpose."
            ),
            "snippet": None
        })

    return suggestions
