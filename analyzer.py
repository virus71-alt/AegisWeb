"""
Website Health Analyzer CLI Entrypoint.

Orchestrates crawling, network latency measurement, DNS validation,
SSL certificate analysis, security header scanning, performance profiling,
health scoring, persistence, and CLI presentation.
"""

import argparse
import asyncio
import sys
import os
import datetime
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.theme import Theme
from rich.rule import Rule

# Import modular components
from db import DatabaseManager
from crawler import AsyncWebCrawler
from network import NetworkProfiler
from security import SecurityScanner
from performance import PerformanceAgent
from scoring import calculate_health_score

# Custom color theme for premium design feel
custom_theme = Theme({
    "info": "dim cyan",
    "warning": "magenta",
    "danger": "bold red",
    "success": "bold green",
    "score_high": "bold green",
    "score_mid": "bold yellow",
    "score_low": "bold red"
})

console = Console(theme=custom_theme)


def get_score_style(score: float) -> str:
    """Returns the theme style corresponding to the score range."""
    if score >= 90.0:
        return "score_high"
    elif score >= 70.0:
        return "score_mid"
    return "score_low"


async def run_audit(args: argparse.Namespace) -> int:
    """
    Executes a comprehensive website health audit.
    """
    url = args.url
    # Validate URL structure
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        console.print(f"[danger]Error:[/danger] Invalid URL format: '{url}'. Please include scheme (e.g. https://)")
        return 1

    console.print(Panel(
        f"[bold cyan]Starting Deep Health Audit for:[/bold cyan] {url}\n"
        f"[dim]Max Depth: {args.depth} | Max Pages: {args.max_pages} | Database: {args.db}[/dim]",
        title="AegisWeb Health Analyzer",
        border_style="cyan"
    ))

    # Initialize Database
    db_mgr = DatabaseManager(args.db)
    await db_mgr.init_db_async()
    site_id = await db_mgr.get_or_create_site(url)

    # 1. Run Async Web Crawler with active visual progress
    console.print(Rule("[bold magenta]1. Page Crawl & Link Validation[/bold magenta]"))
    crawler = AsyncWebCrawler(
        start_url=url,
        max_depth=args.depth,
        max_pages=args.max_pages
    )

    crawl_results = []
    external_links = set()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console
    ) as progress:
        crawl_task = progress.add_task("[cyan]Crawling website...", total=args.max_pages)
        
        def update_progress(status: str, queue_size: int, crawled_count: int):
            # Calculate a realistic percentage based on current progress
            # Since total pages can be less than max_pages, we update relative values
            progress.update(
                crawl_task,
                completed=crawled_count,
                description=f"[cyan]{status} (Queue size: {queue_size}, Crawled: {crawled_count})"
            )

        crawl_results, external_links = await crawler.crawl(progress_callback=update_progress)
        # Final update
        progress.update(crawl_task, completed=len(crawler.crawled_urls), total=len(crawler.crawled_urls))

    console.print(f"[success]Crawl complete![/success] Audited [bold]{len(crawl_results)}[/bold] internal link/page records.")

    # 2. Run Network latency & DNS profiles
    console.print(Rule("[bold magenta]2. Network & DNS Infrastructure[/bold magenta]"))
    network_profiler = NetworkProfiler(url)
    
    with console.status("[cyan]Profiling network latency & TTFB...", spinner="dots"):
        latency_profile = await network_profiler.profile_latency()
    
    with console.status("[cyan]Resolving DNS records (A, AAAA, MX, NS, TXT)...", spinner="dots"):
        dns_profile = await network_profiler.verify_dns()

    # 3. Run Security auditor
    console.print(Rule("[bold magenta]3. SSL Certificate & Security Headers[/bold magenta]"))
    security_scanner = SecurityScanner(url)

    with console.status("[cyan]Auditing SSL Certificate validity...", spinner="dots"):
        ssl_profile = await security_scanner.audit_ssl_certificate()

    with console.status("[cyan]Scanning homepage security headers...", spinner="dots"):
        security_headers = await security_scanner.audit_security_headers()

    # 4. PageSpeed Insights Core Web Vitals (optional Performance Metrics Agent)
    console.print(Rule("[bold magenta]4. Performance Metrics (Google PageSpeed)[/bold magenta]"))
    perf_agent = PerformanceAgent(url, api_key=args.api_key)
    
    if args.api_key:
        with console.status("[cyan]Fetching Google PageSpeed Core Web Vitals...", spinner="dots"):
            perf_profile = await perf_agent.fetch_performance_metrics()
    else:
        # Check without key (public fallback)
        with console.status("[cyan]Fetching Google PageSpeed (No API key; subject to rate limiting)...", spinner="dots"):
            perf_profile = await perf_agent.fetch_performance_metrics()

    # Calculate overall health score
    score, deductions = calculate_health_score(
        crawl_results=crawl_results,
        network_results={
            "ssl_expiry_days": ssl_profile.get("ssl_expiry_days"),
        },
        security_headers=security_headers
    )

    # Save to Database in a transaction
    audit_id = await db_mgr.create_audit(site_id, score)
    db_network_results = {
        "ttfb_ms": latency_profile.get("ttfb_ms"),
        "dns_resolution_time_ms": dns_profile.get("total_resolution_time_ms"),
        "ssl_expiry_days": ssl_profile.get("ssl_expiry_days")
    }
    await db_mgr.save_audit_details(
        audit_id=audit_id,
        crawl_results=crawl_results,
        network_results=db_network_results,
        security_headers=security_headers
    )

    # Output detailed report using Rich
    console.print("\n")
    score_style = get_score_style(score)
    console.print(Panel(
        f"[bold white]Overall Health Score:[/bold white] [{score_style}]{score:.1f}%[/{score_style}]",
        title="AUDIT SUMMARY REPORT",
        subtitle=f"Audit ID: {audit_id} | Timestamp: {db_network_results.get('timestamp', 'Just Now')}",
        border_style=score_style,
        expand=True
    ))

    # Output Deductions Table
    if deductions:
        deductions_table = Table(title="Deductions Summary", show_header=True, header_style="bold red", expand=True)
        deductions_table.add_column("Category", style="cyan", width=20)
        deductions_table.add_column("Deduction", style="bold red", justify="right", width=15)
        deductions_table.add_column("Details", style="white")

        for category, info in deductions.items():
            deductions_table.add_row(
                category.replace("_", " ").title(),
                f"-{info['penalty']:.1f}%",
                info["description"]
            )
        console.print(deductions_table)
    else:
        console.print("[success]Perfect Score! No health deductions applied.[/success]")

    # Infrastructure & SSL Output
    infra_table = Table(title="Infrastructure & DNS Status", show_header=True, header_style="bold magenta", expand=True)
    infra_table.add_column("Metric/Record", style="cyan")
    infra_table.add_column("Value / Performance", style="white")
    infra_table.add_column("Status", style="bold")

    # Latencies
    ttfb = latency_profile.get("ttfb_ms")
    ttfb_str = f"{ttfb} ms" if ttfb and ttfb > 0 else "N/A"
    ttfb_status = "[success]Good[/success]" if ttfb and ttfb < 200 else "[warning]Slow (>200ms)[/warning]"
    if ttfb == -1.0:
        ttfb_status = "[danger]Failed[/danger]"
    infra_table.add_row("Time to First Byte (TTFB)", ttfb_str, ttfb_status)

    rtt = latency_profile.get("rtt_ms")
    rtt_str = f"{rtt} ms" if rtt and rtt > 0 else "N/A"
    rtt_status = "[success]Good[/success]" if rtt and rtt < 600 else "[warning]Slow[/warning]"
    if rtt == -1.0:
        rtt_status = "[danger]Failed[/danger]"
    infra_table.add_row("Round-Trip Response Time", rtt_str, rtt_status)

    # DNS Resolution time
    dns_time = dns_profile.get("total_resolution_time_ms", 0.0)
    dns_status = "[success]Fast[/success]" if dns_time < 150 else "[warning]Slow[/warning]"
    infra_table.add_row("DNS A-Record Resolution Time", f"{dns_time:.2f} ms", dns_status)

    # SSL Expiry
    ssl_days = ssl_profile.get("ssl_expiry_days")
    if ssl_days is not None:
        if ssl_days < 0:
            ssl_status = "[danger]Expired[/danger]"
            ssl_val = f"Expired"
        elif ssl_days < 30:
            ssl_status = "[danger]Critical (<30d)[/danger]"
            ssl_val = f"{ssl_days} days remaining"
        else:
            ssl_status = "[success]Secure[/success]"
            ssl_val = f"{ssl_days} days remaining"
    else:
        ssl_status = "[warning]Missing / No HTTPS[/warning]"
        ssl_val = "N/A"
    infra_table.add_row("SSL Certificate Expiry", ssl_val, ssl_status)
    infra_table.add_row("SSL Issuer", ssl_profile.get("issuer") or "N/A", "[info]Info[/info]")
    infra_table.add_row("SSL Signature Algorithm", ssl_profile.get("signature_algorithm") or "N/A", "[info]Info[/info]")

    console.print(infra_table)

    # DNS records expansion
    dns_records_table = Table(title="Queried DNS Records", show_header=True, header_style="bold blue")
    dns_records_table.add_column("Type", style="cyan")
    dns_records_table.add_column("Records", style="white")
    dns_records_table.add_column("Resolution Time", style="dim white")
    for rtype, info in dns_profile["records"].items():
        vals = ", ".join(info["values"][:3]) + ("..." if len(info["values"]) > 3 else "")
        err = f"[danger]{info['error']}[/danger]" if info["error"] else "OK"
        dns_records_table.add_row(rtype, vals or err, f"{info['duration_ms']:.1f}ms")
    console.print(dns_records_table)

    # Security Headers Output
    headers_table = Table(title="Security Headers Analysis", show_header=True, header_style="bold yellow")
    headers_table.add_column("Header Name", style="cyan")
    headers_table.add_column("Present", style="bold")
    headers_table.add_column("Value / Recommendation", style="white")

    for header in security_headers:
        present = "[success]Yes[/success]" if header["is_present"] else "[danger]No[/danger]"
        val = header["value"] or "Missing header! We recommend implementing this to protect your users."
        headers_table.add_row(header["header_name"], present, val)
    console.print(headers_table)

    # Core Web Vitals Output
    cv_table = Table(title="Performance Metrics (Lighthouse / Web Vitals)", show_header=True, header_style="bold green")
    cv_table.add_column("Metric Name", style="cyan")
    cv_table.add_column("Value", style="white")
    cv_table.add_column("Status", style="bold")

    if perf_profile.get("status") == "success":
        # FCP
        fcp = perf_profile.get("fcp", {})
        fcp_val = fcp.get("value_ms", 0) or 0
        fcp_status = "[success]Good[/success]" if fcp_val < 1800 else ("[warning]Needs Improvement[/warning]" if fcp_val < 3000 else "[danger]Poor[/danger]")
        cv_table.add_row("First Contentful Paint (FCP)", fcp.get("display") or "N/A", fcp_status)

        # LCP
        lcp = perf_profile.get("lcp", {})
        lcp_val = lcp.get("value_ms", 0) or 0
        lcp_status = "[success]Good[/success]" if lcp_val < 2500 else ("[warning]Needs Improvement[/warning]" if lcp_val < 4000 else "[danger]Poor[/danger]")
        cv_table.add_row("Largest Contentful Paint (LCP)", lcp.get("display") or "N/A", lcp_status)

        # CLS
        cls = perf_profile.get("cls", {})
        cls_val = cls.get("value", 0.0) or 0.0
        cls_status = "[success]Good[/success]" if cls_val < 0.1 else ("[warning]Needs Improvement[/warning]" if cls_val < 0.25 else "[danger]Poor[/danger]")
        cv_table.add_row("Cumulative Layout Shift (CLS)", cls.get("display") or "N/A", cls_status)

        raw_perf_score = perf_profile.get("score")
        perf_score_str = f"{raw_perf_score}%" if raw_perf_score else "N/A"
        cv_table.add_row("Lighthouse Performance Score", perf_score_str, "[info]Info[/info]")
    else:
        error_msg = perf_profile.get("error") or "Lighthouse audit skipped or rate limited."
        cv_table.add_row("Status", "[warning]Not Available[/warning]", f"[dim]{error_msg}[/dim]")
    console.print(cv_table)

    # SEO & Crawl details
    seo_table = Table(title="SEO & Structure Analysis", show_header=True, header_style="bold cyan")
    seo_table.add_column("Page URL", style="cyan")
    seo_table.add_column("Title Tag", style="white")
    seo_table.add_column("Meta Description", style="white")
    seo_table.add_column("H1", style="white", justify="center")
    seo_table.add_column("Canonical", style="white")
    seo_table.add_column("Missing Alts", style="warning", justify="center")

    broken_pages = []

    for page in crawl_results:
        if page.get("is_broken", False):
            broken_pages.append(page)
            continue

        title = page.get("title") or "[warning]Missing[/warning]"
        desc = page.get("meta_description") or "[warning]Missing[/warning]"
        
        # Check canonical
        canonical_status = "[success]OK[/success]" if not page.get("missing_canonical", False) else "[warning]Missing[/warning]"
        
        # Format H1 count
        h1 = str(page.get("h1_count", 0))
        if page.get("h1_count", 0) == 0:
            h1 = "[warning]0[/warning]"
        elif page.get("h1_count", 0) > 1:
            h1 = f"[warning]{h1}[/warning]"

        seo_table.add_row(
            page.get("url"),
            title[:40] + ("..." if len(title) > 40 else ""),
            desc[:40] + ("..." if len(desc) > 40 else ""),
            h1,
            canonical_status,
            str(page.get("missing_alt_images_count", 0))
        )
    console.print(seo_table)

    # Broken links table
    if broken_pages:
        broken_table = Table(title="Broken Links Detected", show_header=True, header_style="bold red")
        broken_table.add_column("Broken URL", style="cyan")
        broken_table.add_column("Status Code", style="bold red", justify="center")
        broken_table.add_column("Redirects", style="white", justify="center")

        for bp in broken_pages:
            broken_table.add_row(
                bp.get("url"),
                str(bp.get("status_code")),
                str(bp.get("redirect_chain_length", 0))
            )
        console.print(broken_table)

    # 5. Export result to Markdown file inside result/<website_name> folder
    # website name from url netloc
    parsed_url = urlparse(url)
    website_name = parsed_url.netloc or parsed_url.path
    if ":" in website_name:
        website_name = website_name.split(":")[0]
    # sanitize website name for filesystem
    website_name = "".join(c for c in website_name if c.isalnum() or c in ".-_").strip()

    # Form timestamp filename
    current_time = datetime.datetime.now()
    filename = current_time.strftime("%Y-%m-%d_%H-%M-%S") + ".md"
    result_dir = os.path.join("result", website_name)
    os.makedirs(result_dir, exist_ok=True)
    filepath = os.path.join(result_dir, filename)

    # Helper function to render MD tables
    def to_markdown_table(headers: List[str], rows: List[List[Any]]) -> str:
        md = "| " + " | ".join(headers) + " |\n"
        md += "| " + " | ".join(["---"] * len(headers)) + " |\n"
        for r in rows:
            md += "| " + " | ".join(str(val).replace("\n", " ") for val in r) + " |\n"
        return md

    md_content = f"# Website Health Audit Report\n\n"
    md_content += f"- **Target URL**: {url}\n"
    md_content += f"- **Audit Date/Time**: {current_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    md_content += f"- **Audit ID**: {audit_id}\n"
    md_content += f"- **Overall Health Score**: **{score:.1f}%**\n\n"

    # Deductions
    md_content += "## Deductions Summary\n\n"
    if deductions:
        ded_headers = ["Category", "Deduction", "Details"]
        ded_rows = []
        for category, info in deductions.items():
            ded_rows.append([
                category.replace("_", " ").title(),
                f"-{info['penalty']:.1f}%",
                info["description"]
            ])
        md_content += to_markdown_table(ded_headers, ded_rows) + "\n"
    else:
        md_content += "No health deductions applied! Perfect score.\n\n"

    # Infrastructure
    md_content += "## Infrastructure & DNS Status\n\n"
    infra_headers = ["Metric/Record", "Value / Performance", "Status"]
    infra_rows = [
        ["Time to First Byte (TTFB)", f"{ttfb} ms" if ttfb and ttfb > 0 else "N/A", "Good" if ttfb and ttfb < 200 else "Slow"],
        ["Round-Trip Response Time", f"{rtt} ms" if rtt and rtt > 0 else "N/A", "Good" if rtt and rtt < 600 else "Slow"],
        ["DNS A-Record Resolution Time", f"{dns_time:.2f} ms", "Fast" if dns_time < 150 else "Slow"],
        ["SSL Certificate Expiry", ssl_val, ssl_status.replace("[success]", "").replace("[/success]", "").replace("[danger]", "").replace("[/danger]", "").replace("[warning]", "").replace("[/warning]", "")],
        ["SSL Issuer", ssl_profile.get("issuer") or "N/A", "Info"],
        ["SSL Signature Algorithm", ssl_profile.get("signature_algorithm") or "N/A", "Info"]
    ]
    md_content += to_markdown_table(infra_headers, infra_rows) + "\n"

    # DNS records
    md_content += "## Queried DNS Records\n\n"
    dns_headers = ["Type", "Records", "Resolution Time"]
    dns_rows = []
    for rtype, info in dns_profile["records"].items():
        vals = ", ".join(info["values"])
        err = info["error"] or "OK"
        dns_rows.append([rtype, vals or err, f"{info['duration_ms']:.1f}ms"])
    md_content += to_markdown_table(dns_headers, dns_rows) + "\n"

    # Security headers
    md_content += "## Security Headers Analysis\n\n"
    sh_headers = ["Header Name", "Present", "Value / Recommendation"]
    sh_rows = []
    for header in security_headers:
        sh_rows.append([
            header["header_name"],
            "Yes" if header["is_present"] else "No",
            header["value"] or "Missing header! We recommend implementing this to protect your users."
        ])
    md_content += to_markdown_table(sh_headers, sh_rows) + "\n"

    # Performance
    md_content += "## Performance Metrics (Google PageSpeed API)\n\n"
    if perf_profile.get("status") == "success":
        perf_headers = ["Metric Name", "Value", "Status"]
        fcp_data = perf_profile.get("fcp", {})
        lcp_data = perf_profile.get("lcp", {})
        cls_data = perf_profile.get("cls", {})
        perf_rows = [
            ["First Contentful Paint (FCP)", fcp_data.get("display") or "N/A", "Good" if fcp_data.get("value_ms", 9999) < 1800 else "Poor"],
            ["Largest Contentful Paint (LCP)", lcp_data.get("display") or "N/A", "Good" if lcp_data.get("value_ms", 9999) < 2500 else "Poor"],
            ["Cumulative Layout Shift (CLS)", cls_data.get("display") or "N/A", "Good" if cls_data.get("value", 1.0) < 0.1 else "Poor"],
            ["Lighthouse Performance Score", f"{perf_profile.get('score')}%" if perf_profile.get('score') else "N/A", "Info"]
        ]
        md_content += to_markdown_table(perf_headers, perf_rows) + "\n"
    else:
        err = perf_profile.get("error") or "Lighthouse audit skipped or rate limited."
        md_content += f"Lighthouse performance status: **Not Available** ({err})\n\n"

    # SEO & Structure
    md_content += "## SEO & Structure Analysis\n\n"
    seo_headers = ["Page URL", "Title Tag", "Meta Description", "H1 Count", "Canonical", "Missing Image Alts"]
    seo_rows = []
    for page in crawl_results:
        if page.get("is_broken", False):
            continue
        seo_rows.append([
            page.get("url"),
            page.get("title") or "Missing",
            page.get("meta_description") or "Missing",
            str(page.get("h1_count", 0)),
            "OK" if not page.get("missing_canonical", False) else "Missing",
            str(page.get("missing_alt_images_count", 0))
        ])
    md_content += to_markdown_table(seo_headers, seo_rows) + "\n"

    # Broken links
    if broken_pages:
        md_content += "## Broken Links Detected\n\n"
        bl_headers = ["Broken URL", "Status Code", "Redirects"]
        bl_rows = []
        for bp in broken_pages:
            bl_rows.append([
                bp.get("url"),
                str(bp.get("status_code")),
                str(bp.get("redirect_chain_length", 0))
            ])
        md_content += to_markdown_table(bl_headers, bl_rows) + "\n"

    # Write report file
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(md_content)
        console.print(f"\n[success]Audit report saved to file:[/success] {filepath}")
    except Exception as e:
        console.print(f"\n[danger]Failed to save report file:[/danger] {str(e)}")

    return 0


async def show_history(args: argparse.Namespace) -> int:
    """
    Displays the historical health score records for monitored domains.
    """
    db_mgr = DatabaseManager(args.db)
    history = await db_mgr.get_history(url=args.url)

    if not history:
        msg = f"No historical records found in '{args.db}'"
        if args.url:
            msg += f" for URL '{args.url}'"
        console.print(f"[warning]{msg}[/warning]")
        return 0

    table = Table(title="Website Audit History Tracker", show_header=True, header_style="bold cyan", expand=True)
    table.add_column("Audit ID", style="dim white", width=10)
    table.add_column("Target URL", style="cyan")
    table.add_column("Timestamp", style="white")
    table.add_column("Pages Crawled", style="white", justify="center")
    table.add_column("Broken Links", style="bold red", justify="center")
    table.add_column("SSL Expiry (Days)", style="white", justify="center")
    table.add_column("Health Score", style="bold", justify="right")

    for item in history:
        score = item["overall_health_score"]
        score_style = get_score_style(score)
        
        ssl_exp = item["ssl_expiry_days"]
        if ssl_exp is not None:
            if ssl_exp < 0:
                ssl_exp_str = "[danger]Expired[/danger]"
            elif ssl_exp < 30:
                ssl_exp_str = f"[danger]{ssl_exp}[/danger]"
            else:
                ssl_exp_str = f"[success]{ssl_exp}[/success]"
        else:
            ssl_exp_str = "N/A"

        table.add_row(
            str(item["audit_id"]),
            item["url"],
            item["timestamp"],
            str(item["total_pages_crawled"]),
            str(item["broken_links_count"]),
            ssl_exp_str,
            f"[{score_style}]{score:.1f}%[/{score_style}]"
        )

    console.print(table)
    return 0


def main():
    """
    Synchronous CLI parser entrypoint.
    """
    parser = argparse.ArgumentParser(
        description="AegisWeb: Comprehensive Website Health & Security Analyzer (Asynchronous CLI Tool)"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Initiate a deep audit on a target website")
    run_parser.add_argument("--url", required=True, help="Target website URL (e.g., https://example.com)")
    run_parser.add_argument("--depth", type=int, default=3, help="Max link crawl depth (default: 3)")
    run_parser.add_argument("--max-pages", type=int, default=100, help="Max page limit count (default: 100)")
    run_parser.add_argument("--api-key", help="Optional Google PageSpeed Insights API Key")
    run_parser.add_argument("--db", default="analyzer.db", help="SQLite3 database file path (default: analyzer.db)")

    # History subcommand
    history_parser = subparsers.add_parser("history", help="Retrieve historical website audit scores")
    history_parser.add_argument("--url", help="Filter history by target website URL")
    history_parser.add_argument("--db", default="analyzer.db", help="SQLite3 database file path (default: analyzer.db)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        if args.command == "run":
            # Enable Windows ProactorEventLoop if needed
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
            
            sys.exit(asyncio.run(run_audit(args)))
            
        elif args.command == "history":
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
                
            sys.exit(asyncio.run(show_history(args)))
            
    except KeyboardInterrupt:
        console.print("\n[warning]Process interrupted by user. Exiting...[/warning]")
        sys.exit(1)


if __name__ == "__main__":
    main()
