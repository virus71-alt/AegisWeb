"""
Health Scoring Engine Module for Website Health Analyzer.

Computes a health score from 0.0 to 100.0 using a weighted deduction model
and returns a detailed breakdown of deductions.
"""

from typing import Dict, List, Any, Tuple


def calculate_health_score(
    crawl_results: List[Dict[str, Any]],
    network_results: Dict[str, Any],
    security_headers: List[Dict[str, Any]]
) -> Tuple[float, Dict[str, Any]]:
    """
    Calculates overall website health score based on crawl, network, and security findings.

    Deduction rules:
    - Broken internal links (404s/500s/etc.): -5% per occurrence, capped at -30%.
    - Missing security headers: -3% per missing header (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
    - SSL expiring in < 30 days: Critical penalty of -25%.
    - SEO anomalies: -0.5% per instance.
      Anomalies include:
      - Missing page title
      - Missing meta description
      - Duplicate titles across crawled pages
      - Duplicate descriptions across crawled pages
      - Missing canonical tags
      - Missing image alt attributes (each count is one anomaly)

    Returns:
        Tuple[float, Dict[str, Any]]: (overall_score, deduction_breakdown)
    """
    score = 100.0
    deductions = {}

    # 1. Broken internal links penalty
    broken_links = [p for p in crawl_results if p.get("is_broken", False)]
    broken_count = len(broken_links)
    broken_penalty = min(30.0, broken_count * 5.0)
    if broken_penalty > 0:
        deductions["broken_links"] = {
            "count": broken_count,
            "penalty": broken_penalty,
            "description": f"Broken internal links (capped at -30%): {broken_count} found (-{broken_penalty}%)"
        }
    score -= broken_penalty

    # 2. Missing security headers penalty
    missing_headers = [h for h in security_headers if not h.get("is_present", False)]
    missing_headers_count = len(missing_headers)
    headers_penalty = missing_headers_count * 3.0
    if headers_penalty > 0:
        header_names = [h.get("header_name") for h in missing_headers]
        deductions["security_headers"] = {
            "count": missing_headers_count,
            "penalty": headers_penalty,
            "description": f"Missing security headers: {missing_headers_count} missing ({', '.join(header_names)}) (-{headers_penalty}%)"
        }
    score -= headers_penalty

    # 3. SSL Expiring < 30 days penalty
    ssl_expiry = network_results.get("ssl_expiry_days")
    ssl_penalty = 0.0
    if ssl_expiry is not None:
        if ssl_expiry < 0:
            ssl_penalty = 25.0
            deductions["ssl_status"] = {
                "days": ssl_expiry,
                "penalty": ssl_penalty,
                "description": f"SSL Certificate has already expired! (-{ssl_penalty}%)"
            }
        elif ssl_expiry < 30:
            ssl_penalty = 25.0
            deductions["ssl_status"] = {
                "days": ssl_expiry,
                "penalty": ssl_penalty,
                "description": f"SSL Certificate expires in {ssl_expiry} days (< 30 days)! (-{ssl_penalty}%)"
            }
    else:
        # SSL details are missing or error connecting (could be handled as a warning or standard check)
        pass
    score -= ssl_penalty

    # 4. SEO & Structure anomalies
    # Let's count anomalies
    seo_anomalies_count = 0
    seo_details = []

    # Check for missing titles, descriptions, canonicals, alts
    titles = []
    descriptions = []
    
    missing_title_count = 0
    missing_desc_count = 0
    missing_canonical_count = 0
    total_missing_alts = 0

    for page in crawl_results:
        # We only look at non-broken pages for structural/SEO elements
        if page.get("is_broken", False):
            continue

        title = page.get("title")
        desc = page.get("meta_description")
        
        # Missing title
        if not title or title.strip() == "":
            missing_title_count += 1
            seo_anomalies_count += 1
        else:
            titles.append(title.strip())

        # Missing meta description
        if not desc or desc.strip() == "":
            missing_desc_count += 1
            seo_anomalies_count += 1
        else:
            descriptions.append(desc.strip())

        # Missing canonical tag (can be passed in crawl result dictionary)
        if page.get("missing_canonical", False):
            missing_canonical_count += 1
            seo_anomalies_count += 1

        # Missing image alt count
        missing_alts = page.get("missing_alt_images_count", 0)
        if missing_alts > 0:
            total_missing_alts += missing_alts
            seo_anomalies_count += missing_alts

    # Check duplicate titles
    title_counts = {}
    for t in titles:
        title_counts[t] = title_counts.get(t, 0) + 1
    duplicate_titles = sum(count - 1 for count in title_counts.values() if count > 1)
    if duplicate_titles > 0:
        seo_anomalies_count += duplicate_titles
        seo_details.append(f"{duplicate_titles} duplicate titles")

    # Check duplicate descriptions
    desc_counts = {}
    for d in descriptions:
        desc_counts[d] = desc_counts.get(d, 0) + 1
    duplicate_descs = sum(count - 1 for count in desc_counts.values() if count > 1)
    if duplicate_descs > 0:
        seo_anomalies_count += duplicate_descs
        seo_details.append(f"{duplicate_descs} duplicate descriptions")

    # Format other details
    if missing_title_count > 0:
        seo_details.append(f"{missing_title_count} pages missing title")
    if missing_desc_count > 0:
        seo_details.append(f"{missing_desc_count} pages missing description")
    if missing_canonical_count > 0:
        seo_details.append(f"{missing_canonical_count} pages missing canonical link")
    if total_missing_alts > 0:
        seo_details.append(f"{total_missing_alts} images missing alt text")

    seo_penalty = seo_anomalies_count * 0.5
    if seo_penalty > 0:
        deductions["seo_anomalies"] = {
            "count": seo_anomalies_count,
            "penalty": seo_penalty,
            "description": f"SEO & structural issues: {', '.join(seo_details)} (-{seo_penalty}%)"
        }
    score -= seo_penalty

    # Clamp the score between 0.0 and 100.0
    final_score = max(0.0, min(100.0, score))
    
    return round(final_score, 2), deductions
