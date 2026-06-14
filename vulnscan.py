"""
Vulnerability & Exposure Scanner Module for AegisWeb.

Performs SAFE, non-intrusive, read-only reconnaissance against a target domain to
surface common loopholes attackers exploit. Every check is a simple GET/HEAD request
(no payload injection, no fuzzing, no destructive actions) so it is appropriate for
auditing your own infrastructure.

Checks implemented:
  * Cookie security flags (Secure, HttpOnly, SameSite, __Host-/__Secure- prefixes)
  * Sensitive file / path exposure (.git, .env, backups, admin panels, status pages)
  * Directory listing enabled ("Index of /")
  * Technology / version fingerprint disclosure (Server, X-Powered-By, etc.)
  * CORS misconfiguration (reflected Origin, wildcard + credentials)
  * Content-Security-Policy weakness analysis (unsafe-inline, unsafe-eval, wildcards)
  * Extended hardening headers (Permissions-Policy, COOP, COEP, CORP)
  * HTTP -> HTTPS redirect enforcement
  * HSTS quality (max-age, includeSubDomains, preload)
  * Subresource Integrity (SRI) on third-party scripts
  * Mixed (insecure) content references on an HTTPS page
  * Missing /.well-known/security.txt disclosure policy

All findings are returned in the same shape consumed by suggestor/analyzer so they
flow straight into the console report, the Markdown export, and the AI fix-prompt.
"""

import asyncio
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, urljoin

import httpx
from bs4 import BeautifulSoup


# Common sensitive paths that should never be publicly reachable.
# (path, human label) -- kept short and high-signal to stay polite to the target.
SENSITIVE_PATHS = [
    ("/.git/config", "Exposed Git repository config"),
    ("/.git/HEAD", "Exposed Git repository metadata"),
    ("/.env", "Exposed environment/secrets file"),
    ("/.env.bak", "Exposed environment backup file"),
    ("/.svn/entries", "Exposed Subversion metadata"),
    ("/.htaccess", "Exposed Apache .htaccess file"),
    ("/.htpasswd", "Exposed credential hash file"),
    ("/wp-config.php.bak", "Exposed WordPress config backup"),
    ("/config.php.bak", "Exposed PHP config backup"),
    ("/backup.zip", "Exposed site backup archive"),
    ("/backup.sql", "Exposed database dump"),
    ("/database.sql", "Exposed database dump"),
    ("/dump.sql", "Exposed database dump"),
    ("/phpinfo.php", "Exposed phpinfo() diagnostics page"),
    ("/server-status", "Exposed Apache server-status page"),
    ("/.DS_Store", "Exposed macOS directory index file"),
    ("/.well-known/security.txt", "security.txt disclosure policy"),
]

# Headers that leak software stack / version information.
FINGERPRINT_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version",
                       "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"]

# Extended hardening headers not covered by the base SecurityScanner.
EXTENDED_HEADERS = {
    "Permissions-Policy": (
        "Restricts access to powerful browser features (camera, geolocation, microphone).",
        'add_header Permissions-Policy "geolocation=(), camera=(), microphone=()" always;'
    ),
    "Cross-Origin-Opener-Policy": (
        "Isolates your browsing context to mitigate cross-origin (Spectre-class) attacks.",
        'add_header Cross-Origin-Opener-Policy "same-origin" always;'
    ),
    "Cross-Origin-Resource-Policy": (
        "Blocks other origins from embedding your resources, limiting data leakage.",
        'add_header Cross-Origin-Resource-Policy "same-origin" always;'
    ),
}


class VulnerabilityScanner:
    """Runs safe, read-only vulnerability and exposure checks against a target."""

    def __init__(self, url: str, timeout_seconds: float = 10.0):
        self.url = url
        self.timeout = timeout_seconds

        parsed = urlparse(url)
        self.scheme = parsed.scheme if parsed.scheme in ["http", "https"] else "https"
        self.hostname = (parsed.netloc or parsed.path)
        if ":" in self.hostname:
            self.hostname = self.hostname.split(":")[0]
        self.base = f"{self.scheme}://{parsed.netloc or parsed.path}"

    async def scan(self) -> Dict[str, Any]:
        """
        Executes every check and returns a structured report.

        Returns:
            {
              "findings": [ {category, severity, title, issue, remediation, snippet, evidence}, ... ],
              "error": Optional[str]
            }
        """
        findings: List[Dict[str, Any]] = []

        # A single shared client; verify=False so a broken cert doesn't abort the audit.
        try:
            async with httpx.AsyncClient(
                verify=False,
                timeout=self.timeout,
                follow_redirects=True,
                headers={"User-Agent": "AegisWeb-VulnScanner/1.0"},
            ) as client:
                # Fetch the homepage once and reuse it for header/HTML based checks.
                try:
                    home = await client.get(self.url)
                except Exception as e:
                    return {"findings": findings, "error": f"Could not reach target: {e}"}

                findings += self._check_cookies(home)
                findings += self._check_fingerprint(home)
                findings += self._check_csp(home)
                findings += self._check_extended_headers(home)
                findings += self._check_directory_listing(home)
                findings += self._check_html_body(home)

                # Concurrent network checks.
                paths_task = self._check_sensitive_paths(client)
                cors_task = self._check_cors(client)
                redirect_task = self._check_https_redirect(client)
                hsts_findings = self._check_hsts(home)

                path_findings, cors_findings, redirect_findings = await asyncio.gather(
                    paths_task, cors_task, redirect_task
                )
                findings += path_findings + cors_findings + redirect_findings + hsts_findings
        except Exception as e:
            return {"findings": findings, "error": str(e)}

        return {"findings": findings, "error": None}

    # ------------------------------------------------------------------ #
    # Individual checks
    # ------------------------------------------------------------------ #

    def _check_cookies(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        # httpx exposes multiple Set-Cookie headers via get_list.
        set_cookies = response.headers.get_list("set-cookie")
        for raw in set_cookies:
            attrs = [p.strip().lower() for p in raw.split(";")]
            name = raw.split("=", 1)[0].strip()
            flags = attrs[1:]
            missing = []
            if "secure" not in flags:
                missing.append("Secure")
            if "httponly" not in flags:
                missing.append("HttpOnly")
            if not any(f.startswith("samesite") for f in flags):
                missing.append("SameSite")
            if missing:
                findings.append({
                    "category": "Security",
                    "severity": "Medium" if "HttpOnly" in missing or "Secure" in missing else "Low",
                    "title": f"Cookie '{name}' Missing Security Flags",
                    "issue": (
                        f"The cookie '{name}' is set without the following flag(s): {', '.join(missing)}. "
                        "Without Secure it can be sent over HTTP; without HttpOnly it is readable by "
                        "JavaScript (XSS theft); without SameSite it is vulnerable to CSRF."
                    ),
                    "remediation": (
                        "Set Secure, HttpOnly and an explicit SameSite attribute on every cookie. For "
                        "session cookies prefer the __Host- prefix, which forces Secure + path=/ + no Domain."
                    ),
                    "snippet": "Set-Cookie: __Host-session=...; Secure; HttpOnly; SameSite=Lax; Path=/",
                    "evidence": raw[:120],
                })
        return findings

    def _check_fingerprint(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        leaked = []
        for h in FINGERPRINT_HEADERS:
            val = response.headers.get(h)
            # Only flag values that actually disclose a version number or product detail.
            if val and (any(ch.isdigit() for ch in val) or h != "Server"):
                leaked.append(f"{h}: {val}")
        if leaked:
            findings.append({
                "category": "Security",
                "severity": "Low",
                "title": "Software Version / Stack Disclosure in Headers",
                "issue": (
                    "Response headers reveal your server software and versions, helping attackers "
                    "match known CVEs to your stack: " + "; ".join(leaked)
                ),
                "remediation": (
                    "Suppress or genericize version-revealing headers. In Nginx set "
                    "'server_tokens off;' and strip X-Powered-By; in Apache set "
                    "'ServerTokens Prod' and 'ServerSignature Off'."
                ),
                "snippet": 'server_tokens off;\nproxy_hide_header X-Powered-By;\nmore_clear_headers Server;',
                "evidence": "; ".join(leaked)[:160],
            })
        return findings

    def _check_csp(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        csp = response.headers.get("content-security-policy")
        if not csp:
            # Absence is already reported by the base SecurityScanner; we only grade quality here.
            return findings
        lowered = csp.lower()
        weaknesses = []
        if "'unsafe-inline'" in lowered:
            weaknesses.append("'unsafe-inline' allows inline scripts/styles (defeats most XSS protection)")
        if "'unsafe-eval'" in lowered:
            weaknesses.append("'unsafe-eval' permits eval()-based code execution")
        if "default-src *" in lowered or "script-src *" in lowered:
            weaknesses.append("wildcard '*' source lets any origin load resources")
        if "default-src" not in lowered:
            weaknesses.append("no 'default-src' fallback directive defined")
        if weaknesses:
            findings.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Weak Content-Security-Policy Configuration",
                "issue": (
                    "A CSP is present but contains weaknesses that undermine its XSS protection: "
                    + "; ".join(weaknesses)
                ),
                "remediation": (
                    "Remove 'unsafe-inline' and 'unsafe-eval'. Use nonces or hashes for required inline "
                    "scripts, define an explicit 'default-src', and avoid wildcard sources."
                ),
                "snippet": (
                    'add_header Content-Security-Policy "default-src \'self\'; '
                    "script-src 'self' 'nonce-{RANDOM}'; object-src 'none'; base-uri 'self'; "
                    'frame-ancestors \'self\'" always;'
                ),
                "evidence": csp[:160],
            })
        return findings

    def _check_extended_headers(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        for header, (purpose, snippet) in EXTENDED_HEADERS.items():
            if header.lower() not in {k.lower() for k in response.headers.keys()}:
                findings.append({
                    "category": "Security",
                    "severity": "Low",
                    "title": f"Missing {header} Header",
                    "issue": f"{header} is not set. {purpose}",
                    "remediation": f"Add the {header} response header in your server configuration.",
                    "snippet": snippet,
                    "evidence": None,
                })
        return findings

    def _check_hsts(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        if self.scheme != "https":
            return findings
        hsts = response.headers.get("strict-transport-security")
        if not hsts:
            return findings  # missing-HSTS is reported by the base scanner
        lowered = hsts.lower()
        problems = []
        # Parse max-age value.
        max_age = None
        for part in lowered.split(";"):
            part = part.strip()
            if part.startswith("max-age="):
                try:
                    max_age = int(part.split("=", 1)[1])
                except ValueError:
                    pass
        if max_age is None or max_age < 15552000:  # < 180 days
            problems.append("max-age is missing or below the recommended 6 months (15552000s)")
        if "includesubdomains" not in lowered:
            problems.append("includeSubDomains is not set, leaving subdomains unprotected")
        if "preload" not in lowered:
            problems.append("preload directive absent (not eligible for browser preload lists)")
        if problems:
            findings.append({
                "category": "Security",
                "severity": "Low",
                "title": "HSTS Policy Could Be Strengthened",
                "issue": "HSTS is enabled but: " + "; ".join(problems),
                "remediation": (
                    "Use a long max-age, cover subdomains, and add preload once you are confident all "
                    "subdomains support HTTPS."
                ),
                "snippet": 'add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;',
                "evidence": hsts[:120],
            })
        return findings

    def _check_directory_listing(self, response: httpx.Response) -> List[Dict[str, Any]]:
        findings = []
        body = (response.text or "")[:4000].lower()
        if "<title>index of /" in body or ">index of /</" in body or "directory listing for" in body:
            findings.append({
                "category": "Security",
                "severity": "Medium",
                "title": "Directory Listing Is Enabled",
                "issue": (
                    "The server returns an auto-generated directory index, exposing your file/folder "
                    "structure and potentially sensitive files to anyone."
                ),
                "remediation": (
                    "Disable automatic directory indexing. In Nginx ensure 'autoindex off;' (the default); "
                    "in Apache add 'Options -Indexes'."
                ),
                "snippet": "# Apache (.htaccess)\nOptions -Indexes\n\n# Nginx\nautoindex off;",
                "evidence": None,
            })
        return findings

    def _check_html_body(self, response: httpx.Response) -> List[Dict[str, Any]]:
        """SRI on third-party scripts + mixed content on HTTPS pages."""
        findings = []
        ctype = response.headers.get("content-type", "")
        if "text/html" not in ctype:
            return findings
        try:
            soup = BeautifulSoup(response.text, "html.parser")
        except Exception:
            return findings

        page_host = urlparse(str(response.url)).netloc.lower()

        # 1. Third-party scripts without Subresource Integrity.
        no_sri = []
        for s in soup.find_all("script", src=True):
            src = s.get("src", "")
            abs_src = urljoin(str(response.url), src)
            host = urlparse(abs_src).netloc.lower()
            if host and host != page_host and not s.get("integrity"):
                no_sri.append(abs_src)
        if no_sri:
            findings.append({
                "category": "Security",
                "severity": "Medium",
                "title": f"{len(no_sri)} Third-Party Script(s) Without Subresource Integrity",
                "issue": (
                    "External scripts are loaded without an 'integrity' hash. If the third-party host or "
                    "CDN is compromised, malicious code runs on your site (supply-chain / Magecart risk). "
                    "Example: " + ", ".join(no_sri[:3])
                ),
                "remediation": (
                    "Add an integrity (SRI) hash and crossorigin attribute to every external <script>/<link>. "
                    "Generate the hash with: openssl dgst -sha384 -binary file.js | openssl base64 -A"
                ),
                "snippet": (
                    '<script src="https://cdn.example.com/lib.js" '
                    'integrity="sha384-{HASH}" crossorigin="anonymous"></script>'
                ),
                "evidence": ", ".join(no_sri[:3])[:160],
            })

        # 2. Mixed content: insecure http:// references on an https page.
        if str(response.url).startswith("https://"):
            mixed = []
            for tag, attr in [("script", "src"), ("link", "href"), ("img", "src"),
                              ("iframe", "src"), ("source", "src")]:
                for el in soup.find_all(tag):
                    val = el.get(attr, "")
                    if isinstance(val, str) and val.startswith("http://"):
                        mixed.append(val)
            if mixed:
                findings.append({
                    "category": "Security",
                    "severity": "Medium",
                    "title": f"{len(mixed)} Mixed (Insecure) Content Reference(s)",
                    "issue": (
                        "An HTTPS page loads resources over plain http://, which browsers may block or "
                        "which attackers can tamper with (MITM). Example: " + ", ".join(mixed[:3])
                    ),
                    "remediation": (
                        "Update all asset URLs to https:// (or protocol-relative // served over TLS). "
                        "Add 'upgrade-insecure-requests' to your CSP to auto-rewrite legacy references."
                    ),
                    "snippet": 'add_header Content-Security-Policy "upgrade-insecure-requests" always;',
                    "evidence": ", ".join(mixed[:3])[:160],
                })
        return findings

    async def _check_sensitive_paths(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        findings = []
        sem = asyncio.Semaphore(8)

        async def probe(path: str, label: str):
            url = urljoin(self.base + "/", path.lstrip("/"))
            async with sem:
                try:
                    r = await client.get(url)
                except Exception:
                    return None
            return (path, label, r, url)

        results = await asyncio.gather(*[probe(p, l) for p, l in SENSITIVE_PATHS])

        for item in results:
            if not item:
                continue
            path, label, r, url = item
            is_securitytxt = path.endswith("security.txt")

            if is_securitytxt:
                # This one is "good if present" -- flag only when ABSENT.
                if r.status_code >= 400:
                    findings.append({
                        "category": "Security",
                        "severity": "Low",
                        "title": "No security.txt Disclosure Policy",
                        "issue": (
                            "No /.well-known/security.txt was found. This file tells security researchers "
                            "how to responsibly report vulnerabilities they discover in your site."
                        ),
                        "remediation": (
                            "Publish /.well-known/security.txt with a contact address and policy link."
                        ),
                        "snippet": "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z\nPolicy: https://example.com/security-policy",
                        "evidence": None,
                    })
                continue

            # For everything else: a 200 with real content == exposure.
            if r.status_code == 200 and len(r.content or b"") > 0:
                body_sample = (r.text or "")[:200].lower()
                # Skip soft-404 pages that return 200 with an error page.
                if "not found" in body_sample and "404" in body_sample:
                    continue
                findings.append({
                    "category": "Security",
                    "severity": "High",
                    "title": f"Sensitive File Exposed: {path}",
                    "issue": (
                        f"{label} is publicly accessible at {url} (HTTP 200). This can leak source code, "
                        "credentials, database contents, or internal configuration to attackers."
                    ),
                    "remediation": (
                        "Remove the file from the web root and block access at the server level. Rotate any "
                        "credentials that may have been exposed."
                    ),
                    "snippet": (
                        "# Nginx -- deny dotfiles & backups\n"
                        "location ~ /\\.(git|svn|env|ht) { deny all; return 404; }\n"
                        "location ~* \\.(bak|sql|zip|old)$ { deny all; return 404; }"
                    ),
                    "evidence": f"{url} -> HTTP {r.status_code}",
                })
        return findings

    async def _check_cors(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        findings = []
        probe_origin = "https://aegisweb-cors-probe.example.com"
        try:
            r = await client.get(self.url, headers={"Origin": probe_origin})
        except Exception:
            return findings

        acao = r.headers.get("access-control-allow-origin")
        acac = (r.headers.get("access-control-allow-credentials") or "").lower()
        if not acao:
            return findings

        if acao == probe_origin:
            findings.append({
                "category": "Security",
                "severity": "High" if acac == "true" else "Medium",
                "title": "CORS Reflects Arbitrary Origin",
                "issue": (
                    "The server reflected our untrusted Origin back in Access-Control-Allow-Origin"
                    + (" together with Allow-Credentials: true, which lets any site read authenticated "
                       "responses on behalf of your users." if acac == "true"
                       else ", allowing any origin to make cross-origin reads.")
                ),
                "remediation": (
                    "Never reflect the Origin header blindly. Validate it against an explicit allowlist and "
                    "only echo back known-good origins. Do not combine '*' or reflected origins with credentials."
                ),
                "snippet": (
                    "if ($http_origin ~* ^https://(app|www)\\.example\\.com$) {\n"
                    "    add_header Access-Control-Allow-Origin $http_origin always;\n}"
                ),
                "evidence": f"ACAO={acao}; ACAC={acac or 'unset'}",
            })
        elif acao == "*" and acac == "true":
            findings.append({
                "category": "Security",
                "severity": "Medium",
                "title": "CORS Wildcard With Credentials",
                "issue": "Access-Control-Allow-Origin: * is combined with credentials, a misconfiguration.",
                "remediation": "Replace the wildcard with a validated allowlist when credentials are involved.",
                "snippet": None,
                "evidence": f"ACAO=*; ACAC={acac}",
            })
        return findings

    async def _check_https_redirect(self, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
        findings = []
        # Only meaningful when the canonical site is HTTPS.
        if self.scheme != "https":
            findings.append({
                "category": "Security",
                "severity": "High",
                "title": "Site Served Over Unencrypted HTTP",
                "issue": "The target is configured for plain HTTP; all traffic is transmitted in cleartext.",
                "remediation": (
                    "Obtain a TLS certificate (e.g. free via Let's Encrypt/Certbot) and force HTTPS."
                ),
                "snippet": "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}",
                "evidence": None,
            })
            return findings

        http_url = "http://" + self.hostname
        try:
            r = await client.get(http_url)
        except Exception:
            return findings  # http port likely closed -> fine

        final = str(r.url)
        if final.startswith("http://"):
            findings.append({
                "category": "Security",
                "severity": "Medium",
                "title": "HTTP Does Not Redirect to HTTPS",
                "issue": (
                    f"Requesting {http_url} did not upgrade to HTTPS (ended at {final}). Users typing the "
                    "bare domain are served insecurely and are exposed to MITM/downgrade attacks."
                ),
                "remediation": "Add a permanent 301 redirect from all HTTP traffic to HTTPS, then enable HSTS.",
                "snippet": "server {\n  listen 80;\n  server_name example.com;\n  return 301 https://$host$request_uri;\n}",
                "evidence": f"http:// resolved to {final}",
            })
        return findings
