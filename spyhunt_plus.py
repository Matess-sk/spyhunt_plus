#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SpyHunt+ v1.2.2 — OSINT a web-recon toolkit (monolit, terminálové menu + auto-update pri štarte)
Používaj iba na ciele, na ktoré máš povolenie.
Repo pre auto-update: https://github.com/Matess-sk/spyhunt_plus
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import contextlib
import dataclasses as dc
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlencode, urlsplit, urlunsplit, parse_qsl

# ---------------- Konštanty ----------------
APP = "spyhunt_plus"
VERSION = "1.2.2"
DEFAULT_TIMEOUT = 12.0
CONCURRENCY = 100
USER_AGENT = f"{APP}/{VERSION}"

# Auto-update cieľ
DEFAULT_REPO   = "Matess-sk/spyhunt_plus"
DEFAULT_BRANCH = "main"
DEFAULT_PATH   = "spyhunt_plus.py"

# ---------------- Závislosti ----------------
try:
    import httpx  # povinné
except Exception:
    print("[!] Nainštaluj: pip install httpx>=0.24", file=sys.stderr)
    raise

# voliteľné
try:
    import mmh3  # favicon hash
except Exception:
    mmh3 = None  # type: ignore

try:
    import dns.resolver  # type: ignore
except Exception:
    dns = None  # type: ignore

# ---------------- Pomocné typy a utily ----------------
@dc.dataclass
class Finding:
    module: str
    target: str
    data: Dict[str, Any]

def jdump(x: Dict[str, Any]) -> str:
    return json.dumps(x, ensure_ascii=False, separators=(",", ":"))

def jsonl_write(path: Path, item: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(jdump(item) + "\n")

class RateLimiter:
    def __init__(self, rate_per_sec: float):
        self._interval = 1.0 / max(rate_per_sec, 0.001)
        self._last = 0.0
        self._lock = asyncio.Lock()
    async def wait(self):
        async with self._lock:
            now = asyncio.get_event_loop().time()
            delta = self._interval - (now - self._last)
            if delta > 0:
                await asyncio.sleep(delta)
            self._last = asyncio.get_event_loop().time()

def which(tool: str) -> Optional[str]:
    return shutil.which(tool)

def run_subprocess(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def norm_url(u: str) -> str:
    return u if re.match(r"^https?://", u, re.I) else "http://" + u

async def fetch(client: httpx.AsyncClient, method: str, url: str, **kw) -> Optional[httpx.Response]:
    try:
        return await client.request(method, url, timeout=DEFAULT_TIMEOUT, follow_redirects=True, **kw)
    except Exception:
        return None

# ---------------- Interaktívne MENU (terminál) ----------------
def _ask(prompt: str, default: Optional[str]=None, required: bool=False) -> str:
    while True:
        s = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
        if not s and default is not None:
            s = default
        if s or not required:
            return s
        print("Hodnota je povinná.")

def _menu_build_argv() -> List[str]:
    print("\n=== SpyHunt+ — Interaktívne menu ===")
    items = [
        ("autorecon", "Auto Recon (CMS, CVE, theme, crawl, fuzz, headers)"),
        ("cms",       "CMS/Theme/Plugins audit + CVE"),
        ("subdomains","Subdomain enumeration"),
        ("dns",       "DNS record lookup"),
        ("crawl",     "Web crawling + URL/JS"),
        ("favicon",   "Favicon mmh3 hash"),
        ("hosttest",  "Host header injection test"),
        ("secheads",  "Security headers analysis"),
        ("wayback",   "Wayback Machine URLs"),
        ("broken",    "Broken link check (zo súboru)"),
        ("smuggle",   "HTTP request smuggling heuristics"),
        ("dirb",      "Directory & file brute-forcing"),
        ("ports",     "Port scan / CIDR"),
        ("nmap",      "Nmap wrapper"),
        ("nuclei",    "Nuclei wrapper"),
        ("shodan",    "Shodan host lookup"),
        ("dork",      "Google dorking (SerpAPI)"),
        ("s3",        "AWS S3 bucket enumeration"),
        ("fuzz",      "Heuristický fuzz (XSS/SQLi/Traversal)"),
        ("selfupdate","Self-update z GitHubu"),
    ]
    for i,(cmd,desc) in enumerate(items, start=1):
        print(f"{i:2d}) {cmd:11s} — {desc}")
    print(" 0) ukončiť")
    while True:
        sel = _ask("Vyber číslo", required=True)
        if sel.isdigit():
            n = int(sel)
            if n==0:
                sys.exit(0)
            if 1 <= n <= len(items):
                cmd = items[n-1][0]
                break
        print("Neplatná voľba.")

    argv: List[str] = [cmd]
    if cmd in ("autorecon","cms","crawl","favicon","hosttest","smuggle","fuzz"):
        url = _ask("URL", required=True)
        argv.append(url)
    elif cmd in ("subdomains",):
        dom = _ask("Domain", required=True); argv += [dom]
        w = _ask("Wordlist cesta (-w) (Enter pre vynechanie)")
        if w: argv += ["-w", w]
    elif cmd in ("dns",):
        name = _ask("Name", required=True); rtype=_ask("Type (A,MX,TXT,CNAME...)", "A")
        argv += [name, "-t", rtype]
    elif cmd in ("wayback","s3","shodan"):
        val = _ask("Domain/IP/host", required=True); argv += [val]
    elif cmd in ("broken",):
        path = _ask("Súbor s URL (1 na riadok)", required=True); argv += [path]
    elif cmd in ("dirb",):
        base = _ask("Base URL", required=True); argv += [base]
        w = _ask("Wordlist cesta (-w) (Enter pre vynechanie)")
        if w: argv += ["-w", w]
    elif cmd in ("ports",):
        tgt = _ask("Target alebo --cidr", required=True); argv += [tgt]
        top = _ask("Použiť --top? (y/N)","N").lower().startswith("y")
        if top: argv += ["--top"]
        ports = _ask("Vlastné porty, napr. 1-1024,80,443 (Enter pre vynechanie)")
        if ports: argv += ["--ports", ports]
        cidr = _ask("CIDR, napr. 192.168.1.0/24 (Enter pre vynechanie)")
        if cidr: argv += ["--cidr", cidr]
    elif cmd in ("nmap",):
        tgt = _ask("Target", required=True); argv += [tgt]
        fast = _ask("Rýchly sken --fast? (y/N)","N").lower().startswith("y")
        if fast: argv += ["--fast"]
    elif cmd in ("nuclei",):
        url = _ask("URL", required=True); argv += [url]
        tpl = _ask("Templates (-t) (Enter pre vynechanie)")
        if tpl: argv += ["-t", tpl]
    elif cmd in ("dork",):
        q = _ask("Dork query", required=True); argv += [q]
    elif cmd in ("selfupdate",):
        repo = _ask("owner/repo", DEFAULT_REPO)
        branch = _ask("branch", DEFAULT_BRANCH)
        path = _ask("path", DEFAULT_PATH)
        argv += ["--repo", repo, "--branch", branch, "--path", path]

    out = _ask("Výstupný súbor -o (Enter = default)")
    if out:
        argv = ["-o", out] + argv

    # Hlavičky: áno/nie → potom Key: Value
    extra_hdrs = []
    want_hdr = _ask("Chceš pridať HTTP header? (y/N)", "N").lower()
    if want_hdr in ("y", "yes", "ano", "a"):
        while True:
            kv = _ask("Zadaj header vo formáte 'Key: Value' (Enter = koniec)")
            if not kv:
                break
            if ":" not in kv:
                print("Neplatný formát. Použi 'Key: Value'.")
                continue
            extra_hdrs += ["--header", kv]
    if extra_hdrs:
        argv = extra_hdrs + argv
    return argv

# ---------------- Subdomény ----------------
COMMON_SUBS = [
    "www","dev","staging","api","cdn","static","img","admin","beta","test","portal",
    "assets","m","mail","app","edge","ws","node","internal","vpn","git","repo","blog"
]

async def subdomain_enum(domain: str, words: Iterable[str], rps: float = 0.0) -> List[str]:
    limiter = RateLimiter(rps) if rps > 0 else None
    sem = asyncio.Semaphore(CONCURRENCY)
    found: Set[str] = set()
    async def one(w: str):
        fqdn = f"{w}.{domain}"
        if limiter:
            await limiter.wait()
        try:
            async with sem:
                await asyncio.get_event_loop().getaddrinfo(fqdn, None)
            found.add(fqdn)
        except Exception:
            pass
    tasks = [asyncio.create_task(one(w.strip())) for w in words if w.strip()]
    if tasks:
        await asyncio.gather(*tasks)
    return sorted(found)

# ---------------- DNS ----------------
def dns_query(name: str, rtype: str) -> List[str]:
    out: List[str] = []
    if 'dns' in globals() and dns:
        try:
            ans = dns.resolver.resolve(name, rtype)
            return [str(r.to_text()) for r in ans]
        except Exception:
            return out
    for bin_ in ("dig", "nslookup"):
        b = which(bin_)
        if not b:
            continue
        code, stdout, _ = run_subprocess([b, name] if bin_ == "nslookup" else [b, rtype, name], timeout=10)
        if code == 0:
            out = [ln.strip() for ln in stdout.splitlines() if ln.strip()]
            break
    return out

# ---------------- Crawl / URL / JS ----------------
HREF_RX = re.compile(r'href=["\']([^"\'>\s#]+)', re.I)
SRC_RX  = re.compile(r'src=["\']([^"\'>\s#]+)', re.I)
ABS_RX  = re.compile(r"^https?://", re.I)

async def crawl(start: str, client: httpx.AsyncClient, max_pages: int = 100, same_host: bool = True) -> Dict[str, List[str]]:
    start = norm_url(start)
    seen: Set[str] = {start}
    q: asyncio.Queue[str] = asyncio.Queue()
    await q.put(start)
    pages, urls, jsfiles = [], set(), set()
    while not q.empty() and len(pages) < max_pages:
        url = await q.get()
        r = await fetch(client, "GET", url)
        if not r or r.status_code >= 400:
            continue
        body, base = r.text, str(r.url)
        pages.append(url)
        for rx in (HREF_RX, SRC_RX):
            for m in rx.findall(body):
                u = urljoin(base, m)
                urls.add(u)
                if u.endswith(".js"):
                    jsfiles.add(u)
                if same_host and urlparse(u).netloc != urlparse(start).netloc:
                    continue
                if u not in seen and ABS_RX.match(u):
                    seen.add(u)
                    await q.put(u)
    return {"pages": pages, "urls": sorted(urls), "js": sorted(jsfiles)}

# ---------------- Favicon hash ----------------
async def favicon_hash(base: str, client: httpx.AsyncClient) -> Optional[int]:
    r = await fetch(client, "GET", norm_url(base).rstrip("/") + "/favicon.ico")
    if not r or r.status_code >= 400 or not mmh3:
        return None
    try:
        return mmh3.hash(base64.b64encode(r.content))
    except Exception:
        return None

# ---------------- Host header injection ----------------
async def host_header_test(url: str, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    base = norm_url(url)
    host = urlparse(base).netloc
    payloads = ["evil.com", f"{host}.evil.com", "127.0.0.1", "localhost", "invalid", "example.com"]
    out = []
    for p in payloads:
        r = await fetch(client, "GET", base, headers={"Host": p})
        if not r:
            continue
        out.append({
            "host": p,
            "status": r.status_code,
            "location": r.headers.get("Location"),
            "anomaly": (300 <= r.status_code < 400) or (p in r.text[:2000])
        })
    return out

# ---------------- Security headers ----------------
SEC_HEADERS = [
    "Content-Security-Policy","X-Frame-Options","X-Content-Type-Options","Referrer-Policy",
    "Strict-Transport-Security","Permissions-Policy","Cross-Origin-Opener-Policy","Cross-Origin-Resource-Policy"
]
async def security_headers(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    r = await fetch(client, "GET", norm_url(url))
    if not r:
        return {"error": "request failed"}
    present = {h: r.headers.get(h) for h in SEC_HEADERS if h in r.headers}
    missing = [h for h in SEC_HEADERS if h not in r.headers]
    return {"status": r.status_code, "present": present, "missing": missing}

# ---------------- Wayback ----------------
async def wayback_urls(domain: str, client: httpx.AsyncClient, limit: int = 500) -> List[str]:
    api = f"https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey&limit={limit}"
    r = await fetch(client, "GET", api)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
        return sorted({row[0] for row in data[1:]}) if isinstance(data, list) and data else []
    except Exception:
        return []

# ---------------- Broken links ----------------
async def broken_links(urls: Iterable[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    sem = asyncio.Semaphore(CONCURRENCY)
    out: List[Dict[str, Any]] = []
    async def one(u: str):
        async with sem:
            r = await fetch(client, "GET", u)
        if not r or r.status_code >= 400:
            out.append({"url": u, "status": getattr(r, "status_code", None)})
    await asyncio.gather(*[asyncio.create_task(one(u)) for u in urls])
    return out

# ---------------- Request smuggling heuristiky ----------------
async def smuggling_probe(url: str) -> Dict[str, Any]:
    pr = urlparse(norm_url(url))
    host = pr.hostname or ""
    port = pr.port or (443 if pr.scheme == "https" else 80)
    ssl = pr.scheme == "https"
    te_cl = (f"POST {pr.path or '/'} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n0\r\n\r\n").encode()
    cl_te = (f"POST {pr.path or '/'} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n").encode()
    results = []
    for pay in (te_cl, cl_te):
        try:
            if ssl:
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                with socket.create_connection((host, port), timeout=6) as s:
                    with ctx.wrap_socket(s, server_hostname=host) as ss:
                        ss.sendall(pay); ss.settimeout(6); data = ss.recv(1024)
            else:
                with socket.create_connection((host, port), timeout=6) as s:
                    s.sendall(pay); s.settimeout(6); data = s.recv(1024)
            results.append(data[:200].decode(errors="ignore"))
        except Exception as e:
            results.append(f"error:{type(e).__name__}")
    hint = any("400" in r or "408" in r for r in results)
    return {"results": results, "anomaly_hint": hint}

# ---------------- IP extrakcia ----------------
IP_RX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
async def extract_ips_from_text(text: str) -> List[str]:
    return sorted(set(IP_RX.findall(text)))

# ---------------- CMS/tech detection ----------------
CMS_SIGNS = {
    "wordpress": ["wp-content/","wp-includes/","generator\" content=\"WordPress"],
    "drupal": ["/sites/default/","X-Generator: Drupal","generator\" content=\"Drupal"],
    "joomla": ["/media/system/js/","generator\" content=\"Joomla"],
}
async def detect_cms(url: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    r = await fetch(client, "GET", norm_url(url))
    if not r:
        return {"error": "request failed"}
    body = r.text
    cms, version = None, None
    for name, sigs in CMS_SIGNS.items():
        if any(s.lower() in body.lower() or s.lower() in str(r.headers).lower() for s in sigs):
            cms = name
            break
    m = re.search(r'<meta[^>]*name="generator"[^>]*content="([^"]+)"', body, re.I)
    if m:
        gen = m.group(1)
        mv = re.search(r"(\d+\.\d+(?:\.\d+)?)", gen)
        if mv:
            version = mv.group(1)
    return {
        "server": r.headers.get("Server"),
        "x_powered_by": r.headers.get("X-Powered-By"),
        "cms": cms,
        "version": version
    }

# ---------------- Ver porovnávanie ----------------
def _ver_tuple(v: Optional[str]) -> tuple:
    if not v:
        return tuple()
    nums = re.findall(r"\d+", v)
    return tuple(int(x) for x in nums[:3])

# ---------------- WP jadro: latest ----------------
async def wp_core_latest(client: httpx.AsyncClient) -> Optional[str]:
    u = "https://api.wordpress.org/core/version-check/1.7/"
    r = await fetch(client, "GET", u)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
        if isinstance(data, dict) and data.get("offers"):
            return str(data["offers"][0].get("current") or "").strip() or None
    except Exception:
        return None
    return None

# ---------------- WP téma ----------------
THEME_PATH_RX = re.compile(r"/wp-content/themes/([a-zA-Z0-9_-]+)/", re.I)

async def detect_wp_theme(base_url: str, client: httpx.AsyncClient) -> Dict[str, str]:
    r = await fetch(client, "GET", norm_url(base_url))
    if not r or r.status_code >= 400:
        return {}
    m = THEME_PATH_RX.search(r.text)
    if not m:
        return {}
    slug = m.group(1)
    style_url = urljoin(str(r.url), f"/wp-content/themes/{slug}/style.css")
    r2 = await fetch(client, "GET", style_url)
    out = {"theme_slug": slug}
    if not r2 or r2.status_code >= 400:
        return out
    name = None; ver = None
    for line in r2.text.splitlines()[:80]:
        low = line.lower()
        if not name and low.startswith("theme name:"):
            name = line.split(":", 1)[1].strip()
        if not ver and low.startswith("version:"):
            ver = line.split(":", 1)[1].strip()
        if name and ver:
            break
    if name: out["theme_name"] = name
    if ver:  out["theme_version"] = ver
    return out

async def wp_theme_latest(slug: str, client: httpx.AsyncClient) -> Optional[str]:
    u = f"https://api.wordpress.org/themes/info/1.0/{slug}.json"
    r = await fetch(client, "GET", u)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
        v = data.get("version")
        return str(v).strip() if v else None
    except Exception:
        return None

# ---------------- WP pluginy ----------------
PLUGIN_PATH_RX = re.compile(r"/wp-content/plugins/([a-zA-Z0-9_-]+)/", re.I)

async def detect_wp_plugins(base_url: str, client: httpx.AsyncClient, html_cache: Optional[str] = None) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if html_cache is None:
        r = await fetch(client, "GET", norm_url(base_url))
        if not r or r.status_code >= 400:
            return out
        html = r.text
        base = str(r.url)
    else:
        html = html_cache
        base = norm_url(base_url)

    slugs = sorted(set(PLUGIN_PATH_RX.findall(html)))
    for slug in slugs:
        info: Dict[str, str] = {"slug": slug}
        main_php = urljoin(base, f"/wp-content/plugins/{slug}/{slug}.php")
        r1 = await fetch(client, "GET", main_php)
        text = ""
        if r1 and r1.status_code == 200:
            text = r1.text[:4000]
        else:
            readme = urljoin(base, f"/wp-content/plugins/{slug}/readme.txt")
            r2 = await fetch(client, "GET", readme)
            if r2 and r2.status_code == 200:
                text = r2.text[:4000]
        if text:
            for line in text.splitlines()[:120]:
                low = line.lower()
                if low.startswith("version:"):
                    ver = line.split(":", 1)[1].strip()
                    if ver:
                        info["version"] = ver
                if low.startswith("plugin name:") and "name" not in info:
                    info["name"] = line.split(":", 1)[1].strip()
                if "version" in info and "name" in info:
                    break
        out.append(info)
    return out

async def wp_plugin_latest(slug: str, client: httpx.AsyncClient) -> Optional[str]:
    u = f"https://api.wordpress.org/plugins/info/1.0/{slug}.json"
    r = await fetch(client, "GET", u)
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
        v = data.get("version")
        return str(v).strip() if v else None
    except Exception:
        return None

def _uptodate(installed: Optional[str], latest: Optional[str]) -> Optional[bool]:
    if not installed or not latest:
        return None
    return _ver_tuple(installed) >= _ver_tuple(latest)

# ---------------- CVE (CIRCL) ----------------
async def cve_search_circl(query: str, client: httpx.AsyncClient, limit: int = 20) -> List[Dict[str, Any]]:
    url = f"https://cve.circl.lu/api/search/{query}"
    r = await fetch(client, "GET", url)
    if not r or r.status_code != 200:
        return []
    try:
        data = r.json()
        out = []
        for it in data[:limit]:
            out.append({
                "id": it.get("id"),
                "summary": it.get("summary"),
                "cvss": it.get("cvss"),
                "published": it.get("Published")
            })
        return out
    except Exception:
        return []

async def cms_vulns_online(cms: Optional[str], version: Optional[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    if not cms or not version:
        return []
    return await cve_search_circl(f"{cms} {version}", client)

async def theme_vulns_online(theme_name: Optional[str], theme_version: Optional[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    if not theme_name or not theme_version:
        return []
    q = f"{theme_name} WordPress theme {theme_version}"
    return await cve_search_circl(q, client)

# ---------------- Dir brute-force ----------------
COMMON_DIRS = [
    "admin/",".git/HEAD",".env",".well-known/security.txt","backup/","old/","phpinfo.php",
    "server-status","wp-admin/","wp-login.php","robots.txt","sitemap.xml"
]
async def dir_bruteforce(base: str, words: Iterable[str], client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    base = norm_url(base).rstrip('/') + '/'
    sem = asyncio.Semaphore(CONCURRENCY)
    hits: List[Dict[str, Any]] = []
    async def one(p: str):
        url = base + p
        try:
            async with sem:
                r = await client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=False)
            if r.status_code not in (404, 400):
                hits.append({"path": p, "status": r.status_code, "length": int(r.headers.get("Content-Length", 0))})
        except Exception:
            pass
    await asyncio.gather(*[asyncio.create_task(one(w.strip())) for w in words if w.strip() and not w.startswith("#")])
    return sorted(hits, key=lambda x: (x["status"], x["path"]))

# ---------------- Subdomain takeover heuristiky ----------------
TAKEOVER_PATTERNS = {
    "aws_s3": re.compile(r"NoSuchBucket|The specified bucket does not exist|Code: NoSuchBucket", re.I),
    "github_pages": re.compile(r"There isn't a GitHub Pages site here|404 File not found", re.I),
    "vercel": re.compile(r"Vercel Deployment Not Found|DEPLOYMENT_NOT_FOUND", re.I),
    "cloudfront": re.compile(r"ERROR\s*The request could not be satisfied|Code: NoSuchDistribution", re.I),
}
async def check_takeover(host: str, client: httpx.AsyncClient) -> List[str]:
    matches: Set[str] = set()
    for u in [f"http://{host}", f"https://{host}"]:
        with contextlib.suppress(Exception):
            r = await client.get(u, timeout=DEFAULT_TIMEOUT)
            if not r:
                continue
            body = r.text[:3000]
            for name, rx in TAKEOVER_PATTERNS.items():
                if rx.search(body):
                    matches.add(name)
    return sorted(matches)

# ---------------- Porty + CIDR ----------------
async def scan_port(host: str, port: int, timeout: float = 1.2) -> bool:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return True
    except Exception:
        return False

async def port_scan(host: str, ports: Iterable[int]) -> List[int]:
    sem = asyncio.Semaphore(CONCURRENCY)
    openp: List[int] = []
    async def one(p: int):
        async with sem:
            if await scan_port(host, p):
                openp.append(p)
    await asyncio.gather(*[asyncio.create_task(one(p)) for p in ports])
    return sorted(openp)

def iter_cidr(cidr: str) -> List[str]:
    net = ipaddress.ip_network(cidr, strict=False)
    return [str(ip) for ip in net.hosts()]

# ---------------- Nmap / Nuclei ----------------
def nmap_scan(target: str, fast: bool = True) -> Dict[str, Any]:
    b = which("nmap")
    if not b:
        return {"error": "nmap not found"}
    args = [b, "-Pn", "-n", "-oX", "-", target]
    if fast:
        args[1:1] = ["-T4", "-F"]
    code, out, err = run_subprocess(args, timeout=900)
    return {"code": code, "stdout": out, "stderr": err}

def nuclei_scan(target: str, templates: Optional[str] = None) -> Dict[str, Any]:
    b = which("nuclei")
    if not b:
        return {"error": "nuclei not found"}
    args = [b, "-u", target, "-json"]
    if templates:
        args += ["-t", templates]
    code, out, err = run_subprocess(args, timeout=1800)
    findings: List[Dict[str, Any]] = []
    for ln in out.splitlines():
        with contextlib.suppress(Exception):
            findings.append(json.loads(ln))
    return {"code": code, "findings": findings, "stderr": err}

# ---------------- Shodan / SerpAPI ----------------
async def shodan_host_lookup(ip_or_host: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    key = os.getenv("SHODAN_API_KEY")
    if not key:
        return {"error": "missing SHODAN_API_KEY"}
    try:
        ipaddress.ip_address(ip_or_host)
        host = ip_or_host
    except Exception:
        try:
            host = socket.gethostbyname(ip_or_host)
        except Exception:
            return {"error": "cannot resolve host"}
    url = f"https://api.shodan.io/shodan/host/{host}?key={key}"
    r = await fetch(client, "GET", url)
    return r.json() if r and r.status_code == 200 else {"error": f"status {getattr(r,'status_code',None)}"}

async def serpapi_google_dork(query: str, client: httpx.AsyncClient) -> Dict[str, Any]:
    key = os.getenv("SERPAPI_KEY")
    if not key:
        return {"error": "missing SERPAPI_KEY"}
    r = await fetch(client, "GET", f"https://serpapi.com/search.json?q={query}&engine=google&api_key={key}")
    return r.json() if r and r.status_code == 200 else {"error": f"status {getattr(r,'status_code',None)}"}

# ---------------- JWT scanning ----------------
JWT_RX = re.compile(r"eyJ[A-Za-z0-9_-]+?\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
async def jwt_scan(body: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for tok in set(JWT_RX.findall(body)):
        try:
            h, p, _ = tok.split(".")
            header = json.loads(b64url_decode(h))
            payload = json.loads(b64url_decode(p))
            out.append({"token": tok[:40] + "...", "header": header, "payload": payload})
        except Exception:
            out.append({"token": tok[:40] + "...", "error": "decode failed"})
    return out

# ---------------- Light fuzzing: traversal / sqli / xss ----------------
TRAV_PAYLOADS = ["../../../../etc/passwd", "..%2f..%2f..%2fetc/passwd", "..%252f..%252fetc/passwd"]
SQLI_PAYLOADS = ["' OR '1'='1", "1' OR '1'='1", "' UNION SELECT NULL-- "]
XSS_PAYLOADS  = ["<script>alert(1)</script>", "\"><svg onload=alert(1)>"]
async def fuzz_get_params(url: str, client: httpx.AsyncClient, name: str, payloads: List[str]) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []
    sp = urlsplit(norm_url(url))
    qs = dict(parse_qsl(sp.query, keep_blank_values=True)) or {"q": ""}
    for p in payloads:
        qs2 = qs.copy()
        k = next(iter(qs2))
        qs2[k] = p
        new = urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(qs2), sp.fragment))
        r = await fetch(client, "GET", new)
        if not r:
            continue
        hit = False
        if name == "traversal":
            hit = ("root:x:" in r.text) or r.status_code == 500
        elif name == "sqli":
            hit = any(x in r.text.lower() for x in ["sql syntax", "mysql", "syntax error", "warning: pg_", "odbc"])
        elif name == "xss":
            hit = ("alert(1)" in r.text)
        res.append({"url": new, "status": getattr(r, "status_code", None), "hit": hit})
    return res

# ---------------- S3 enum ----------------
async def s3_enum(domain: str, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    short = domain.split(".")[0]
    candidates = {f"http://{n}.s3.amazonaws.com" for n in {domain, short, short + "-assets", short + "-static", short + "-media"}}
    candidates |= {f"http://{short}.s3-website-us-east-1.amazonaws.com"}
    out: List[Dict[str, Any]] = []
    for u in sorted(candidates):
        r = await fetch(client, "GET", u)
        if r and r.status_code in (200, 403, 404) and any(x in r.text for x in ["NoSuchBucket", "AccessDenied", "ListBucketResult"]):
            out.append({"url": u, "status": r.status_code, "indicator": True})
    return out

# ---------------- 403 bypass ----------------
BYPASS_PATHS = ["/admin", "/.", "/..;/admin", "/%2e/", "/admin/.%2e/", "/;/", "/?", "/*;*/", "/..%2f"]
async def try_403_bypass(base: str, client: httpx.AsyncClient) -> List[Dict[str, Any]]:
    base = norm_url(base).rstrip("/")
    sem = asyncio.Semaphore(CONCURRENCY)
    out: List[Dict[str, Any]] = []
    async def one(p: str):
        url = base + p
        try:
            async with sem:
                r = await client.get(url, timeout=DEFAULT_TIMEOUT, follow_redirects=True)
            if r.status_code not in (401, 403, 404):
                out.append({"url": url, "status": r.status_code})
        except Exception:
            pass
    await asyncio.gather(*[asyncio.create_task(one(p)) for p in BYPASS_PATHS])
    return out

# ---------------- AutoRecon ----------------
async def auto_recon(target: str, client: httpx.AsyncClient, out: Path) -> None:
    det = await detect_cms(target, client)
    jsonl_write(out, {"module": "cms", "target": target, **det})
    vulns = await cms_vulns_online(det.get("cms"), det.get("version"), client)
    if vulns:
        jsonl_write(out, {"module": "cms_vulns", "target": target, "items": vulns})

    tdet = await detect_wp_theme(target, client)
    if tdet:
        jsonl_write(out, {"module": "wp_theme", "target": target, **tdet})
    tvul = await theme_vulns_online(tdet.get("theme_name"), tdet.get("theme_version"), client)
    if tvul:
        jsonl_write(out, {"module": "wp_theme_vulns", "target": target, "items": tvul})

    cms_latest = None
    cms_up = None
    if det.get("cms") == "wordpress" and det.get("version"):
        cms_latest = await wp_core_latest(client)
        cms_up = _uptodate(det.get("version"), cms_latest)
        jsonl_write(out, {"module": "wp_core_status", "target": target, "installed": det.get("version"),
                          "latest": cms_latest, "up_to_date": cms_up})
    theme_latest = None
    theme_up = None
    if tdet.get("theme_slug"):
        theme_latest = await wp_theme_latest(tdet["theme_slug"], client)
        theme_up = _uptodate(tdet.get("theme_version"), theme_latest)
        jsonl_write(out, {"module": "wp_theme_status", "target": target,
                          "theme": tdet.get("theme_name"), "installed": tdet.get("theme_version"),
                          "latest": theme_latest, "up_to_date": theme_up})

    sec = await security_headers(target, client)
    jsonl_write(out, {"module": "sec_headers", "target": target, **sec})
    cr = await crawl(target, client, max_pages=60)
    jsonl_write(out, {"module": "crawl", "target": target, "pages": cr["pages"], "urls": cr["urls"][:200], "js": cr["js"][:200]})
    br = await broken_links(cr["urls"][:200], client)
    if br:
        jsonl_write(out, {"module": "broken", "target": target, "items": br[:200]})
    fav = await favicon_hash(target, client)
    if fav is not None:
        jsonl_write(out, {"module": "favicon", "target": target, "mmh3": fav})
    trav = await fuzz_get_params(target, client, "traversal", TRAV_PAYLOADS)
    sqli = await fuzz_get_params(target, client, "sqli", SQLI_PAYLOADS)
    xss  = await fuzz_get_params(target, client, "xss",  XSS_PAYLOADS)
    jsonl_write(out, {"module": "fuzz", "target": target, "traversal": trav, "sqli": sqli, "xss": xss})

# ---------------- Handlery príkazov ----------------
async def cmd_subdomains(args):
    words = COMMON_SUBS
    if args.wordlist:
        words = [w.strip() for w in Path(args.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    hosts = await subdomain_enum(args.domain, words, rps=args.rps)
    for h in hosts:
        jsonl_write(Path(args.out), {"module": "subdomains", "domain": args.domain, "host": h})
    print(f"[subdomains] {len(hosts)}")

async def cmd_dns(args):
    rec = dns_query(args.name, args.type.upper())
    jsonl_write(Path(args.out), {"module": "dns", "name": args.name, "type": args.type.upper(), "records": rec})
    print(f"[dns] {len(rec)}")

async def cmd_crawl(args):
    async with await _client(args.header) as client:
        res = await crawl(args.url, client, max_pages=args.max)
        jsonl_write(Path(args.out), {"module": "crawl", "target": args.url, **res})
    print(f"[crawl] pages={len(res['pages'])} urls={len(res['urls'])} js={len(res['js'])}")

async def cmd_favicon(args):
    async with await _client(args.header) as client:
        h = await favicon_hash(args.url, client)
        jsonl_write(Path(args.out), {"module": "favicon", "target": args.url, "mmh3": h})
    print(f"[favicon] {h}")

async def cmd_host(args):
    async with await _client(args.header) as client:
        res = await host_header_test(args.url, client)
        jsonl_write(Path(args.out), {"module": "host_injection", "target": args.url, "tests": res})
    print(f"[hosttest] {len(res)}")

async def cmd_secheads(args):
    async with await _client(args.header) as client:
        res = await security_headers(args.url, client)
        jsonl_write(Path(args.out), {"module": "sec_headers", "target": args.url, **res})
    print("[secheads] done")

async def cmd_wayback(args):
    async with await _client(args.header) as client:
        urls = await wayback_urls(args.domain, client)
        jsonl_write(Path(args.out), {"module": "wayback", "domain": args.domain, "urls": urls})
    print(f"[wayback] {len(urls)}")

async def cmd_broken(args):
    urls = [l.strip() for l in Path(args.input).read_text(encoding="utf-8", errors="ignore").splitlines() if l.strip()]
    async with await _client(None) as client:
        res = await broken_links(urls, client)
        jsonl_write(Path(args.out), {"module": "broken", "items": res})
    print(f"[broken] {len(res)} bad")

async def cmd_smuggle(args):
    res = await smuggling_probe(args.url)
    jsonl_write(Path(args.out), {"module": "smuggle", "target": args.url, **res})
    print("[smuggle] done")

async def cmd_cms(args):
    async with await _client(args.header) as client:
        det = await detect_cms(args.url, client)
        cms_name = det.get("cms")
        cms_ver  = det.get("version")

        cms_latest = None
        cms_up = None
        if cms_name == "wordpress" and cms_ver:
            cms_latest = await wp_core_latest(client)
            cms_up = _uptodate(cms_ver, cms_latest)

        tdet = await detect_wp_theme(args.url, client)
        tvul = await theme_vulns_online(tdet.get("theme_name"), tdet.get("theme_version"), client)
        theme_latest = None
        theme_up = None
        if tdet.get("theme_slug"):
            theme_latest = await wp_theme_latest(tdet["theme_slug"], client)
            theme_up = _uptodate(tdet.get("theme_version"), theme_latest)

        r_home = await fetch(client, "GET", norm_url(args.url))
        html_cache = r_home.text if (r_home and r_home.status_code < 400) else None
        plugins = await detect_wp_plugins(args.url, client, html_cache=html_cache)
        plugin_reports = []
        for p in plugins:
            slug = p.get("slug")
            inst_v = p.get("version")
            latest_v = await wp_plugin_latest(slug, client) if slug else None
            up = _uptodate(inst_v, latest_v)
            vulns = []
            if p.get("name") and inst_v:
                qn = f"{p['name']} WordPress plugin {inst_v}"
                vulns = await cve_search_circl(qn, client, limit=10)
            plugin_reports.append({**p, "latest": latest_v, "up_to_date": up, "vulns": vulns})

        vul = await cms_vulns_online(cms_name, cms_ver, client)

        jsonl_write(Path(args.out), {
            "module": "cms",
            "target": args.url,
            **det,
            "cms_latest": cms_latest,
            "cms_up_to_date": cms_up,
            "theme": {**tdet, "latest": theme_latest, "up_to_date": theme_up},
            "plugins": plugin_reports,
            "cms_vulns": vul,
            "theme_vulns": tvul
        })
    print(f"[cms] {cms_name} {cms_ver} (latest={cms_latest}, up_to_date={cms_up}) | "
          f"theme={tdet.get('theme_name')} {tdet.get('theme_version')} (latest={theme_latest}, up_to_date={theme_up}) | "
          f"plugins={len(plugins)} | vulns cms={len(vul)} theme={len(tvul)}")

async def cmd_dirb(args):
    words = COMMON_DIRS
    if args.wordlist:
        words = [w.strip() for w in Path(args.wordlist).read_text(encoding="utf-8", errors="ignore").splitlines() if w.strip()]
    async with await _client(args.header) as client:
        hits = await dir_bruteforce(args.base, words, client)
        jsonl_write(Path(args.out), {"module": "dirb", "base": args.base, "hits": hits})
    print(f"[dirb] {len(hits)}")

async def cmd_ports(args):
    ports: Set[int] = set()
    if args.top:
        ports.update([80,443,22,21,25,110,143,53,3306,3389,8080,8443,6379,5900,9200,27017,8000,23,139,445])
    if args.ports:
        for part in args.ports.split(","):
            if "-" in part:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            else:
                ports.add(int(part))
    if not ports:
        ports.update([80, 443, 22])
    targets = [args.target] if not args.cidr else iter_cidr(args.cidr)
    for t in targets:
        openp = await port_scan(t, sorted(ports))
        jsonl_write(Path(args.out), {"module": "ports", "target": t, "open": openp})
        print(f"[ports] {t} -> {openp}")

async def cmd_nmap(args):
    res = nmap_scan(args.target, fast=args.fast)
    jsonl_write(Path(args.out), {"module": "nmap", "target": args.target, **res})
    print(f"[nmap] exit={res.get('code')}")

async def cmd_nuclei(args):
    res = nuclei_scan(args.target, templates=args.templates)
    jsonl_write(Path(args.out), {"module": "nuclei", "target": args.target, **res})
    print(f"[nuclei] findings={len(res.get('findings', [])) if isinstance(res.get('findings'), list) else 'N/A'}")

async def cmd_shodan(args):
    async with await _client(None) as client:
        res = await shodan_host_lookup(args.host, client)
        jsonl_write(Path(args.out), {"module": "shodan", "target": args.host, "data": res})
    print("[shodan] done")

async def cmd_dork(args):
    async with await _client(None) as client:
        res = await serpapi_google_dork(args.query, client)
        jsonl_write(Path(args.out), {"module": "dork", "query": args.query, "data": res})
    print("[dork] done")

async def cmd_s3(args):
    async with await _client(None) as client:
        res = await s3_enum(args.domain, client)
        jsonl_write(Path(args.out), {"module": "s3", "domain": args.domain, "items": res})
    print(f"[s3] {len(res)}")

async def cmd_fuzz(args):
    async with await _client(None) as client:
        trav = await fuzz_get_params(args.url, client, "traversal", TRAV_PAYLOADS)
        sqli = await fuzz_get_params(args.url, client, "sqli", SQLI_PAYLOADS)
        xss  = await fuzz_get_params(args.url, client, "xss",  XSS_PAYLOADS)
        jsonl_write(Path(args.out), {"module": "fuzz", "target": args.url, "traversal": trav, "sqli": sqli, "xss": xss})
    print("[fuzz] done")

async def cmd_autorecon(args):
    async with await _client(None) as client:
        await auto_recon(args.url, client, Path(args.out))
    print("[autorecon] done")

# ---------------- HTTP klient s custom hlavičkami ----------------
async def _client(headers: Optional[List[str]]) -> httpx.AsyncClient:
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        for h in headers:
            if ":" in h:
                k, v = h.split(":", 1)
                hdrs[k.strip()] = v.strip()
    return httpx.AsyncClient(headers=hdrs)

# ---------------- Self-update (manuálny príkaz) ----------------
async def _download_raw(repo: str, branch: str, path: str) -> Optional[bytes]:
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
        r = await client.get(url, timeout=20)
    return r.content if r.status_code == 200 else None

async def cmd_selfupdate(args):
    repo   = getattr(args, "repo",   DEFAULT_REPO)
    branch = getattr(args, "branch", DEFAULT_BRANCH)
    path   = getattr(args, "path",   DEFAULT_PATH)
    data = await _download_raw(repo, branch, path)
    if not data:
        print(f"[selfupdate] zlyhalo stiahnutie {repo}/{branch}/{path}")
        return
    target = Path(__file__).resolve()
    backup = target.with_suffix(".py.bak")
    with contextlib.suppress(Exception):
        if target.exists():
            backup.write_bytes(target.read_bytes())
    target.write_bytes(data)
    print(f"[selfupdate] aktualizované -> {target.name} (backup: {backup.name})")
    print("[selfupdate] reštartujem...")
    os.execv(sys.executable, [sys.executable, str(target)] + sys.argv[1:])

# ---------------- Auto-update pri štarte ----------------
async def _fetch_remote_version(repo: str, branch: str, path: str) -> Optional[str]:
    url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
    try:
        async with httpx.AsyncClient(headers={"User-Agent": USER_AGENT}) as client:
            r = await client.get(url, timeout=10)
        if r.status_code != 200:
            return None
        m = re.search(r'VERSION\s*=\s*["\']([\d\.]+)["\']', r.text)
        return m.group(1) if m else None
    except Exception:
        return None

async def _do_selfupdate(repo: str, branch: str, path: str) -> bool:
    data = await _download_raw(repo, branch, path)
    if not data:
        return False
    target = Path(__file__).resolve()
    backup = target.with_suffix(".py.bak")
    with contextlib.suppress(Exception):
        if target.exists():
            backup.write_bytes(target.read_bytes())
    target.write_bytes(data)
    print(f"[update] aktualizované -> {target.name} (backup: {backup.name})")
    return True

async def check_autoupdate_on_start(
    repo: str = DEFAULT_REPO, branch: str = DEFAULT_BRANCH, path: str = DEFAULT_PATH
) -> None:
    if os.getenv("SPYHUNT_NO_UPDATE") == "1":
        return
    remote = await _fetch_remote_version(repo, branch, path)
    if not remote:
        return
    if _ver_tuple(remote) > _ver_tuple(VERSION):
        ans = input(f"[update] dostupná verzia {remote} (aktuálne {VERSION}). Aktualizovať? (y/N): ").strip().lower()
        if ans in ("y", "yes", "ano", "a"):
            ok = await _do_selfupdate(repo, branch, path)
            if ok:
                print("[update] reštartujem skript...")
                os.execv(sys.executable, [sys.executable, __file__] + sys.argv[1:])

# ---------------- CLI parser ----------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog=APP, description="OSINT/Web recon toolkit", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("-o", "--out", default=f"{APP}.jsonl", help="Výstupný JSONL")
    p.add_argument("--rps", type=float, default=0.0, help="Rate-limit req/s")
    p.add_argument("--header", action="append", help="Custom header 'Key: Value' (repeatable)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("subdomains"); s.add_argument("domain"); s.add_argument("-w","--wordlist"); s.set_defaults(func=cmd_subdomains)
    s = sub.add_parser("dns"); s.add_argument("name"); s.add_argument("-t","--type", default="A"); s.set_defaults(func=cmd_dns)
    s = sub.add_parser("crawl"); s.add_argument("url"); s.add_argument("--max", type=int, default=100); s.set_defaults(func=cmd_crawl)
    s = sub.add_parser("favicon"); s.add_argument("url"); s.set_defaults(func=cmd_favicon)
    s = sub.add_parser("hosttest"); s.add_argument("url"); s.set_defaults(func=cmd_host)
    s = sub.add_parser("secheads"); s.add_argument("url"); s.set_defaults(func=cmd_secheads)
    s = sub.add_parser("wayback"); s.add_argument("domain"); s.set_defaults(func=cmd_wayback)
    s = sub.add_parser("broken"); s.add_argument("input"); s.set_defaults(func=cmd_broken)
    s = sub.add_parser("smuggle"); s.add_argument("url"); s.set_defaults(func=cmd_smuggle)
    s = sub.add_parser("cms"); s.add_argument("url"); s.set_defaults(func=cmd_cms)
    s = sub.add_parser("dirb"); s.add_argument("base"); s.add_argument("-w","--wordlist"); s.set_defaults(func=cmd_dirb)
    s = sub.add_parser("ports"); s.add_argument("target"); s.add_argument("--ports"); s.add_argument("--cidr"); s.add_argument("--top", action="store_true"); s.set_defaults(func=cmd_ports)
    s = sub.add_parser("nmap"); s.add_argument("target"); s.add_argument("--fast", action="store_true"); s.set_defaults(func=cmd_nmap)
    s = sub.add_parser("nuclei"); s.add_argument("target"); s.add_argument("-t","--templates"); s.set_defaults(func=cmd_nuclei)
    s = sub.add_parser("shodan"); s.add_argument("host"); s.set_defaults(func=cmd_shodan)
    s = sub.add_parser("dork"); s.add_argument("query"); s.set_defaults(func=cmd_dork)
    s = sub.add_parser("s3"); s.add_argument("domain"); s.set_defaults(func=cmd_s3)
    s = sub.add_parser("fuzz"); s.add_argument("url"); s.set_defaults(func=cmd_fuzz)
    s = sub.add_parser("autorecon"); s.add_argument("url"); s.set_defaults(func=cmd_autorecon)

    s = sub.add_parser("selfupdate", help="Stiahne poslednú verziu spyhunt_plus.py z GitHubu")
    s.add_argument("--repo", default=DEFAULT_REPO, help="owner/repo")
    s.add_argument("--branch", default=DEFAULT_BRANCH)
    s.add_argument("--path", default=DEFAULT_PATH)
    s.set_defaults(func=cmd_selfupdate)

    s = sub.add_parser("menu", help="Spustí terminálové menu")
    s.set_defaults(func=lambda a: None)  # obslúži sa v amain()

    return p

# ---------------- main ----------------
async def amain(argv: Optional[List[str]] = None) -> int:
    # auto-update check pred štartom
    await check_autoupdate_on_start()

    # bez argumentov → terminálové menu
    if argv is None and len(sys.argv) <= 1:
        try:
            argv = _menu_build_argv()
        except SystemExit:
            return 0

    parser = build_parser(); args = parser.parse_args(argv)

    # explicitný "menu" príkaz
    if args.cmd == "menu":
        argv2 = _menu_build_argv()
        return await amain(argv2)

    try:
        await args.func(args)  # type: ignore
        return 0
    except KeyboardInterrupt:
        print("prerušené"); return 130

def main() -> int:
    return asyncio.run(amain())

if __name__ == "__main__":
    raise SystemExit(main())
