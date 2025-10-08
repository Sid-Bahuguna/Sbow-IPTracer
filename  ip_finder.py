#!/usr/bin/env python3
"""
IP Finder - Advanced IP Discovery Tool for Security Research

LEGAL & ETHICAL NOTICE:
This tool is designed for authorized security testing, defensive security research,
vulnerability assessment, and network reconnaissance ONLY. Users MUST have explicit
permission to scan and enumerate infrastructure for any target domain or organization.
Unauthorized scanning may violate computer fraud laws, terms of service, and regulations
such as the CFAA (USA), Computer Misuse Act (UK), and similar laws worldwide.

By using this tool, you agree that you have proper authorization and will comply with
all applicable laws and regulations. The authors assume no liability for misuse.

Copyright (c) 2025 - For defensive security research only.
"""

import asyncio
import json
import csv
import os
import sys
import logging
import argparse
import hashlib
import time
from pathlib import Path
from typing import List, Dict, Set, Optional, Any, Tuple
from datetime import datetime, timedelta
from ipaddress import ip_address, ip_network, IPv4Address, IPv6Address
from urllib.parse import quote, urlencode
import re

import aiohttp
import dns.resolver
import dns.reversename
from dotenv import load_dotenv
import yaml
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from tqdm.asyncio import tqdm_asyncio

# ============================================================================
# Configuration & Constants
# ============================================================================

VERSION = "1.0.0"
USER_AGENT = f"IPFinder/{VERSION} (Defensive Security Research Tool)"
CACHE_DIR = Path(".cache")
LOG_FILE = "ip_finder.log"
DEFAULT_CONCURRENCY = 10
HTTP_TIMEOUT = 30
DNS_TIMEOUT = 5
CACHE_TTL_HOURS = 24

# API endpoints and configurations
API_CONFIGS = {
    "crt_sh": "https://crt.sh/?q={query}&output=json",
    "censys_search": "https://search.censys.io/api/v2/hosts/search",
    "shodan_host": "https://api.shodan.io/shodan/host/{ip}",
    "shodan_search": "https://api.shodan.io/shodan/host/search",
    "zoomeye_search": "https://api.zoomeye.org/host/search",
    "virustotal_domain": "https://www.virustotal.com/api/v3/domains/{domain}",
    "virustotal_resolutions": "https://www.virustotal.com/api/v3/domains/{domain}/resolutions",
    "fofa_search": "https://fofa.info/api/v1/search/all",
    "binaryedge_domain": "https://api.binaryedge.io/v2/query/domains/subdomain/{domain}",
    "securitytrails_domain": "https://api.securitytrails.com/v1/domain/{domain}",
    "bgp_he_net": "https://bgp.he.net/net/{prefix}",
    "cymru_whois": "whois.cymru.com",
}

# ============================================================================
# Setup & Utilities
# ============================================================================

def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure logging with file and console handlers."""
    log_level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)

    # Create logger
    logger = logging.getLogger("ip_finder")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    # File handler - always debug
    fh = logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    logger.addHandler(fh)

    # Console handler - respects verbosity
    if not quiet:
        ch = logging.StreamHandler(sys.stdout)
        ch.setLevel(log_level)
        ch.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
        logger.addHandler(ch)

    return logger

def load_config(config_path: Optional[str] = None) -> Dict[str, str]:
    """Load API keys from environment variables or config file."""
    # Load .env file if present
    load_dotenv()

    config = {}

    # Load from environment variables (preferred)
    env_keys = [
        "SHODAN_API_KEY",
        "CENSYS_API_ID",
        "CENSYS_API_SECRET",
        "VT_API_KEY",
        "ZOOMEYE_API_KEY",
        "FOFA_EMAIL",
        "FOFA_KEY",
        "BINARYEDGE_API_KEY",
        "SECURITYTRAILS_API_KEY",
        "MAXMIND_LICENSE_KEY",
    ]

    for key in env_keys:
        value = os.environ.get(key)
        if value:
            config[key] = value

    # Load from YAML config if provided
    if config_path and Path(config_path).exists():
        with open(config_path, 'r') as f:
            yaml_config = yaml.safe_load(f) or {}
            config.update(yaml_config)

    return config

def get_cache_path(cache_key: str) -> Path:
    """Generate cache file path from key."""
    CACHE_DIR.mkdir(exist_ok=True)
    hash_key = hashlib.sha256(cache_key.encode()).hexdigest()
    return CACHE_DIR / f"{hash_key}.json"

def get_cached(cache_key: str, ttl_hours: int = CACHE_TTL_HOURS) -> Optional[Any]:
    """Retrieve cached data if not expired."""
    cache_path = get_cache_path(cache_key)
    if not cache_path.exists():
        return None

    try:
        with open(cache_path, 'r') as f:
            cached = json.load(f)

        cached_time = datetime.fromisoformat(cached['timestamp'])
        if datetime.now() - cached_time < timedelta(hours=ttl_hours):
            return cached['data']
    except (json.JSONDecodeError, KeyError, ValueError):
        pass

    return None

def set_cache(cache_key: str, data: Any) -> None:
    """Store data in cache with timestamp."""
    cache_path = get_cache_path(cache_key)
    try:
        with open(cache_path, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'data': data
            }, f)
    except Exception as e:
        logging.getLogger("ip_finder").debug(f"Cache write failed: {e}")

def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IPv4 or IPv6 address."""
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

def is_private_ip(ip_str: str) -> bool:
    """Check if IP is in private/reserved ranges."""
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return True

# ============================================================================
# HTTP Client with Rate Limiting & Retries
# ============================================================================

class RateLimitedClient:
    """Async HTTP client with rate limiting, caching, and retry logic."""

    def __init__(self, max_concurrency: int = DEFAULT_CONCURRENCY, logger: Optional[logging.Logger] = None):
        self.semaphore = asyncio.Semaphore(max_concurrency)
        self.session: Optional[aiohttp.ClientSession] = None
        self.logger = logger or logging.getLogger("ip_finder")

    async def __aenter__(self):
        timeout = aiohttp.ClientTimeout(total=HTTP_TIMEOUT)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT}
        )
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError))
    )
    async def get(self, url: str, headers: Optional[Dict] = None,
                  cache_key: Optional[str] = None, params: Optional[Dict] = None) -> Optional[Dict]:
        """Perform GET request with caching and retry."""
        # Check cache first
        if cache_key:
            cached_data = get_cached(cache_key)
            if cached_data is not None:
                self.logger.debug(f"Cache hit: {cache_key}")
                return cached_data

        async with self.semaphore:
            try:
                self.logger.debug(f"GET {url}")
                async with self.session.get(url, headers=headers, params=params, ssl=False) as response:
                    if response.status == 200:
                        data = await response.json()
                        if cache_key:
                            set_cache(cache_key, data)
                        return data
                    elif response.status == 429:
                        self.logger.warning(f"Rate limited on {url}, waiting...")
                        await asyncio.sleep(5)
                        raise aiohttp.ClientError("Rate limited")
                    elif response.status in [401, 403]:
                        self.logger.warning(f"Auth failed for {url}: {response.status}")
                        return None
                    else:
                        self.logger.debug(f"HTTP {response.status} for {url}")
                        return None
            except asyncio.TimeoutError:
                self.logger.debug(f"Timeout for {url}")
                raise
            except aiohttp.ClientError as e:
                self.logger.debug(f"HTTP error for {url}: {e}")
                raise
            except Exception as e:
                self.logger.debug(f"Unexpected error for {url}: {e}")
                return None

    async def post(self, url: str, headers: Optional[Dict] = None,
                   json_data: Optional[Dict] = None, data: Optional[Dict] = None) -> Optional[Dict]:
        """Perform POST request with retry."""
        async with self.semaphore:
            try:
                self.logger.debug(f"POST {url}")
                async with self.session.post(url, headers=headers, json=json_data, data=data, ssl=False) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        self.logger.debug(f"HTTP {response.status} for {url}")
                        return None
            except Exception as e:
                self.logger.debug(f"POST error for {url}: {e}")
                return None

# ============================================================================
# IP Result Data Structure
# ============================================================================

class IPResult:
    """Container for discovered IP address with metadata."""

    def __init__(self, ip: str, source: str):
        self.ip = ip
        self.sources: Set[str] = {source}
        self.first_seen = datetime.now().isoformat()
        self.asn: Optional[str] = None
        self.netblock: Optional[str] = None
        self.country: Optional[str] = None
        self.ptr: Optional[str] = None
        self.ports: List[int] = []
        self.notes: str = ""

    def merge(self, other: 'IPResult') -> None:
        """Merge another IPResult into this one."""
        self.sources.update(other.sources)
        if other.asn and not self.asn:
            self.asn = other.asn
        if other.netblock and not self.netblock:
            self.netblock = other.netblock
        if other.country and not self.country:
            self.country = other.country
        if other.ptr and not self.ptr:
            self.ptr = other.ptr
        if other.ports:
            self.ports.extend(other.ports)
        if other.notes:
            self.notes = self.notes + "; " + other.notes if self.notes else other.notes

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "ip": self.ip,
            "sources": sorted(list(self.sources)),
            "first_seen": self.first_seen,
            "asn": self.asn,
            "netblock": self.netblock,
            "country": self.country,
            "ptr": self.ptr,
            "ports": sorted(list(set(self.ports))) if self.ports else [],
            "notes": self.notes
        }

# ============================================================================
# Data Source Collectors
# ============================================================================

class IPCollector:
    """Base class for IP address collectors."""

    def __init__(self, client: RateLimitedClient, config: Dict[str, str], logger: logging.Logger):
        self.client = client
        self.config = config
        self.logger = logger
        self.name = self.__class__.__name__.replace("Collector", "")

    def is_configured(self) -> bool:
        """Check if this collector has required API keys."""
        return True

    async def collect(self, target: str) -> List[IPResult]:
        """Collect IPs for target. Override in subclasses."""
        raise NotImplementedError

class CrtShCollector(IPCollector):
    """Certificate Transparency log collector via crt.sh."""

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        try:
            url = API_CONFIGS["crt_sh"].format(query=quote(f"%.{target}"))
            cache_key = f"crt_sh:{target}"

            data = await self.client.get(url, cache_key=cache_key)
            if not data:
                return results

            # Extract unique domain names from certificates
            domains = set()
            for cert in data:
                name_value = cert.get("name_value", "")
                for domain in name_value.split("\n"):
                    domain = domain.strip().lower()
                    if domain and not domain.startswith("*"):
                        domains.add(domain)

            # Resolve each domain to IPs
            self.logger.info(f"crt.sh found {len(domains)} unique domains, resolving...")
            for domain in list(domains)[:100]:  # Limit to avoid overload
                ips = await self._resolve_domain(domain)
                for ip in ips:
                    results.append(IPResult(ip, "crt.sh"))

        except Exception as e:
            self.logger.debug(f"crt.sh error: {e}")

        return results

    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IP addresses."""
        ips = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            for qtype in ['A', 'AAAA']:
                try:
                    answers = await asyncio.to_thread(resolver.resolve, domain, qtype)
                    for rdata in answers:
                        ips.append(str(rdata))
                except Exception:
                    pass
        except Exception:
            pass
        return ips

class CensysCollector(IPCollector):
    """Censys search API collector."""

    def is_configured(self) -> bool:
        return "CENSYS_API_ID" in self.config and "CENSYS_API_SECRET" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            auth = aiohttp.BasicAuth(
                self.config["CENSYS_API_ID"],
                self.config["CENSYS_API_SECRET"]
            )

            query = f"services.tls.certificates.leaf_data.subject.common_name: {target}"
            url = API_CONFIGS["censys_search"]

            headers = {"Accept": "application/json"}
            params = {"q": query, "per_page": 100}

            # Note: Censys requires special handling - using post with auth
            async with self.client.semaphore:
                try:
                    async with self.client.session.get(
                        url,
                        auth=auth,
                        headers=headers,
                        params=params,
                        ssl=False
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            hits = data.get("result", {}).get("hits", [])

                            for hit in hits:
                                ip = hit.get("ip")
                                if ip and is_valid_ip(ip):
                                    result = IPResult(ip, "censys")
                                    result.asn = hit.get("autonomous_system", {}).get("asn")
                                    result.country = hit.get("location", {}).get("country")
                                    services = hit.get("services", [])
                                    result.ports = [s.get("port") for s in services if s.get("port")]
                                    results.append(result)
                        elif response.status in [401, 403]:
                            self.logger.warning(f"Censys auth failed")
                except Exception as e:
                    self.logger.debug(f"Censys request error: {e}")

        except Exception as e:
            self.logger.debug(f"Censys error: {e}")

        return results

class ShodanCollector(IPCollector):
    """Shodan search API collector."""

    def is_configured(self) -> bool:
        return "SHODAN_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            api_key = self.config["SHODAN_API_KEY"]
            url = API_CONFIGS["shodan_search"]
            params = {"key": api_key, "query": f"hostname:{target}"}
            cache_key = f"shodan:{target}"

            data = await self.client.get(url, params=params, cache_key=cache_key)
            if not data:
                return results

            matches = data.get("matches", [])
            for match in matches:
                ip = match.get("ip_str")
                if ip and is_valid_ip(ip):
                    result = IPResult(ip, "shodan")
                    result.asn = match.get("asn")
                    result.country = match.get("location", {}).get("country_code")
                    result.ports = [match.get("port")] if match.get("port") else []
                    hostnames = match.get("hostnames", [])
                    if hostnames:
                        result.ptr = hostnames[0]
                    results.append(result)

        except Exception as e:
            self.logger.debug(f"Shodan error: {e}")

        return results

class ZoomEyeCollector(IPCollector):
    """ZoomEye search API collector."""

    def is_configured(self) -> bool:
        return "ZOOMEYE_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            api_key = self.config["ZOOMEYE_API_KEY"]
            url = API_CONFIGS["zoomeye_search"]
            headers = {"API-KEY": api_key}
            params = {"query": f"hostname:{target}", "page": 1}
            cache_key = f"zoomeye:{target}"

            data = await self.client.get(url, headers=headers, params=params, cache_key=cache_key)
            if not data:
                return results

            matches = data.get("matches", [])
            for match in matches:
                ip = match.get("ip")
                if ip and is_valid_ip(ip):
                    result = IPResult(ip, "zoomeye")
                    result.ports = [match.get("portinfo", {}).get("port")] if match.get("portinfo", {}).get("port") else []
                    results.append(result)

        except Exception as e:
            self.logger.debug(f"ZoomEye error: {e}")

        return results

class VirusTotalCollector(IPCollector):
    """VirusTotal domain and passive DNS collector."""

    def is_configured(self) -> bool:
        return "VT_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            api_key = self.config["VT_API_KEY"]
            headers = {"x-apikey": api_key}

            # Get domain resolutions (passive DNS)
            url = API_CONFIGS["virustotal_resolutions"].format(domain=target)
            cache_key = f"vt_resolutions:{target}"

            data = await self.client.get(url, headers=headers, cache_key=cache_key)
            if data and "data" in data:
                for resolution in data["data"]:
                    ip = resolution.get("attributes", {}).get("ip_address")
                    if ip and is_valid_ip(ip):
                        result = IPResult(ip, "virustotal")
                        result.notes = "Passive DNS resolution"
                        results.append(result)

        except Exception as e:
            self.logger.debug(f"VirusTotal error: {e}")

        return results

class FOFACollector(IPCollector):
    """FOFA search API collector."""

    def is_configured(self) -> bool:
        return "FOFA_EMAIL" in self.config and "FOFA_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            import base64

            email = self.config["FOFA_EMAIL"]
            key = self.config["FOFA_KEY"]

            query = f'domain="{target}"'
            encoded_query = base64.b64encode(query.encode()).decode()

            url = API_CONFIGS["fofa_search"]
            params = {
                "email": email,
                "key": key,
                "qbase64": encoded_query,
                "size": 100,
                "fields": "ip,port,country"
            }
            cache_key = f"fofa:{target}"

            data = await self.client.get(url, params=params, cache_key=cache_key)
            if not data or "results" not in data:
                return results

            for result_row in data["results"]:
                if result_row and len(result_row) >= 1:
                    ip = result_row[0]
                    if ip and is_valid_ip(ip):
                        result = IPResult(ip, "fofa")
                        if len(result_row) >= 2:
                            result.ports = [int(result_row[1])] if result_row[1] else []
                        if len(result_row) >= 3:
                            result.country = result_row[2]
                        results.append(result)

        except Exception as e:
            self.logger.debug(f"FOFA error: {e}")

        return results

class BinaryEdgeCollector(IPCollector):
    """BinaryEdge subdomain and host discovery collector."""

    def is_configured(self) -> bool:
        return "BINARYEDGE_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            api_key = self.config["BINARYEDGE_API_KEY"]
            headers = {"X-Key": api_key}
            url = API_CONFIGS["binaryedge_domain"].format(domain=target)
            cache_key = f"binaryedge:{target}"

            data = await self.client.get(url, headers=headers, cache_key=cache_key)
            if not data:
                return results

            # BinaryEdge returns subdomains; we need to resolve them
            subdomains = data.get("events", [])
            for subdomain in subdomains[:50]:  # Limit
                ips = await self._resolve_domain(subdomain)
                for ip in ips:
                    results.append(IPResult(ip, "binaryedge"))

        except Exception as e:
            self.logger.debug(f"BinaryEdge error: {e}")

        return results

    async def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IPs."""
        ips = []
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            for qtype in ['A', 'AAAA']:
                try:
                    answers = await asyncio.to_thread(resolver.resolve, domain, qtype)
                    for rdata in answers:
                        ips.append(str(rdata))
                except Exception:
                    pass
        except Exception:
            pass
        return ips

class SecurityTrailsCollector(IPCollector):
    """SecurityTrails passive DNS and domain collector."""

    def is_configured(self) -> bool:
        return "SECURITYTRAILS_API_KEY" in self.config

    async def collect(self, target: str) -> List[IPResult]:
        results = []
        if not self.is_configured():
            return results

        try:
            api_key = self.config["SECURITYTRAILS_API_KEY"]
            headers = {"APIKEY": api_key}
            url = API_CONFIGS["securitytrails_domain"].format(domain=target)
            cache_key = f"securitytrails:{target}"

            data = await self.client.get(url, headers=headers, cache_key=cache_key)
            if not data:
                return results

            # Get current IPs
            current_dns = data.get("current_dns", {})
            a_records = current_dns.get("a", {}).get("values", [])
            aaaa_records = current_dns.get("aaaa", {}).get("values", [])

            for record in a_records + aaaa_records:
                ip = record.get("ip")
                if ip and is_valid_ip(ip):
                    results.append(IPResult(ip, "securitytrails"))

        except Exception as e:
            self.logger.debug(f"SecurityTrails error: {e}")

        return results

class DNSCollector(IPCollector):
    """Local DNS resolution collector (A, AAAA, MX, NS, CNAME)."""

    def is_configured(self) -> bool:
        return True  # Always available

    async def collect(self, target: str) -> List[IPResult]:
        results = []

        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            # Direct A/AAAA records
            for qtype in ['A', 'AAAA']:
                try:
                    answers = await asyncio.to_thread(resolver.resolve, target, qtype)
                    for rdata in answers:
                        ip = str(rdata)
                        result = IPResult(ip, "dns")
                        result.notes = f"{qtype} record"
                        results.append(result)
                except Exception:
                    pass

            # MX records
            try:
                mx_answers = await asyncio.to_thread(resolver.resolve, target, 'MX')
                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip('.')
                    for qtype in ['A', 'AAAA']:
                        try:
                            answers = await asyncio.to_thread(resolver.resolve, mx_host, qtype)
                            for ip_rdata in answers:
                                ip = str(ip_rdata)
                                result = IPResult(ip, "dns")
                                result.notes = f"MX record for {mx_host}"
                                results.append(result)
                        except Exception:
                            pass
            except Exception:
                pass

            # NS records
            try:
                ns_answers = await asyncio.to_thread(resolver.resolve, target, 'NS')
                for rdata in ns_answers:
                    ns_host = str(rdata).rstrip('.')
                    for qtype in ['A', 'AAAA']:
                        try:
                            answers = await asyncio.to_thread(resolver.resolve, ns_host, qtype)
                            for ip_rdata in answers:
                                ip = str(ip_rdata)
                                result = IPResult(ip, "dns")
                                result.notes = f"NS record for {ns_host}"
                                results.append(result)
                        except Exception:
                            pass
            except Exception:
                pass

        except Exception as e:
            self.logger.debug(f"DNS error: {e}")

        return results

class PTRCollector(IPCollector):
    """Reverse DNS (PTR) lookup collector."""

    def is_configured(self) -> bool:
        return True  # Always available

    async def collect_for_ip(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup for single IP."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            rev_name = dns.reversename.from_address(ip)
            answers = await asyncio.to_thread(resolver.resolve, rev_name, 'PTR')

            if answers:
                return str(answers[0]).rstrip('.')
        except Exception:
            pass

        return None

    async def collect(self, target: str) -> List[IPResult]:
        """Not used directly - used to enrich existing IPs."""
        return []

class ASNCollector(IPCollector):
    """Team Cymru IP to ASN collector."""

    def is_configured(self) -> bool:
        return True  # Public service

    async def collect_for_ip(self, ip: str) -> Tuple[Optional[str], Optional[str]]:
        """Query Team Cymru for ASN and netblock."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = DNS_TIMEOUT
            resolver.lifetime = DNS_TIMEOUT

            # Construct origin query for Team Cymru
            ip_obj = ip_address(ip)
            if isinstance(ip_obj, IPv4Address):
                parts = ip.split('.')
                origin_query = f"{parts[3]}.{parts[2]}.{parts[1]}.{parts[0]}.origin.asn.cymru.com"
            else:
                # IPv6 support
                rev = dns.reversename.from_address(ip)
                origin_query = str(rev).replace('.ip6.arpa.', '.origin6.asn.cymru.com.')

            answers = await asyncio.to_thread(resolver.resolve, origin_query, 'TXT')

            if answers:
                # Parse response: "ASN | IP Prefix | CC | Registry | Allocated"
                txt = str(answers[0]).strip('"')
                parts = [p.strip() for p in txt.split('|')]
                if len(parts) >= 2:
                    asn = f"AS{parts[0]}"
                    netblock = parts[1]
                    return asn, netblock
        except Exception:
            pass

        return None, None

    async def collect(self, target: str) -> List[IPResult]:
        """Not used directly - used to enrich existing IPs."""
        return []

class BGPHECollector(IPCollector):
    """BGP.he.net scraper (optional, behind flag)."""

    def is_configured(self) -> bool:
        return True  # Public service, but scraping

    async def collect(self, target: str) -> List[IPResult]:
        """
        TODO: Implement BGP.he.net scraping for netblock enumeration.
        This should be behind --enable-scrape flag.

        Implementation notes:
        1. Query bgp.he.net for ASN associated with target
        2. Scrape netblocks announced by that ASN
        3. Optionally enumerate IPs in small netblocks
        4. Respect robots.txt and add delays between requests
        """
        results = []
        # Placeholder - user should enable with --enable-scrape
        return results

# ============================================================================
# Main IP Finder Engine
# ============================================================================

class IPFinder:
    """Main orchestrator for IP discovery."""

    def __init__(self, config: Dict[str, str], max_concurrency: int = DEFAULT_CONCURRENCY,
                 logger: Optional[logging.Logger] = None, limit_sources: Optional[List[str]] = None):
        self.config = config
        self.max_concurrency = max_concurrency
        self.logger = logger or logging.getLogger("ip_finder")
        self.limit_sources = limit_sources
        self.results: Dict[str, IPResult] = {}

    async def discover(self, targets: List[str]) -> Dict[str, IPResult]:
        """Main discovery orchestration."""
        async with RateLimitedClient(self.max_concurrency, self.logger) as client:
            # Initialize collectors
            collectors = [
                CrtShCollector(client, self.config, self.logger),
                CensysCollector(client, self.config, self.logger),
                ShodanCollector(client, self.config, self.logger),
                ZoomEyeCollector(client, self.config, self.logger),
                VirusTotalCollector(client, self.config, self.logger),
                FOFACollector(client, self.config, self.logger),
                BinaryEdgeCollector(client, self.config, self.logger),
                SecurityTrailsCollector(client, self.config, self.logger),
                DNSCollector(client, self.config, self.logger),
            ]

            # Filter collectors if limit_sources specified
            if self.limit_sources:
                collectors = [c for c in collectors if c.name.lower() in [s.lower() for s in self.limit_sources]]

            # Check configured sources
            configured = [c for c in collectors if c.is_configured()]
            unconfigured = [c for c in collectors if not c.is_configured()]

            self.logger.info(f"Active sources: {', '.join([c.name for c in configured])}")
            if unconfigured:
                self.logger.warning(f"Skipping unconfigured sources: {', '.join([c.name for c in unconfigured])}")

            # Collect from all sources for all targets
            tasks = []
            for target in targets:
                for collector in configured:
                    tasks.append(self._collect_with_progress(collector, target))

            # Execute all collection tasks
            all_results = await asyncio.gather(*tasks, return_exceptions=True)

            # Flatten and merge results
            for item in all_results:
                if isinstance(item, list):
                    for ip_result in item:
                        self._merge_result(ip_result)
                elif isinstance(item, Exception):
                    self.logger.debug(f"Collection task failed: {item}")

            # Filter out private IPs
            self.results = {
                ip: result for ip, result in self.results.items()
                if not is_private_ip(ip)
            }

            # Enrich with PTR and ASN
            await self._enrich_results(client)

            return self.results

    async def _collect_with_progress(self, collector: IPCollector, target: str) -> List[IPResult]:
        """Collect with error handling."""
        try:
            return await collector.collect(target)
        except Exception as e:
            self.logger.debug(f"{collector.name} collection failed for {target}: {e}")
            return []

    def _merge_result(self, ip_result: IPResult) -> None:
        """Merge IP result into results dict."""
        if ip_result.ip in self.results:
            self.results[ip_result.ip].merge(ip_result)
        else:
            self.results[ip_result.ip] = ip_result

    async def _enrich_results(self, client: RateLimitedClient) -> None:
        """Enrich results with PTR and ASN data."""
        if not self.results:
            return

        self.logger.info(f"Enriching {len(self.results)} IPs with PTR and ASN data...")

        ptr_collector = PTRCollector(client, self.config, self.logger)
        asn_collector = ASNCollector(client, self.config, self.logger)

        tasks = []
        for ip in self.results.keys():
            tasks.append(self._enrich_single_ip(ip, ptr_collector, asn_collector))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _enrich_single_ip(self, ip: str, ptr_collector: PTRCollector,
                                asn_collector: ASNCollector) -> None:
        """Enrich single IP with PTR and ASN."""
        try:
            result = self.results[ip]

            # PTR lookup
            if not result.ptr:
                ptr = await ptr_collector.collect_for_ip(ip)
                if ptr:
                    result.ptr = ptr

            # ASN lookup
            if not result.asn:
                asn, netblock = await asn_collector.collect_for_ip(ip)
                if asn:
                    result.asn = asn
                if netblock:
                    result.netblock = netblock

        except Exception as e:
            self.logger.debug(f"Enrichment failed for {ip}: {e}")

# ============================================================================
# Output Handlers
# ============================================================================

def export_json(results: Dict[str, IPResult], output_path: str) -> None:
    """Export results to JSON file."""
    data = [r.to_dict() for r in results.values()]
    with open(output_path, 'w') as f:
        json.dump(data, f, indent=2)

def export_csv(results: Dict[str, IPResult], output_path: str) -> None:
    """Export results to CSV file."""
    with open(output_path, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['IP', 'Sources', 'First Seen', 'ASN', 'Netblock', 'Country', 'PTR', 'Ports', 'Notes'])

        for result in results.values():
            writer.writerow([
                result.ip,
                ';'.join(sorted(result.sources)),
                result.first_seen,
                result.asn or '',
                result.netblock or '',
                result.country or '',
                result.ptr or '',
                ';'.join(map(str, sorted(set(result.ports)))),
                result.notes
            ])

def export_txt(results: Dict[str, IPResult], output_path: str) -> None:
    """Export results to plain text file (one IP per line)."""
    with open(output_path, 'w') as f:
        for ip in sorted(results.keys()):
            f.write(f"{ip}\n")

def print_results_table(results: Dict[str, IPResult]) -> None:
    """Print results to stdout in a readable table format."""
    if not results:
        print("\n[!] No IP addresses discovered")
        return

    print(f"\n{'='*100}")
    print(f"{'IP ADDRESS':<40} {'SOURCES':<30} {'ASN':<15} {'COUNTRY':<10}")
    print(f"{'='*100}")

    for ip, result in sorted(results.items()):
        sources_str = ', '.join(sorted(result.sources)[:3])  # Show first 3 sources
        if len(result.sources) > 3:
            sources_str += f" +{len(result.sources)-3} more"

        asn_str = result.asn or 'N/A'
        country_str = result.country or 'N/A'

        print(f"{ip:<40} {sources_str:<30} {asn_str:<15} {country_str:<10}")

    print(f"{'='*100}")
    print(f"\nTotal IPs discovered: {len(results)}")

    # Source breakdown
    source_counts = {}
    for result in results.values():
        for source in result.sources:
            source_counts[source] = source_counts.get(source, 0) + 1

    print(f"\nIPs by source:")
    for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {source:<20} {count} IPs")
    print()

def print_sources_status(config: Dict[str, str]) -> None:
    """Print which sources are configured and which are not."""
    print("\n=== Data Sources Status ===\n")

    sources = {
        "crt.sh": ("Always available", True),
        "DNS": ("Always available", True),
        "Censys": ("CENSYS_API_ID, CENSYS_API_SECRET", "CENSYS_API_ID" in config),
        "Shodan": ("SHODAN_API_KEY", "SHODAN_API_KEY" in config),
        "ZoomEye": ("ZOOMEYE_API_KEY", "ZOOMEYE_API_KEY" in config),
        "VirusTotal": ("VT_API_KEY", "VT_API_KEY" in config),
        "FOFA": ("FOFA_EMAIL, FOFA_KEY", "FOFA_EMAIL" in config and "FOFA_KEY" in config),
        "BinaryEdge": ("BINARYEDGE_API_KEY", "BINARYEDGE_API_KEY" in config),
        "SecurityTrails": ("SECURITYTRAILS_API_KEY", "SECURITYTRAILS_API_KEY" in config),
        "Team Cymru ASN": ("Always available", True),
    }

    for name, (requirement, configured) in sources.items():
        status = "✓ CONFIGURED" if configured else "✗ NOT CONFIGURED"
        print(f"{name:20} {status:20} ({requirement})")

    print()

# ============================================================================
# CLI & Main
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="IP Finder - Advanced IP Discovery Tool for Security Research",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com
  %(prog)s --target example.com --output results.json
  %(prog)s --target example.com --output results.csv --format csv
  %(prog)s --target example.com --output ips.txt --format txt
  %(prog)s --target example.com --sources-only
  %(prog)s --target-file subdomains.txt --max-concurrency 20

Environment Variables:
  SHODAN_API_KEY              Shodan API key
  CENSYS_API_ID               Censys API ID
  CENSYS_API_SECRET           Censys API secret
  VT_API_KEY                  VirusTotal API key
  ZOOMEYE_API_KEY             ZoomEye API key
  FOFA_EMAIL                  FOFA account email
  FOFA_KEY                    FOFA API key
  BINARYEDGE_API_KEY          BinaryEdge API key
  SECURITYTRAILS_API_KEY      SecurityTrails API key

For detailed documentation, see README.md
        """
    )

    parser.add_argument('--target', type=str, help='Target domain (e.g., example.com)')
    parser.add_argument('--org', type=str, help='Organization name (for WHOIS/RDAP queries)')
    parser.add_argument('--target-file', type=str, help='File containing list of domains/subdomains')
    parser.add_argument('--output', type=str, help='Output file path (if not specified, results only shown on screen)')
    parser.add_argument('--format', choices=['json', 'csv', 'txt'], default='json',
                       help='Output format: json (full details), csv (spreadsheet), txt (IPs only)')
    parser.add_argument('--apikey-config', type=str, help='Path to YAML config file with API keys')
    parser.add_argument('--max-concurrency', type=int, default=DEFAULT_CONCURRENCY,
                       help='Maximum concurrent requests')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--quiet', '-q', action='store_true', help='Minimal output')
    parser.add_argument('--sources-only', action='store_true',
                       help='Show available sources and exit')
    parser.add_argument('--limit-source', action='append', dest='limit_sources',
                       help='Limit to specific sources (can be used multiple times)')
    parser.add_argument('--dry-run', action='store_true',
                       help='Dry run with mock data (for testing)')
    parser.add_argument('--enable-scrape', action='store_true',
                       help='Enable web scraping sources (bgp.he.net) - use responsibly')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')

    return parser.parse_args()

async def main_async(args: argparse.Namespace) -> int:
    """Async main function."""
    # Setup logging
    logger = setup_logging(args.verbose, args.quiet)
    logger.info(f"IP Finder v{VERSION} starting...")

    # Load configuration
    config = load_config(args.apikey_config)

    # Show sources status if requested
    if args.sources_only:
        print_sources_status(config)
        return 0

    # Validate input
    targets = []
    if args.target:
        targets.append(args.target)

    if args.target_file:
        try:
            with open(args.target_file, 'r') as f:
                file_targets = [line.strip() for line in f if line.strip()]
                targets.extend(file_targets)
        except Exception as e:
            logger.error(f"Failed to read target file: {e}")
            return 1

    if not targets:
        logger.error("No targets specified. Use --target or --target-file")
        return 1

    logger.info(f"Loaded {len(targets)} target(s)")

    # Dry run mode
    if args.dry_run:
        logger.info("DRY RUN mode - using mock data")
        mock_result = IPResult("93.184.216.34", "mock")
        mock_result.asn = "AS15133"
        mock_result.country = "US"
        mock_result.ptr = "example.com"
        results = {"93.184.216.34": mock_result}
    else:
        # Run discovery
        finder = IPFinder(config, args.max_concurrency, logger, args.limit_sources)
        results = await finder.discover(targets)

    # Output results
    if not results:
        logger.warning("No IP addresses discovered")
        return 0

    logger.info(f"Discovered {len(results)} unique IP addresses")

    # Always print results to stdout (unless quiet mode)
    if not args.quiet:
        print_results_table(results)

    # Export to file only if --output is specified
    if args.output:
        try:
            if args.format == 'json':
                export_json(results, args.output)
            elif args.format == 'csv':
                export_csv(results, args.output)
            elif args.format == 'txt':
                export_txt(results, args.output)

            logger.info(f"Results saved to {args.output}")
            if not args.quiet:
                print(f"\n[+] Results saved to: {args.output}")
        except Exception as e:
            logger.error(f"Failed to export results: {e}")
            return 1

    return 0

def main() -> int:
    """Main entry point."""
    args = parse_args()

    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\nInterrupted by user")
        return 130
    except Exception as e:
        logging.getLogger("ip_finder").error(f"Fatal error: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    sys.exit(main())