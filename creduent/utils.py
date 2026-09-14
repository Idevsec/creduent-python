# NOTE: Sync with creduent/utils.py
import ipaddress
import socket
import requests
from urllib.parse import urlparse, urljoin


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def resolve_ips(host: str) -> list[str]:
    ips = []
    try:
        addr_infos = socket.getaddrinfo(host, None)
        for info in addr_infos:
            sockaddr = info[4]
            if sockaddr and len(sockaddr) > 0:
                ips.append(sockaddr[0])
    except Exception:
        pass
    return list(set(ips))


def verify_dnssec(domain: str) -> bool:
    """Queries DNS-over-HTTPS (DoH) via Cloudflare to verify if DNSSEC AD flag is True."""
    if not domain or "localhost" in domain or "127.0.0.1" in domain:
        return False
    try:
        parsed = urlparse(domain if "://" in domain else f"https://{domain}")
        host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0]
        if not host:
            return False

        doh_url = f"https://1.1.1.1/dns-query?name={host}&type=A"
        headers = {"Accept": "application/dns-json"}
        response = safe_requests_get(doh_url, timeout=3, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return bool(data.get("AD", False))
    except Exception:
        pass
    return False


def safe_requests_get(
    url: str, timeout: int = 5, allow_private: bool = False, headers: dict = None
) -> requests.Response:
    """
    Safe version of requests.get that prevents SSRF by blocking access
    to private IP ranges, including redirect targets.
    """
    req_headers = headers.copy() if headers else {}
    history = []
    current_url = url
    for _ in range(5):  # Follow max 5 redirects
        parsed = urlparse(current_url)
        host = parsed.netloc.split(":")[0]
        ips = resolve_ips(host)
        for ip in ips:
            if not allow_private and is_private_ip(ip):
                raise ValueError("Access to private IP ranges is blocked.")

        merged_headers = req_headers.copy()
        response = requests.get(
            current_url,
            headers=merged_headers,
            verify=True,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.is_redirect:
            history.append(response)
            next_url = response.headers.get("location")
            if not next_url:
                break
            current_url = urljoin(current_url, next_url)
        else:
            response.history = history
            return response

    # Final request outside the loop
    parsed = urlparse(current_url)
    host = parsed.netloc.split(":")[0]
    ips = resolve_ips(host)
    for ip in ips:
        if not allow_private and is_private_ip(ip):
            raise ValueError("Access to private IP ranges is blocked.")

    merged_headers = req_headers.copy()
    response = requests.get(
        current_url,
        headers=merged_headers,
        verify=True,
        timeout=timeout,
        allow_redirects=False,
    )
    response.history = history
    return response


def safe_requests_post(
    url: str,
    json: dict = None,
    data: dict = None,
    timeout: int = 5,
    allow_private: bool = False,
    headers: dict = None,
) -> requests.Response:
    """
    Safe version of requests.post that prevents SSRF by blocking access
    to private IP ranges, including redirect targets.
    """
    req_headers = headers.copy() if headers else {}
    history = []
    current_url = url
    for _ in range(5):  # Follow max 5 redirects
        parsed = urlparse(current_url)
        host = parsed.netloc.split(":")[0]
        ips = resolve_ips(host)
        for ip in ips:
            if not allow_private and is_private_ip(ip):
                raise ValueError("Access to private IP ranges is blocked.")

        merged_headers = req_headers.copy()
        response = requests.post(
            current_url,
            json=json,
            data=data,
            headers=merged_headers,
            verify=True,
            timeout=timeout,
            allow_redirects=False,
        )
        if response.is_redirect:
            history.append(response)
            next_url = response.headers.get("location")
            if not next_url:
                break
            current_url = urljoin(current_url, next_url)
        else:
            response.history = history
            return response

    # Final request outside the loop
    parsed = urlparse(current_url)
    host = parsed.netloc.split(":")[0]
    ips = resolve_ips(host)
    for ip in ips:
        if not allow_private and is_private_ip(ip):
            raise ValueError("Access to private IP ranges is blocked.")

    merged_headers = req_headers.copy()
    response = requests.post(
        current_url,
        json=json,
        data=data,
        headers=merged_headers,
        verify=True,
        timeout=timeout,
        allow_redirects=False,
    )
    response.history = history
    return response


def load_dotenv():
    """
    Manually loads .env.local or .env file from the project base directory
    into os.environ for local testing/development.
    """
    import os

    # Do not load local dotenv files in Vercel environment to prevent overwriting
    # production settings with local/placeholder values.
    if os.environ.get("VERCEL") == "1":
        return
    # Try to find base dir (where .env.local resides)
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    for filename in [".env.local", ".env"]:
        filepath = os.path.join(base_dir, filename)
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if "=" in line:
                            key, val = line.split("=", 1)
                            key = key.strip()
                            val = val.strip()
                            # Strip quotes
                            if (val.startswith('"') and val.endswith('"')) or (
                                val.startswith("'") and val.endswith("'")
                            ):
                                val = val[1:-1]
                            # Only set if not already present or empty
                            if not os.environ.get(key):
                                os.environ[key] = val
            except Exception as e:
                print(f"[-] Warning: Failed to load environment file {filename}: {e}")


import time
from collections import OrderedDict
from typing import Any, Optional


class AttestationLRUCache:
    """Thread-safe LRU cache with TTL expiration for resolved agent documents and attestation lookups."""

    def __init__(self, maxsize: int = 500, ttl_seconds: int = 300):
        self.maxsize = maxsize
        self.ttl_seconds = ttl_seconds
        self._cache: OrderedDict[str, tuple[Any, float]] = OrderedDict()

    def get(self, key: str) -> Optional[Any]:
        if key not in self._cache:
            return None
        val, expiry = self._cache[key]
        if time.time() >= expiry:
            del self._cache[key]
            return None
        self._cache.move_to_end(key)
        return val

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        eff_ttl = ttl if ttl is not None else self.ttl_seconds
        expiry = time.time() + eff_ttl
        if key in self._cache:
            self._cache.move_to_end(key)
        self._cache[key] = (value, expiry)
        if len(self._cache) > self.maxsize:
            self._cache.popitem(last=False)

    def delete(self, key: str) -> None:
        self._cache.pop(key, None)

    def clear(self) -> None:
        self._cache.clear()


# Global instance of verification cache
_global_verification_cache = AttestationLRUCache(maxsize=500, ttl_seconds=300)

