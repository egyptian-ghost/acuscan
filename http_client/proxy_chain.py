#!/usr/bin/env python3
"""Proxy chain support."""


def build_proxies(config):
    """Build proxies dict for requests."""
    proxy_chain = config.get("proxy_chain") or []
    proxy_url = config.get("proxy")
    if proxy_chain:
        return {"http": proxy_chain[0], "https": proxy_chain[0]}
    elif proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    return {}


def get_proxy_tags(config):
    """Return headers describing proxy chain (for Burp filtering)."""
    proxy_chain = config.get("proxy_chain") or []
    proxy_url = config.get("proxy")
    tags = {}
    if proxy_chain:
        tags["X-AcuScan-Proxy-Chain"] = ",".join(proxy_chain)
    elif proxy_url:
        tags["X-AcuScan-Scanner"] = "AcuScan/v6.0"
    return tags