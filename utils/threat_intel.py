import ipaddress
import os
import time
from typing import Any

import httpx


GEO_CACHE_TTL_SECONDS = 3600
_geo_cache: dict[str, tuple[float, dict[str, Any]]] = {}


def enrich_ip(ip: str) -> dict[str, Any]:
    base = {
        "ip": ip,
        "scope": "unknown",
        "country": "Unknown",
        "city": "Unknown",
        "latitude": None,
        "longitude": None,
        "asn": "Unknown",
        "isp": "Unknown",
        "vpn_risk": "Unknown",
        "vpn_reason": "Geo lookup not enabled or unavailable",
    }

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return base | {"vpn_reason": "Invalid IP address"}

    if addr.is_loopback:
        return base | {
            "scope": "loopback",
            "country": "Localhost",
            "city": "Local machine",
            "vpn_risk": "None",
            "vpn_reason": "Loopback traffic generated on this host",
        }

    if addr.is_private:
        return base | {
            "scope": "private",
            "country": "Private network",
            "city": "LAN",
            "vpn_risk": "Low",
            "vpn_reason": "RFC1918/private address; external VPN reputation does not apply",
        }

    if addr.is_reserved or addr.is_multicast or addr.is_unspecified:
        return base | {
            "scope": "reserved",
            "country": "Reserved",
            "city": "Non-routable",
            "vpn_risk": "Unknown",
            "vpn_reason": "Reserved or non-routable address",
        }

    base["scope"] = "public"
    if os.getenv("ORION_GEOLOOKUP_ENABLED", "").strip().lower() not in {"1", "true", "yes", "on"}:
        return base | {"vpn_reason": "Public IP; enable ORION_GEOLOOKUP_ENABLED=true for live geo/VPN context"}

    cached = _geo_cache.get(ip)
    now = time.time()
    if cached and now - cached[0] < GEO_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        response = httpx.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,message,country,city,lat,lon,as,isp,proxy,hosting,mobile"},
            timeout=2.5,
        )
        response.raise_for_status()
        data = response.json()
        if data.get("status") != "success":
            return base | {"vpn_reason": data.get("message", "Geo provider returned no match")}

        proxy = bool(data.get("proxy"))
        hosting = bool(data.get("hosting"))
        mobile = bool(data.get("mobile"))
        if proxy or hosting:
            vpn_risk = "Elevated"
            reason = "Geo provider marked this IP as proxy/VPN or hosting infrastructure"
        elif mobile:
            vpn_risk = "Medium"
            reason = "Mobile carrier address; attribution may be weak"
        else:
            vpn_risk = "Low"
            reason = "No proxy/hosting indicator returned by geo provider"

        enriched = base | {
            "country": data.get("country") or "Unknown",
            "city": data.get("city") or "Unknown",
            "latitude": data.get("lat"),
            "longitude": data.get("lon"),
            "asn": data.get("as") or "Unknown",
            "isp": data.get("isp") or "Unknown",
            "vpn_risk": vpn_risk,
            "vpn_reason": reason,
        }
        _geo_cache[ip] = (now, enriched)
        return enriched
    except Exception as e:
        return base | {"vpn_reason": f"Geo lookup failed: {e}"}

