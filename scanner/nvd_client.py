import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen


NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"

_CACHE = {}
_LAST_REQUEST_AT = 0.0


def _english_description(cve):
    for desc in cve.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _metric_from(metrics, names):
    for name in names:
        values = metrics.get(name) or []
        if values:
            metric = values[0].get("cvssData", {})
            return {
                "score": metric.get("baseScore", 0.0),
                "severity": metric.get("baseSeverity") or values[0].get("baseSeverity") or "unknown",
            }
    return {"score": 0.0, "severity": "unknown"}


def _parse_cve(item):
    cve = item.get("cve", {})
    metric = _metric_from(
        cve.get("metrics", {}),
        ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"),
    )

    return {
        "cve_id": cve.get("id"),
        "cvss_score": metric["score"],
        "severity": str(metric["severity"]).lower(),
        "description": _english_description(cve),
    }


def _throttle(api_key):
    global _LAST_REQUEST_AT

    # NVD recommends sleeping between requests. Keep keyed scans responsive,
    # but slow anonymous use enough to respect the public rate limit.
    delay = 0.8 if api_key else 6.1
    elapsed = time.time() - _LAST_REQUEST_AT
    if elapsed < delay:
        time.sleep(delay - elapsed)
    _LAST_REQUEST_AT = time.time()


def search_cves(keyword, max_results=5, api_key=None):
    """
    Search NVD CVEs by keyword and return normalized vulnerability dicts.

    API key lookup:
        export NVD_API_KEY="your-key"
    """
    keyword = " ".join((keyword or "").split())
    if not keyword:
        return []

    cache_key = (keyword.lower(), max_results)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    api_key = api_key or os.getenv(NVD_API_KEY_ENV)
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max(1, min(max_results, 20)),
    }
    url = f"{NVD_CVE_URL}?{urlencode(params)}&noRejected"
    headers = {"User-Agent": "SentiNet/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    _throttle(api_key)

    try:
        request = Request(url, headers=headers)
        with urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        message = exc.headers.get("message") or exc.reason
        print(f"[!] NVD API error for '{keyword}': HTTP {exc.code} {message}")
        return []
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"[!] NVD lookup failed for '{keyword}': {exc}")
        return []

    vulnerabilities = [
        parsed for parsed in (_parse_cve(item) for item in payload.get("vulnerabilities", []))
        if parsed.get("cve_id")
    ]
    _CACHE[cache_key] = vulnerabilities
    return vulnerabilities


def build_device_queries(device):
    queries = []
    vendor = (device.get("vendor") or "").strip()
    model = (device.get("model") or "").strip()
    firmware = (device.get("firmware") or "").strip()
    device_type = (device.get("device_type") or "").strip()

    if model and firmware and firmware.lower() != "unknown":
        queries.append(f"{model} {firmware}")
    if vendor and model:
        queries.append(f"{vendor} {model}")

    for port in device.get("ports", []):
        product = (port.get("product") or "").strip()
        version = (port.get("version") or "").strip()
        service = (port.get("service") or "").strip()

        if product and version:
            queries.append(f"{product} {version}")
        elif vendor and product:
            queries.append(f"{vendor} {product}")
        elif product:
            queries.append(product)
        elif vendor and service and service not in {"unknown", "tcpwrapped"}:
            queries.append(f"{vendor} {service}")

    if not queries and vendor and device_type not in {"unknown", "computer"}:
        queries.append(f"{vendor} {device_type}")

    deduped = []
    seen = set()
    for query in queries:
        key = query.lower()
        if key not in seen:
            deduped.append(query)
            seen.add(key)
    return deduped[:3]


def find_device_vulnerabilities(device, max_results_per_query=5):
    results = []
    seen_cves = set()

    for query in build_device_queries(device):
        print(f"    NVD query: {query}")
        for vuln in search_cves(query, max_results=max_results_per_query):
            cve_id = vuln.get("cve_id")
            if cve_id and cve_id not in seen_cves:
                results.append(vuln)
                seen_cves.add(cve_id)

    return sorted(results, key=lambda v: float(v.get("cvss_score") or 0), reverse=True)
