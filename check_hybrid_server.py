# -*- coding: utf-8 -*-
import re
import requests
import time
from ipwhois import IPWhois
import socket
import whois
from urllib.parse import urlparse
def query_ip_whois(ip):
    debug_log(f"Performing WHOIS lookup for IP: {ip}")
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        return {
            "type": "ip",
            "value": ip,
            "asn": res.get("asn"),
            "asn_description": res.get("asn_description"),
            "network_name": res.get("network", {}).get("name"),
            "country": res.get("network", {}).get("country") or "N/A",
            "ip_range": res.get("network", {}).get("cidr", "N/A"),
            "source": "RDAP WHOIS"
        }
    except Exception as e:
        return {
            "type": "ip",
            "value": ip,
            "error": f"WHOIS lookup failed: {str(e)}"
        }

def resolve_domain(domain):
    debug_log(f"Resolving domain: {domain}")
    try:
        ip = socket.gethostbyname(domain)
        return {
            "type": "domain",
            "value": domain,
            "resolved_ip": ip,
            "source": "DNS resolve"
        }
    except Exception as e:
        return {
            "type": "domain",
            "value": domain,
            "error": f"DNS resolve failed: {str(e)}"
        }

def whois_domain(domain):
    debug_log(f"Performing WHOIS for domain: {domain}")
    try:
        w = whois.whois(domain)
        return {
            "type": "domain",
            "value": domain,
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "name_servers": w.name_servers,
            "emails": w.emails,
            "source": "Domain WHOIS"
        }
    except Exception as e:
        err = str(e)
        if "No match for" in err:
            err = err.split("\r")[0]  # ???????? ??? ????? "No match..."
        return {
            "type": "domain",
            "value": domain,
            "error": f"Domain WHOIS failed: {err.strip()}"
        }

def process_url(url):
    debug_log(f"Processing URL: {url}")
    try:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.hostname
        if not domain:
            return {
                "type": "url",
                "value": url,
                "error": "Unable to extract domain from URL"
            }
        return {
            "type": "url",
            "value": url,
            "extracted_domain": domain,
            "source": "URL parsing"
        }
    except Exception as e:
        return {
            "type": "url",
            "value": url,
            "error": f"URL parse failed: {str(e)}"
        }

DEBUG = False

API_KEY = ""
HEADERS = {
    "api-key": API_KEY,
    "User-Agent": "Falcon Sandbox",
    "accept": "application/json"
}

def debug_log(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

BASE_URL = "https://www.hybrid-analysis.com/api/v2"

def query_hash(file_hash):
    debug_log(f"Querying hash: {file_hash}")
    if len(file_hash) != 64:
        return {
            "type": "hash",
            "value": file_hash,
            "error": "Only SHA256 hashes are supported by the Hybrid Analysis API"
        }

    url = f"{BASE_URL}/overview/{file_hash}"
    r = requests.get(url, headers=HEADERS)
    debug_log(f"Response: {r.status_code} {r.text}")

    try:
        data = r.json()
    except Exception:
        return {"type": "hash", "value": file_hash, "error": f"Invalid JSON: {r.text}"}

    # ???????? ??????? ??????
    if isinstance(data, dict):
        return {
            "type": "hash",
            "value": file_hash,
            "threat_score": data.get("threat_score"),
            "vx_family": data.get("vx_family"),
            "av_detect": data.get("av_detect"),
            "verdict": data.get("verdict"),
            "source": "Hybrid Analysis"
        }
    elif isinstance(data, dict) and "message" in data:
        return {"type": "hash", "value": file_hash, "error": data["message"]}
    else:
        return {"type": "hash", "value": file_hash, "error": "No results or unknown response"}



import sys
import json

if __name__ == "__main__":
    if len(sys.argv) < 2:
        debug_log(f"sys.argv: {sys.argv}")
        print("Usage: python hybrid_analysis.py '<json_input>'")
        sys.exit(1)

    try:
        raw_input = " ".join(sys.argv[1:])
        debug_log(f"Combined argv: {raw_input}")
        try:
            data = json.loads(raw_input)
        except json.JSONDecodeError:
            raw_values = re.findall(r'value:([^,\]\s]+)', raw_input)
            raw_types = re.findall(r'type:([^,\]\s]+)', raw_input)
            data = []

            def guess_type(value):
                if re.match(r'^(https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', value):
                    return 'url'
                elif re.fullmatch(r'[a-fA-F\d]{32}', value):
                    return 'md5'
                elif re.fullmatch(r'[a-fA-F\d]{64}', value):
                    return 'sha256'
                elif re.fullmatch(r'\d{1,3}(\.\d{1,3}){3}', value):
                    return 'ip'
                elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
                    return 'domain'
                else:
                    return None

            for v in raw_values:
                t = guess_type(v)
                if t:
                    data.append({"type": t, "value": v})

            if len(data) < len(raw_types):
                for t in raw_types:
                    if not any(o["type"] == t for o in data):
                        data.append({"type": t, "value": None})

            data = [o for o in data if o.get("value")]
            seen = set()
            unique = []
            for o in data:
                key = (o["type"], o["value"])
                if key not in seen:
                    seen.add(key)
                    unique.append(o)
            data = unique
        debug_log(f"Loaded JSON input: {json.dumps(data, indent=2)}")
        results = []
        if isinstance(data, list):
            observables = data
        elif isinstance(data, dict):
            observables = data.get("observables", [])
        else:
            observables = []

        for obs in observables:
            obs_type = obs.get("type", "").lower()
            value = obs.get("value")

            if obs_type in ["md5", "sha1", "sha256"]:
                result = query_hash(value)
                results.append(result)
                time.sleep(1.5)
            elif obs_type == "ip":
                result = query_ip_whois(value)
                results.append(result)
                time.sleep(1.5)
            elif obs_type == "domain":
                result = resolve_domain(value)
                results.append(result)
                results.append(whois_domain(value))
                time.sleep(1.5)
                continue
            elif obs_type == "url":
                result = process_url(value)
                results.append(result)
                domain = result.get("extracted_domain")
                if domain:
                    results.append(resolve_domain(domain))
                    results.append(whois_domain(domain))
                time.sleep(1.5)
                continue
            else:
                result = {"type": obs_type, "value": value, "error": "Unsupported type"}
                results.append(result)
                time.sleep(1.5)

        print(json.dumps({"results": results}, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(1)
