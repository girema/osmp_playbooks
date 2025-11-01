# -*- coding: utf-8 -*-
import requests
import time
from flask import Flask, request, jsonify
import base64

API_KEY = 'ad0f386a9df8032e4a188ca378135e259cde81939ade109ed523c0d2ec3debec'  # ? insert your VirusTotal API key here
VT_URL = 'https://www.virustotal.com/api/v3/'

HEADERS = {
    'x-apikey': API_KEY
}

def check_ip(ip):
    if not ip:
        return {"type": "ip", "value": ip, "error": "Empty IP provided"}

    url = VT_URL + f'ip_addresses/{ip}'
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        undetected = stats.get("undetected", 0)
        malicious_engines = [
            engine for engine, result in data['data']['attributes']['last_analysis_results'].items()
            if result['category'] == 'malicious'
        ]
        harmless = stats.get("harmless", 0)
        reputation = data['data']['attributes'].get("reputation", 0)
        first_seen = data['data']['attributes'].get("first_seen", "")
        permalink = data['data']['links'].get("self", "")
        return {
            "type": "ip",
            "value": ip,
            "malicious": stats['malicious'],
            "suspicious": stats['suspicious'],
            "undetected": undetected,
            "malicious_engines": malicious_engines,
            "harmless": harmless,
            "reputation": reputation,
            "first_seen": first_seen,
            "permalink": permalink
        }
    else:
        return {"type": "ip", "value": ip, "error": r.text}


def check_domain(domain):
    if not domain:
        return {"type": "domain", "value": domain, "error": "Empty domain provided"}

    url = VT_URL + f'domains/{domain}'
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        undetected = stats.get("undetected", 0)
        malicious_engines = [
            engine for engine, result in data['data']['attributes']['last_analysis_results'].items()
            if result['category'] == 'malicious'
        ]
        harmless = stats.get("harmless", 0)
        reputation = data['data']['attributes'].get("reputation", 0)
        first_seen = data['data']['attributes'].get("first_seen", "")
        permalink = data['data']['links'].get("self", "")
        return {
            "type": "domain",
            "value": domain,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": undetected,
            "malicious_engines": malicious_engines,
            "harmless": harmless,
            "reputation": reputation,
            "first_seen": first_seen,
            "permalink": permalink
        }
    else:
        return {"type": "domain", "value": domain, "error": r.text}


def check_url(url):
    if not url:
        return {"type": "url", "value": url, "error": "Empty URL provided"}

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = VT_URL + f'urls/{url_id}'
    r = requests.get(vt_url, headers=HEADERS)

    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        undetected = stats.get("undetected", 0)
        malicious_engines = [
            engine for engine, result in data['data']['attributes']['last_analysis_results'].items()
            if result['category'] == 'malicious'
        ]
        harmless = stats.get("harmless", 0)
        reputation = data['data']['attributes'].get("reputation", 0)
        first_seen = data['data']['attributes'].get("first_submission_date", "")
        if first_seen:
            from datetime import datetime
            first_seen = datetime.utcfromtimestamp(first_seen).isoformat()
        permalink = f"https://www.virustotal.com/gui/url/{data['data']['id']}"
        return {
            "type": "url",
            "value": url,
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "undetected": undetected,
            "malicious_engines": malicious_engines,
            "harmless": harmless,
            "reputation": reputation,
            "first_seen": first_seen,
            "permalink": permalink
        }
    else:
        return {"type": "url", "value": url, "error": r.text}


def check_hash(hash_str, hash_type):
    if not hash_str:
        return {"type": hash_type, "value": hash_str, "error": "Empty hash provided"}

    url = VT_URL + f'files/{hash_str}'
    r = requests.get(url, headers=HEADERS)
    if r.status_code == 404:
        return {"type": hash_type, "value": hash_str, "error": "File not found in VirusTotal database"}
    if r.status_code == 200:
        data = r.json()
        stats = data['data']['attributes']['last_analysis_stats']
        undetected = stats.get("undetected", 0)
        malicious_engines = [
            engine for engine, result in data['data']['attributes']['last_analysis_results'].items()
            if result['category'] == 'malicious'
        ]
        harmless = stats.get("harmless", 0)
        reputation = data['data']['attributes'].get("reputation", 0)
        first_seen = data['data']['attributes'].get("first_submission_date", "")
        if first_seen:
            from datetime import datetime
            first_seen = datetime.utcfromtimestamp(first_seen).isoformat()
        permalink = data['data']['links'].get("self", "")
        return {
            "type": hash_type,
            "value": hash_str,
            "malicious": stats['malicious'],
            "suspicious": stats['suspicious'],
            "undetected": undetected,
            "malicious_engines": malicious_engines,
            "harmless": harmless,
            "reputation": reputation,
            "first_seen": first_seen,
            "permalink": permalink
        }
    else:
        return {"type": hash_type, "value": hash_str, "error": r.text}


app = Flask(__name__)

@app.route('/enrich', methods=['POST'])
def enrich():
    try:
        input_data = request.get_json()
        observables = input_data.get("observables", [])
        observables = [dict(t) for t in {tuple(o.items()) for o in observables}]
        results = []

        for obs in observables:
            obs_type = obs.get("type")
            value = obs.get("value")

            if obs_type == "ip":
                results.append(check_ip(value))
            elif obs_type in ["md5", "sha256"]:
                results.append(check_hash(value, obs_type))
            elif obs_type == "domain":
                results.append(check_domain(value))
            elif obs_type == "url":
                results.append(check_url(value))
            else:
                results.append({"type": obs_type, "value": value, "error": "Unsupported observable type"})

            time.sleep(15)

        return jsonify({"results": results})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    import json
    import sys
    import re

    if len(sys.argv) > 1:
        try:
            raw_input = " ".join(sys.argv[1:])

            try:
                observables = json.loads(raw_input)
            except json.JSONDecodeError:
                raw_values = re.findall(r'value:([^,\]\s]+)', raw_input)
                raw_types = re.findall(r'type:([^,\]\s]+)', raw_input)
                observables = []

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
                        observables.append({"type": t, "value": v})

                if len(observables) < len(raw_types):
                    for t in raw_types:
                        if not any(o["type"] == t for o in observables):
                            observables.append({"type": t, "value": None})

                observables = [o for o in observables if o.get("value")]
                seen = set()
                unique = []
                for o in observables:
                    key = (o["type"], o["value"])
                    if key not in seen:
                        seen.add(key)
                        unique.append(o)
                observables = unique

            if not observables or not isinstance(observables, list):
                raise ValueError("No valid observables found")

            results = []
            seen = set()
            for obs in observables:
                key = (obs.get('type'), obs.get('value'))
                if key in seen:
                    continue
                seen.add(key)

                obs_type = obs.get("type")
                value = obs.get("value")

                if obs_type == "ip":
                    results.append(check_ip(value))
                elif obs_type in ["md5", "sha256"]:
                    results.append(check_hash(value, obs_type))
                elif obs_type == "domain":
                    results.append(check_domain(value))
                elif obs_type == "url":
                    results.append(check_url(value))
                else:
                    results.append({
                        "type": obs_type,
                        "value": value,
                        "error": "Unsupported observable type"
                    })

                time.sleep(15)

            print(json.dumps({"results": results}, indent=2))

        except Exception as e:
            print(json.dumps({
                "error": f"Failed to parse observables input: {str(e)}",
                "raw_input": raw_input
            }))
            sys.exit(1)
    else:
        app.run(host="0.0.0.0", port=8010)