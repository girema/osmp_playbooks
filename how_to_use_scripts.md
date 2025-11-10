# Unix Response Script — Dependencies and Requirements

## 🖥️ Controller (Local Machine)

### Required Packages
| Type | Packages / Tools |
|------|------------------|
| Shell & Core | `bash`, `awk`, `sed`, `grep`, `tr`, `xargs`, `locale`, `head`, `find`, `tar`, `cp`, `mv`, `echo`, `printf` |
| SSH Client | `openssh-client` (supports `StrictHostKeyChecking=accept-new`) |
| JSON Processor | `jq` |
| OS Compatibility | Works on all modern Linux distributions and macOS with Bash |

### Installation Examples
**Ubuntu / Debian:**
```bash```
sudo apt-get update && sudo apt-get install -y jq openssh-client

# Windows Response Script — Dependencies and Requirements

## 🖥️ Controller (Local Machine)

### Required Python Packages
| Package | Purpose |
|----------|----------|
| `python-ldap` | Provides LDAP protocol support for Python |
| `gssapi` | Kerberos authentication library (sometimes bundled with `python-ldap`) |
| `argparse` | Command-line argument parsing (included in Python standard library) |

### Installation (Debian/Ubuntu)
```bash```
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev libsasl2-dev libldap2-dev libssl-dev
pip3 install python-ldap

# Hybrid Analysis Response Script — Dependencies and Requirements

## 🖥️ Controller (Local Machine)

### Required Python Packages

| Package | Purpose |
|----------|----------|
| `requests` | Interact with the Hybrid Analysis API |
| `ipwhois` | Perform WHOIS lookups for IP addresses |
| `python-whois` | Retrieve WHOIS info for domains |
| `socket` (built-in) | DNS resolution |
| `urllib.parse` (built-in) | URL parsing |
| `re`, `json`, `sys`, `time` (built-in) | Input parsing, JSON handling, delays |

### Installation on Ubuntu/Debian
```bash```
sudo apt-get update
sudo apt-get install -y python3 python3-pip
pip3 install requests ipwhois python-whois

# VirusTotal Response Script — Dependencies and Requirements

## 🖥️ Controller (Local Machine)

### Required Python Packages

| Package | Purpose |
|----------|----------|
| `requests` | HTTP client for VirusTotal API calls |
| `flask` | Provides REST API endpoint `/enrich` |
| `base64` | URL-safe encoding for URL lookups |
| `time`, `re`, `json`, `sys` | Core Python modules (standard library) |

### Installation (Ubuntu/Debian)
```bash```
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests flask
