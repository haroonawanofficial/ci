# CMD‑Injection AI Powered Fuzzer  (v5.0)

A modern, AI‑enhanced **Command Injection vulnerability fuzzer**. Designed for deep recon in red‑team environments, targeting web parameters vulnerable to shell command execution.

---

## Summary

- **Name**: `CMD‑Injection AI Fuzzer`
- **Version**: 5.0 (April 2025)
- **Author**: Haroon Ahmad Awan · CyberZeus  
- **Email**: haroon@cyberzeus.pk
- **License**: MIT  
- **File**: `ci.py`

---

##  Key Features

- **Command Injection discovery via:**
  - In-band output detection (e.g., `uid=`, `root:x`)
  - Time-delay analysis (e.g., `sleep 5`)
  - Blind DNS beaconing to `dnslog.cn`

- **AI-Powered Mutation** (optional):
  - Integrates with **Microsoft CodeBERT** to mutate base payloads
  - Extends static payloads with predicted shell logic

- **Payload Obfuscation & Wrappers**:
  - Wrapping via `|`, `&&`, `||`, `;`, `$(...)`, backticks, `base64`, etc.
  - Encoded: hex, URL‑encoded, double‑URL, null‑byte, base64

- **Smart Crawler**:
  - Finds `<a href=…>` URLs with query parameters
  - Detects forms and extracts parameter names
  - Same-domain recursive crawling

- **Headers & Fuzzing Techniques**:
  - Random `User-Agent`, spoofed `X-Forwarded-For`, rotating `Referer`
  - Time-based jitter between requests to evade WAF detection

- **Logging**:
  - Markdown output (`cmdi_results.md`)
  - Tagged entries: `IN‑BAND`, `TIME`, or `DNSLOG`

---

## Usage

### Installation

```bash
git clone https://github.com/haroonawanofficial/ci.git
cd ci
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt  # requests, bs4, fake-useragent, transformers (optional)
