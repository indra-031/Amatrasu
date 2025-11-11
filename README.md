## Thanks

> **Important for repository owners:** This README references Telegram integration (e.g. `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, and topic IDs). The sample values commonly seen in example scripts may belong to the author — **replace them with your own values** or remove the Telegram integration entirely before publishing. **Do not commit real tokens or sensitive data** to a public repository. In your final release you should remove any example tokens/IDs.

# Amatrasu 🔥

**HTTP Basic Auth Brute Forcer** — multi-domain, threaded, and built for fast, focused testing. Designed for security researchers and bug bounty hunters who test HTTP Basic authentication endpoints. Use responsibly and with permission. ⚖️

---

## 🚀 Features

- Multi-domain support (single `--domain` or `--domains` file)
- Threaded bruteforce per domain (high-concurrency with configurable `--threads`)
- Stop on first success by default, or `--continue` to keep running
- Auto-retry mode for failed attempts (reads from `ERRORS.txt`)
- WAF detection heuristics + optional `wafw00f` integration
- Telegram notifications for successes / errors (optional)
- Lightweight: single-file Python 3 script, minimal dependencies

---

## ⚙️ Requirements

- Python 3.8+
- `requests`
- Optionally: `wafw00f` in PATH (for more accurate WAF detection)

Install dependencies:

```bash
pip install -r requirements.txt
# or
pip install requests

🧭 Quick Start

Prepare your lists:

Username_List.txt — one username per line

Password_List.txt — one password per line

Optionally domains.txt — one domain per line (plain hostnames or full URLs)

Telegram integration (optional):

If you want Telegram notifications, set your own TELEGRAM_TOKEN, TELEGRAM_CHAT_ID and topic IDs.

Important: The example token/IDs in sample scripts are the author's — replace them or remove the integration before publishing.

Recommended: load these values from environment variables or a local config file (never hardcode secrets into committed files).

Example (export env vars):
export TELEGRAM_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-1001234567890"
export TELEGRAM_TOPIC_SUCCESS="1554"
export TELEGRAM_TOPIC_ERROR="1094"
```

Run a single target:
```python Amatrasu.py -d https://example.com --users Username_List.txt --passes Password_List.txt --threads 50```

Run multiple domains from a file:
```python Amatrasu.py --domains domains.txt --users Username_List.txt --passes Password_List.txt```

Retry failed attempts recorded in ERRORS.txt:
```python Amatrasu.py --domains domains.txt --retry```

Keep brute-forcing even after a success:
```
python Amatrasu.py -d https://example.com -c
# or
python Amatrasu.py -d https://example.com --continue
```

🔍 Command Line Options
```
-d, --domain         Single target domain (e.g. https://example.com)
--domains            File containing list of domains (one per line)
--users              User list file (default: Username_List.txt)
--passes             Password list file (default: Password_List.txt)
--threads            Threads per domain (default: 50)
--timeout            Request timeout (default: 5.0)
--insecure           Disable SSL verification
--use-wafw00f        Use wafw00f for WAF detection
--silent             Minimal output (only progress/results)
--retry              Retry only failed credentials from ERRORS.txt
-c, --continue       Continue brute-forcing even after success
```
🔐 Output files

SUCCESS.txt — appended entries for discovered valid credentials

ERRORS.txt — logged errors (used by --retry)

Do not commit SUCCESS.txt or ERRORS.txt to any public repo — they may contain sensitive data.

💡 Implementation Notes (for developers)

Uses requests.Session() with a realistic User-Agent and concurrent threads via concurrent.futures.ThreadPoolExecutor.

Basic auth headers are created using Base64; responses with non-401 status codes are treated as a success.

A tiny sleep (time.sleep(0.001)) is used between generator yields to avoid tight-loop starvation.

The script accesses args.continue with getattr(args, "continue", False) to avoid continue being interpreted as a Python keyword.

🧾 Legal & Ethical Notice

Only use Amatrasu against systems you own or have explicit written permission to test. Unauthorized scanning, credential stuffing, or brute-force attacks are illegal and unethical. The author is not responsible for misuse. By using this tool you accept full responsibility for your actions. ❗️

🛠️ Hardening / Safety Tips

Never commit real credential lists or notification tokens to version control.

Use environment variables or a local, gitignored config file for secrets.

Consider running against a controlled test environment or containerized lab.

Use --insecure only for testing self-signed certs — otherwise keep TLS verification.

Rate-limit threads and add delays when testing fragile targets.

🤝 Contributing

PRs and issues are welcome. If you open a PR:

Keep changes minimal and well-documented

Don’t include secrets

Add tests for new behaviours where practical

🧾 Example (safe testing)

Create a tiny local test server that requires basic auth (e.g., using http.server + simple auth middleware) and try the script against http://127.0.0.1:8000 with a very small user/pass list. This keeps testing legal and repeatable.

📜 License

Choose a license you prefer (MIT / Apache-2.0 recommended). Add LICENSE to the repo.

❤️ Thanks

Built with :keyboard: and a dash of chaos. If you like the project, ⭐ the repo and share responsibly. Stay curious — stay ethical. 🕶️

Amatrasu — blunt, fast, and for authorized research only.


