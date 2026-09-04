# 🔥 Amatrasu

**HTTP Basic Auth Brute Forcer**

Amatrasu is a fast, multi-threaded HTTP Basic Authentication testing tool designed for security researchers and bug bounty hunters.

### ✨ Features

- 🌐 Single & Multi-Domain support
- 🧵 Multi-threaded brute forcing
- 🛑 Stop on success / Continue mode
- 🛡️ WAF detection
- 🔁 Automatic retry for failed requests
- 📊 Live progress & status tracking
- 📡 Telegram notifications
- 💾 Success & error logging

---

## 📦 Installation

```bash
git clone https://github.com/indra-031/Amatrasu.git
cd Amatrasu
pip install -r requirements.txt
```

Optional WAF detection:

```bash
pip install wafw00f
```

---

## 🚀 Usage

### Single Domain

```bash
python amatrasu.py -d https://example.com
```

### Multiple Domains

Put your targets in a file and run:

```bash
python amatrasu.py -l domains.txt
```

### Custom Threads

```bash
python amatrasu.py -d https://example.com -t 100
```

### Continue After Success

```bash
python amatrasu.py -d https://example.com -c
```

### Skip WAF Targets

```bash
python amatrasu.py -d https://example.com --skip-waf
```

### WAF Thread Control

```bash
python amatrasu.py -d https://example.com --waf
```

Or specify the thread count:

```bash
python amatrasu.py -d https://example.com --waf 5
```

### Disable Retry

```bash
python amatrasu.py -d https://example.com --no-retry
```

---

## 📡 Telegram Notifications

Amatrasu supports optional Telegram notifications for successful authentication attempts and errors.

Telegram settings are configured **directly inside `amatrasu.py`**.

Open the file and edit:

```python
TELEGRAM_SEND = True

TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"

TELEGRAM_TOPIC_SUCCESS = None
TELEGRAM_TOPIC_ERROR = None
TELEGRAM_SEND
```
Controls whether Telegram notifications are enabled.

True  → Enable Telegram notifications
False → Disable Telegram notifications

TELEGRAM_TOKEN

Your Telegram Bot API token.

TELEGRAM_CHAT_ID

The target Telegram chat/group/channel ID.

TELEGRAM_TOPIC_SUCCESS

Optional topic ID for successful authentication notifications.

Set to None if you don't use topics.

TELEGRAM_TOPIC_ERROR

Optional topic ID for error notifications.

Set to None if you don't use topics.

---

## ⚙️ Options

```text
-d, --domain          Single target domain
-l, --domains         File containing multiple domains
-u, --users           User list file
-p, --passes          Password list file
-t, --threads         Threads per domain
--timeout             Request timeout
--no-insecure         Enable SSL verification
--use-wafw00f         Use wafw00f for WAF detection
--silent              Show only progress and results
--no-retry            Disable automatic retry
-c, --continue        Continue after successful authentication
--skip-waf            Skip WAF-protected domains
--waf [WAF]           Lower thread count for WAF targets
```

---

## 📁 Output

Successful credentials:

```text
SUCCESS.txt
```

Retryable errors:

```text
ERRORS.txt
```

Do not commit these files to a public repository.

---

## ⚠️ Disclaimer

Amatrasu is intended for **authorized security testing only**.

Only use it against systems you own or have explicit permission to test.

The author is not responsible for misuse.

---

🔥 **Amatrasu — Fast. Focused. Relentless.**
