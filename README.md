# 🔥 Amatrasu

**HTTP Basic Auth Brute Forcer**

Amatrasu is a fast and lightweight HTTP Basic Authentication testing tool built for **security researchers, penetration testers, and bug bounty hunters**.

It supports multi-threaded credential testing, multiple domains, WAF detection, automatic retries, live progress tracking, and Telegram notifications.

> ⚠️ Use this tool only against systems you own or have explicit permission to test.

---

## ✨ Features

- 🔐 HTTP Basic Authentication testing
- 🌐 Single & multi-domain support
- 🧵 Multi-threaded requests
- 🛑 Stop on first successful credential
- 🔄 Continue mode
- 🔁 Automatic retry for failed requests
- 🛡️ WAF detection
- ⚡ WAF-aware thread control
- 📊 Live progress & HTTP status statistics
- 📡 Telegram success notifications
- 💾 Success & error logging
- 🔒 HTTP / HTTPS support

---

## 📦 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/Amatrasu.git
cd Amatrasu
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Or install `requests` manually:

```bash
pip install requests
```

Optional:

```bash
pip install wafw00f
```

---

## 🚀 Quick Start

Prepare your username list:

```text
Username_List.txt
```

Example:

```text
admin
administrator
user
test
```

Prepare your password list:

```text
Password_List.txt
```

Example:

```text
admin
password
admin123
123456
```

Run against a single authorized target:

```bash
python amatrasu.py \
    -d https://example.com \
    -u Username_List.txt \
    -p Password_List.txt
```

---

## 🌐 Multiple Domains

Create:

```text
domains.txt
```

Example:

```text
https://example.com
https://admin.example.com
https://test.example.com
```

Run:

```bash
python amatrasu.py \
    -l domains.txt \
    -u Username_List.txt \
    -p Password_List.txt
```

---

## ⚙️ Options

Show help:

```bash
python amatrasu.py -h
```

### `-d, --domain`

Test a single domain.

```bash
-d https://example.com
```

### `-l, --domains`

Load multiple domains from a file.

```bash
-l domains.txt
```

### `-u, --users`

Specify the username list.

Default:

```text
Username_List.txt
```

Example:

```bash
-u users.txt
```

### `-p, --passes`

Specify the password list.

Default:

```text
Password_List.txt
```

Example:

```bash
-p passwords.txt
```

### `-t, --threads`

Set the number of concurrent threads.

Default:

```text
50
```

Example:

```bash
-t 100
```

### `--timeout`

Set HTTP request timeout.

Default:

```text
5 seconds
```

Example:

```bash
--timeout 10
```

### `--no-insecure`

Enable SSL certificate verification.

By default, SSL verification is disabled.

```bash
--no-insecure
```

### `--use-wafw00f`

Enable the wafw00f option.

```bash
--use-wafw00f
```

> Note: WAF detection is currently part of the normal detection flow.

### `--silent`

Reduce console output and show only progress/results.

```bash
--silent
```

### `--no-retry`

Disable automatic retry of failed requests.

Amatrasu normally retries:

```text
403
429
503
Request Errors
```

Disable it with:

```bash
--no-retry
```

### `-c, --continue`

Continue testing credentials after finding a successful authentication.

```bash
-c
```

or:

```bash
--continue
```

Without this option, Amatrasu stops after the first success.

### `--skip-waf`

Skip targets where a WAF is detected.

```bash
--skip-waf
```

### `--waf [WAF]`

Reduce thread count when a WAF is detected.

Default WAF thread count:

```text
10
```

Example:

```bash
--waf
```

Custom value:

```bash
--waf 5
```

---

## 🔥 Example

A more controlled scan:

```bash
python amatrasu.py \
    -d https://example.com \
    -u Username_List.txt \
    -p Password_List.txt \
    -t 20 \
    --timeout 10 \
    --waf 5
```

Continue after success:

```bash
python amatrasu.py \
    -d https://example.com \
    -c
```

Skip WAF-protected targets:

```bash
python amatrasu.py \
    -l domains.txt \
    --skip-waf
```

---

## 📊 Output

### Successful Credentials

Successful results are stored in:

```text
SUCCESS.txt
```

Example:

```text
example.com | admin:admin123 | Status: 200
```

### Failed / Retryable Attempts

Retryable errors are stored in:

```text
ERRORS.txt
```

These include:

```text
403
429
503
Request Errors
```

Amatrasu automatically retries these credentials unless:

```text
--no-retry
```

is used.

---

## 🛡️ WAF Detection

Amatrasu uses heuristic detection based on HTTP response headers and can also use `wafw00f`.

Common WAF indicators include:

```text
Cloudflare
Akamai
Fastly
Sucuri
```

When a WAF is detected, you can either:

```bash
--skip-waf
```

or reduce concurrency:

```bash
--waf 10
```

---

## 📡 Telegram

Amatrasu can send successful authentication results to Telegram.

Configure your own:

```text
TELEGRAM_TOKEN
TELEGRAM_CHAT_ID
TELEGRAM_TOPIC_SUCCESS
TELEGRAM_TOPIC_ERROR
```

⚠️ Never commit real Telegram tokens or credentials to a public repository.

Use environment variables or a local configuration file instead.

---

## 🧠 How It Works

```text
Target
   │
   ▼
Basic Auth Detection
   │
   ▼
WAF Detection
   │
   ▼
Username × Password
   │
   ▼
Multi-Threaded Requests
   │
   ├── 401 → Failed
   ├── 403 → Retry
   ├── 429 → Retry
   ├── 503 → Retry
   └── Other → Potential Success
                    │
                    ▼
              SUCCESS.txt
                    │
                    ▼
                 Telegram
```

---

## ⚠️ Legal Notice

Amatrasu is intended for **authorized security testing only**.

Do not use it against systems without explicit permission.

Unauthorized brute-force attacks, credential stuffing, or authentication testing may be illegal.

The author is not responsible for misuse of this tool.

---

## 🔥 Amatrasu

**Fast. Focused. Relentless.**

Built for authorized security research.

Stay curious.  
Stay ethical.
