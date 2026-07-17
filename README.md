<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-success?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-orange?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Status-Active%20Development-brightgreen?style=for-the-badge" alt="Status">
</p>

<h1 align="center">Index Hunter</h1>

<p align="center">
  <b>Advanced "Index of" sensitive-file scanner with a modern web UI</b><br>
  <sub>Discover exposed files, credentials, configs, and secrets on web servers</sub>
</p>

<p align="center">
  <a href="#-features">Features</a> &bull;
  <a href="#-quick-start">Quick Start</a> &bull;
  <a href="#-usage">Usage</a> &bull;
  <a href="#-detection">Detection</a> &bull;
  <a href="#-architecture">Architecture</a> &bull;
  <a href="#-api">API</a> &bull;
  <a href="#-plugins">Plugins</a> &bull;
  <a href="#-contributing">Contributing</a>
</p>

---

## Overview

**Index Hunter** is a security auditing tool that crawls web servers looking for exposed sensitive files through directory listing ("Index of" pages). It identifies misconfigured servers that expose backup files, configuration files, database dumps, private keys, credentials, and other sensitive data.

The scanner features:
- **Async multi-worker crawling** for fast, deep scans
- **Smart file classification** across 200+ extensions and patterns
- **Content-based secret detection** using regex, entropy analysis, and YARA rules
- **Modern dark-theme web UI** with live progress, filtering, and export
- **Token-based authentication** with password-protected login
- **Scan history** persisted to JSON on disk
- **Framework & cloud provider detection** (30+ frameworks, 20+ cloud providers)

---

## Quick Start

### Prerequisites

- **Python 3.8+**
- **pip**

### Installation

```bash
git clone https://github.com/CodeZANKO/Index-Hunter.git
cd Index-Hunter
pip install -r requirements.txt
```

### Run Web UI (default)

```bash
python indexhunter.py
```

Opens at **http://127.0.0.1:8000** with default credentials: `admin` / `admin`.

### Run Headless (CLI)

```bash
python indexhunter.py --url https://example.com/index/
```

---

## Usage

### Web UI

| Action | Description |
|--------|-------------|
| **Start Scan** | Enter a URL (must end with `/index/` or similar), click Start |
| **Live Progress** | Watch real-time dashboard: Speed, Queue, Scanned, Requests, Findings |
| **Results Tab** | Sortable/filterable table with severity badges, scores, previews |
| **Tree Tab** | Directory tree with severity icons per folder |
| **Summary Tab** | Final scan summary with donut chart |
| **Log Tab** | Full scan log with auto-scroll |
| **Export** | Download findings as JSON, CSV, SARIF, or HTML report |
| **Saved Scans** | Scan history saved to `indexhunter_scans.json` on the server |

### CLI Options

```
python indexhunter.py --url <URL> [--depth N] [--workers N] [--full] [--no-robots]
```

| Flag | Description |
|------|-------------|
| `--url` | Target URL (headless mode) |
| `--depth N` | Max crawl depth (0 = unlimited) |
| `--workers N` | Concurrent workers (default: 10) |
| `--full` | Download full file content (default: 64KB preview) |
| `--no-robots` | Ignore robots.txt |

### Authentication

- Login at `/login` with credentials
- Token stored in `localStorage` and sent via `Authorization: Bearer` header
- Change password via the Settings panel or API endpoint
- Credentials stored in `indexhunter_auth.json` (auto-created on first run)

---

## Detection

### File Extensions (200+ patterns)

Index Hunter classifies files into severity-based categories:

| Category | Severity | Examples |
|----------|----------|----------|
| **PASSWORD** | Critical/High | `.pem`, `.key`, `.p12`, `.pfx`, `.kdbx`, `.htpasswd` |
| **CERT** | High | `.crt`, `.cer`, `.der`, `.csr`, `.p7b` |
| **DATABASE** | High | `.sql`, `.sqlite`, `.db`, `.csv`, `.dbf`, `.mdf` |
| **CONFIG** | Medium | `.env`, `.yml`, `.toml`, `.xml`, `.json`, `.properties` |
| **BACKUP** | Medium | `.bak`, `.old`, `.swp`, `.save`, `~` |
| **ARCHIVES** | Medium | `.zip`, `.tar`, `.gz`, `.7z`, `.rar`, `.jar`, `.war` |
| **SCRIPT** | Medium | `.php`, `.py`, `.rb`, `.sh`, `.cgi`, `.jsp` |
| **SOURCE** | Low | `.js`, `.ts`, `.jsx`, `.tsx`, `.vue`, `.svelte` |
| **LOG** | Low | `.log`, `.log.1`, `.log.2` |

### Secret Signatures (30+ patterns)

| Provider | Severity | Pattern |
|----------|----------|---------|
| AWS | Critical | `AKIA*`, `aws_secret_access_key` |
| GitHub | Critical | `ghp_*`, `github_pat_*` |
| GitLab | Critical | `glpat-*` |
| Stripe | Critical | `sk_live_*`, `sk_test_*` |
| OpenAI | Critical | `sk-*` |
| Anthropic | Critical | `sk-ant-*` |
| Google | High | `AIza*`, OAuth tokens |
| Slack | High | `xoxb-*`, `xoxp-*` |
| Discord | High | Bot tokens |
| Firebase | High | API keys |
| MongoDB | Critical | Connection URIs |
| PostgreSQL | Critical | Connection URIs |
| MySQL | High | Config passwords |
| Redis | High | Connection URIs |
| JWT | High | `eyJ*` tokens |
| Private Keys | Critical | RSA, EC, OpenSSH, PGP |
| Generic API Keys | Medium | `api_key=*`, `secret=*`, `token=*` |

### Entropy Analysis

Detects high-entropy strings (>4.0 Shannon entropy, 20+ chars) that may indicate:
- API tokens
- Session identifiers
- Random passwords
- Encryption keys

### Framework Detection (40+ frameworks)

WordPress, Laravel, Django, Flask, Express, Next.js, React, Angular, Vue, Svelte, Nuxt, Astro, Remix, Gatsby, FastAPI, NestJS, Rails, Phoenix, ASP.NET, Spring Boot, Symfony, Magento, Shopify, Strapi, Ghost, Flutter, React Native, Tauri, Electron, and more.

### Cloud Provider Detection (30+ providers)

AWS, Azure, Google Cloud, Cloudflare, Firebase, Supabase, Vercel, Netlify, DigitalOcean, Railway, Render, Heroku, Fly.io, Backblaze B2, Wasabi, MinIO, Cloudinary, Fastly, Akamai, Alibaba Cloud, Tencent Cloud, Huawei Cloud, Oracle Cloud, IBM Cloud.

---

## Architecture

```
Index Hunter
├── indexhunter.py          # Entry point (web UI / headless)
├── server.py               # FastAPI backend + auth middleware
├── scanner.py              # Async crawl engine (asyncio + aiohttp)
├── content.py              # Content fetch + analysis
├── signatures.py           # Secret/entropy/framework/cloud detection
├── patterns.py             # File extension classification
├── filters.py              # Result filtering (severity, category, etc.)
├── exporter.py             # JSON/CSV/SARIF/HTML export
├── tree.py                 # Directory tree statistics
├── plugins/                # Framework-specific detection plugins
│   ├── docker.py
│   ├── firebase.py
│   ├── git.py
│   ├── laravel.py
│   └── wordpress.py
├── yara_rules/             # YARA scanning rules
│   ├── api_keys.yar
│   ├── aws.yar
│   ├── malware.yar
│   └── wordpress.yar
├── templates/
│   ├── index.html          # SPA frontend (Tailwind + vanilla JS)
│   └── login.html          # Login page
└── requirements.txt
```

### Key Design Decisions

- **Raw ASGI middleware** (`AuthMiddleware`) for token auth — never buffers SSE streams
- **Event bus** for decoupled SSE streaming — scanner callbacks publish, SSE clients subscribe
- **In-process state** — single-server design, no external database needed
- **Resume support** — scan state saved to `indexhunter_resume.json` for interrupted scans
- **Plugin architecture** — framework-specific detectors loaded dynamically from `plugins/`

---

## API

All `/api/*` endpoints require a valid bearer token (except `/api/login`).

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/login` | Authenticate, returns `{token}` |
| `POST` | `/api/logout` | Invalidate session |
| `POST` | `/api/change_password` | Change password (requires current) |
| `GET` | `/api/status` | Current scan stats |
| `POST` | `/api/scan` | Start a new scan |
| `POST` | `/api/stop` | Stop running scan |
| `GET` | `/api/stream` | SSE event stream (`?token=`) |
| `GET` | `/api/findings` | Filtered findings list |
| `GET` | `/api/export` | Export findings (json/csv/sarif/html) |
| `GET` | `/api/tree` | Directory tree data |
| `GET` | `/api/scans` | List saved scans |
| `POST` | `/api/scans` | Save a scan |
| `GET` | `/api/scans/:id` | Get saved scan |
| `DELETE` | `/api/scans/:id` | Delete saved scan |

### SSE Events

| Event | Data |
|-------|------|
| `progress` | `{scanned, queue, requests, speed, critical, high, medium, low, ...}` |
| `dir` | Directory path discovered |
| `found` | Finding object with url, severity, secrets, preview |
| `log` | Log line |
| `finished` | Summary with tree stats, frameworks, cloud hints |

---

## Plugins

Plugins extend detection for specific frameworks. Place Python files in `plugins/`:

```python
# plugins/example.py
def check(finding):
    """Return modified finding or None."""
    path = finding.get("path", "").lower()
    if "example" in path:
        finding["cloud"] = list(set(finding.get("cloud", []) + ["ExampleCloud"]))
    return finding
```

### Built-in Plugins

| Plugin | Description |
|--------|-------------|
| `wordpress.py` | WordPress-specific path detection |
| `laravel.py` | Laravel `.env` and config detection |
| `git.py` | Git repository exposure detection |
| `docker.py` | Docker config/secret detection |
| `firebase.py` | Firebase/Supabase URL detection |

---

## YARA Rules

Custom YARA rules in `yara_rules/` are compiled and run against file content:

| Rule File | Purpose |
|-----------|---------|
| `api_keys.yar` | Generic API key patterns |
| `aws.yar` | AWS-specific secrets |
| `malware.yar` | Known malware signatures |
| `wordpress.yar` | WordPress-specific patterns |

Add custom `.yar` files to `yara_rules/` — they are auto-loaded on scan start.

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEEPSCAN_USER` | `admin` | Default login username |
| `DEEPSCAN_PASS` | `admin` | Default login password |
| `DEEPSCAN_SECRET` | auto-generated | HMAC signing secret |

### Settings Panel (Web UI)

- **Theme**: Dark / Light
- **Results per page**: 10 / 25 / 50 / 100 / All
- **Column visibility**: Toggle columns in results table
- **Default scan values**: Workers, depth, full download, respect robots.txt

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Development Setup

```bash
pip install -r requirements.txt
python indexhunter.py --web
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Always obtain proper authorization before scanning any system. The authors are not responsible for misuse.

---

<p align="center">
  <b>Built with Python, FastAPI, aiohttp, and Tailwind CSS</b><br>
  <sub>Made by <a href="https://github.com/CodeZANKO">CodeZANKO</a></sub>
</p>
