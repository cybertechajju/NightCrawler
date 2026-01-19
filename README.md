<div align="center">

# 🦇 NightCrawler

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&weight=600&size=28&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=600&lines=Advanced+JS+Secret+Scanner;KeyHacks+Auto-Validation;Red+Team+Level+Tool;Built+for+Bug+Bounty+Hunters" alt="Typing SVG" />

<br>

[![Version](https://img.shields.io/badge/version-5.0-brightgreen.svg?style=for-the-badge)](https://github.com/cybertechajju/NightCrawler)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-yellow.svg?style=for-the-badge)](LICENSE)
[![Stars](https://img.shields.io/github/stars/cybertechajju/NightCrawler?style=for-the-badge&logo=github)](https://github.com/cybertechajju/NightCrawler)

<br>

**Hunt for secrets, API keys, and hidden endpoints in JavaScript files**

*Auto-validate discovered secrets using 75+ KeyHacks validators*

<br>

[📖 Documentation](#-usage) •
[🚀 Quick Start](#-quick-start) •
[🛠️ Installation](#-installation) •
[⚙️ Configuration](#-configuration)

</div>

---

## 🎬 Demo

```
███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗██████╗  █████╗ ██╗    ██╗██╗     ███████╗██████╗ 
████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔════╝██╔══██╗██╔══██╗██║    ██║██║     ██╔════╝██╔══██╗
██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║     ██████╔╝███████║██║ █╗ ██║██║     █████╗  ██████╔╝
██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║     ██╔══██╗██╔══██║██║███╗██║██║     ██╔══╝  ██╔══██╗
██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╗██║  ██║██║  ██║╚███╔███╔╝███████╗███████╗██║  ██║
╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝  ╚═╝

┌─────────────────────────────────────────────────────────────┐
│ v5.0 │ All 9 Tools │ No Timeout │ 75+ KeyHacks │ CyberTechAjju │
└─────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

<table>
<tr>
<td width="50%">

### 🔍 Secret Detection
- **200+ Regex Patterns**
- AWS, Azure, GCP keys
- API tokens & secrets
- Database credentials
- JWT tokens
- Private keys

</td>
<td width="50%">

### 🔑 Auto-Validation
- **75+ KeyHacks Validators**
- GitHub, Stripe, Slack
- Discord, Twilio, SendGrid
- OpenAI, Anthropic, Cohere
- Shodan, VirusTotal
- Real-time validation

</td>
</tr>
<tr>
<td width="50%">

### 🌐 External Tools
- **12+ Recon Tools**
- Subfinder, Httpx
- Katana, Hakrawler
- GAU, Waybackurls
- SubJS, JSLuice
- GetJS, Mantra

</td>
<td width="50%">

### 📊 Reports
- **3 Report Formats**
- HackerOne template
- BugCrowd template
- Email format
- CVSS scores
- PoC included

</td>
</tr>
</table>

---

## 🚀 Quick Start

```bash
# Clone and enter directory
git clone https://github.com/cybertechajju/NightCrawler.git
cd NightCrawler

# Install dependencies
pip3 install -r requirements.txt

# Run interactive mode
python3 run.py
```

That's it! The interactive mode will guide you through everything. 🎉

---

## 🛠️ Installation

### Step 1: Clone Repository

```bash
git clone https://github.com/cybertechajju/NightCrawler.git
cd NightCrawler
```

### Step 2: Install Python Dependencies

```bash
pip3 install -r requirements.txt
```

Required packages:
- `aiohttp` - Async HTTP client
- `rich` - Beautiful terminal UI
- `jsbeautifier` - JS beautification
- `click` - CLI framework

### Step 3: Install External Tools (Optional but Recommended)

<details>
<summary><b>📦 One-liner Install (All Tools)</b></summary>

```bash
# Install Go first (if not installed)
# https://golang.org/doc/install

# Install all tools
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest && \
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest && \
go install -v github.com/projectdiscovery/katana/cmd/katana@latest && \
go install -v github.com/lc/gau/v2/cmd/gau@latest && \
go install -v github.com/tomnomnom/waybackurls@latest && \
go install -v github.com/lc/subjs@latest && \
go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest && \
go install -v github.com/hakluke/hakrawler@latest && \
go install -v github.com/003random/getJS@latest && \
go install -v github.com/tomnomnom/anew@latest

# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

</details>

<details>
<summary><b>📦 Individual Tool Installation</b></summary>

| Tool | Purpose | Install Command |
|------|---------|-----------------|
| **Subfinder** | Subdomain enumeration | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| **Httpx** | HTTP probing | `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| **Katana** | Web crawler | `go install -v github.com/projectdiscovery/katana/cmd/katana@latest` |
| **GAU** | Archive URLs | `go install -v github.com/lc/gau/v2/cmd/gau@latest` |
| **Waybackurls** | Wayback Machine | `go install -v github.com/tomnomnom/waybackurls@latest` |
| **SubJS** | JS file fetcher | `go install -v github.com/lc/subjs@latest` |
| **JSLuice** | JS extractor | `go install -v github.com/BishopFox/jsluice/cmd/jsluice@latest` |
| **Hakrawler** | Crawler | `go install -v github.com/hakluke/hakrawler@latest` |
| **GetJS** | JS extractor | `go install -v github.com/003random/getJS@latest` |
| **Anew** | Unique lines | `go install -v github.com/tomnomnom/anew@latest` |

</details>

### Step 4: Verify Installation

```bash
python3 run.py
```

The tool will show you which tools are found:

```
                          Tool Status                          
┏━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Tool       ┃  Status  ┃ Path                                ┃
┡━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Subfinder  │ ✓ Found  │ /usr/bin/subfinder                  │
│ Httpx      │ ✓ Found  │ /usr/bin/httpx                      │
│ Katana     │ ✓ Found  │ ~/go/bin/katana                     │
│ GAU        │ ✓ Found  │ ~/go/bin/gau                        │
│ Waybackurls│ ✓ Found  │ ~/go/bin/waybackurls                │
└────────────┴──────────┴─────────────────────────────────────┘
```

---

## 📖 Usage

### 🎮 Interactive Mode (Recommended)

```bash
python3 run.py
```

**Flow:**
```
1. 🔍 Dependency Check    → Auto-checks all tools
2. 🎯 Enter Target        → example.com
3. ⚙️ Scan Mode           → [1] Main  [2] Subdomains  [3] Deep
4. 🔑 Validate Keys?      → [y/n]
5. 📄 Generate Report?    → [y/n]
6. 📋 Report Format       → [1] HackerOne  [2] BugCrowd  [3] Email
7. ✍️ Your Name           → Hunter
8. 🚀 Start Scan!
```

### 💻 Command Line Mode

```bash
# Basic scan
python3 main.py -t example.com -o report.html

# With KeyHacks validation
python3 main.py -t example.com -o report.html --validate-keys

# Subdomain scan + validation
python3 main.py -t example.com -o report.html --mode subdomains --validate-keys

# Deep scan (all tools)
python3 main.py -t example.com -o report.html --mode deep --validate-keys

# Automated (no prompts)
python3 main.py -t example.com -o report.html --mode deep --validate-keys --no-prompt
```

### 📋 All CLI Options

```
Usage: main.py [OPTIONS]

Options:
  -t, --target TEXT               Target domain
  -l, --list PATH                 File with list of targets
  -u, --urls PATH                 File with JS URLs to scan
  -o, --output PATH               Output file (.json or .html)
  -c, --concurrency INTEGER       Concurrent requests [default: 50]
  -d, --depth INTEGER             Crawl depth [default: 2]
  --timeout INTEGER               Request timeout [default: 30]
  --mode [main|subdomains|deep]   Scan mode
  --validate-keys                 Auto-validate secrets
  --validate-timeout INTEGER      Validation timeout [default: 10]
  --template [hackerone|bugcrowd|email]   Report format
  --reporter TEXT                 Reporter name
  --program TEXT                  Bug bounty program name
  --no-prompt                     Skip interactive prompts
  -v, --verbose                   Verbose output
  -q, --quiet                     Only output findings
  --version                       Show version
  --help                          Show help
```

---

## ⚙️ Configuration

### config.yaml

```yaml
# Tool paths (leave empty to auto-detect)
tools:
  subfinder: ""      # Auto-detect from PATH
  httpx: ""
  katana: ""
  gau: ""
  waybackurls: ""

# Scan settings
scan:
  concurrency: 50    # Concurrent requests
  timeout: 30        # Request timeout (seconds)
  depth: 2           # Crawl depth

# Report settings
report:
  default_template: hackerone
  default_reporter: YourName
```

### Custom Tool Paths

If your tools are in a custom location:

```yaml
tools:
  subfinder: "/path/to/subfinder"
  katana: "/custom/path/katana"
```

---

## 🔑 KeyHacks Validators

<details>
<summary><b>75+ Supported Services (Click to expand)</b></summary>

| Category | Services |
|----------|----------|
| **Cloud Providers** | AWS, Google Cloud, Firebase, Azure, DigitalOcean, Heroku, Vercel, Netlify, Cloudflare |
| **Git & CI/CD** | GitHub, GitLab, CircleCI, Travis CI, NPM, Bitbucket |
| **Payment** | Stripe, PayPal, Square, Razorpay, Braintree |
| **Messaging** | Slack, Discord, Telegram, Twilio |
| **Email** | SendGrid, MailGun, MailChimp, Postmark |
| **Security/Recon** | Shodan, VirusTotal, Censys, SecurityTrails |
| **AI/ML** | OpenAI, Anthropic/Claude, Cohere, Replicate, Pinecone |
| **Databases** | Supabase, PlanetScale, MongoDB Atlas, Firebase |
| **Productivity** | Notion, Figma, Airtable, Linear, Jira, Confluence, Asana, Monday, ClickUp |
| **Analytics** | Datadog, Sentry, New Relic, Mixpanel, Amplitude, PagerDuty |
| **Social** | Facebook, Twitter/X, Instagram, LinkedIn, Spotify |
| **Storage** | Dropbox, Box, Google Drive |
| **Auth** | Auth0, Clerk, Okta |
| **Other** | Mapbox, Algolia, HubSpot, Zendesk, LaunchDarkly, Intercom |

</details>

---

## 📁 Project Structure

```
NightCrawler/
├── 📄 run.py              # Interactive mode entry
├── 📄 main.py             # CLI mode entry
├── 📄 requirements.txt    # Python dependencies
├── 📄 config.yaml         # Configuration
├── 📁 src/
│   ├── 📁 core/
│   │   └── scanner.py     # Main scanning logic
│   ├── 📁 patterns/
│   │   └── secrets.py     # 200+ regex patterns
│   ├── 📁 validators/
│   │   └── keyhacks.py    # 75+ API validators
│   ├── 📁 integrations/
│   │   └── tools.py       # External tool wrappers
│   ├── 📁 output/
│   │   ├── html_report.py # Report generator
│   │   └── console.py     # Console output
│   └── 📁 ui/
│       └── banner.py      # UI components
└── 📁 data/
    └── patterns/          # Custom patterns
```

---

## 📊 Scan Modes

| Mode | Description | Tools Used |
|------|-------------|------------|
| **Main** | Fast scan on main domain only | Katana, Internal patterns |
| **Subdomains** | Enumerate + scan all subdomains | Subfinder, Httpx, Katana |
| **Deep** | Full recon with archives | All tools: Subfinder, Httpx, Katana, GAU, Waybackurls, SubJS, etc. |

---

## ⚠️ Disclaimer

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           ⚠️  ETHICAL USE ONLY  ⚠️                            ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  This tool is intended for AUTHORIZED security testing only:                ║
║                                                                              ║
║  ✅ Bug Bounty Programs (with explicit permission)                           ║
║  ✅ Authorized Penetration Testing                                           ║
║  ✅ Security Assessments (with signed authorization)                         ║
║                                                                              ║
║  ❌ Unauthorized access is ILLEGAL                                           ║
║  ❌ Using validated keys without permission is a CRIME                       ║
║                                                                              ║
║  The author is NOT responsible for any misuse of this tool.                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

---

## 🤝 Contributing

Contributions are welcome! 

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file.

---

## 👨‍💻 Author

<div align="center">

**CyberTechAjju**

[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/cybertechajju)
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/cybertechajju)

*Keep Learning // Keep Hacking* 🦇

</div>

---

<div align="center">

**If you find this tool useful, please ⭐ star the repository!**

Made with ❤️ for the Bug Bounty Community

</div>
