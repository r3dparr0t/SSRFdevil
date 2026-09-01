📝 README.md جدید برای SSRFdevil

```markdown
# SSRFdevil — Advanced SSRF Scanner & Exploitation Framework

[![Rust](https://img.shields.io/badge/Rust-1.70+-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**SSRFdevil** is a modern, rule‑based Server‑Side Request Forgery (SSRF) scanner with a built‑in crawler, Lua scripting engine, and an intelligent evidence‑based verdict system. It is designed for security researchers and penetration testers to automate detection and exploitation of SSRF vulnerabilities in web applications.

---

## 🚀 Features

- **49+ Built‑in SSRF Rules** — Covers IPv4/IPv6 bypasses, DNS rebinding, encoding tricks (hex/octal/decimal), cloud metadata endpoints (AWS, GCP, Azure), protocol abuse (file://, gopher://, dict://, ftp://), and more.
- **Evidence‑Based Verdict System** — Reduces false positives by using `success_indicator` and `failure_indicator` with `literal:` and `regex:` patterns. Rules with indicators that fail to match are automatically downgraded to `Suspicious`.
- **Lua Scripting Engine** — Write dynamic payload generation rules in Lua. Each rule can generate multiple payloads per target with custom headers, methods, and body.
- **Interactive Console** — Full‑featured TUI with command history, rule selection, crawling, scanning, and real‑time feedback.
- **Built‑in Web Crawler** — Recursively discovers endpoints, extracts parameters, and detects SSRF‑prone parameters (`url`, `dest`, `redirect`, `callback`, etc.).
- **Session Cookie Injection** — Set a cookie once and both crawler and scanner use it for authenticated requests.
- **Proxy Support** — Rotate proxies from a list file for anonymity and rate‑limit avoidance.
- **Rule Generator** — `cargo run --bin new_rule` guides you through creating new rules with confidence scores and indicators.
- **Rule Tester** — `cargo run --bin test_rule -- <path.yaml>` validates Lua scripts before deployment.

---

## 📦 Installation

### Prerequisites

- **Rust** (1.70+)
- **Cargo**

### Build from Source

```bash
git clone https://github.com/r3dparr0t/SSRFdevil.git
cd SSRFdevil
cargo build --release
```

The binary will be available at target/release/ssrfdevil.

---

🎯 Quick Start

Basic Usage

```bash
cargo run -- https://example.com
```

This launches the interactive console with target pre‑loaded.

Console Commands

Command Description
ls / list Show all available rules
use <index\|id\|tag\|all> Select rules for scanning
crawl Run the crawler to discover endpoints
run / scan Execute selected rules against crawled targets
cookie [clear\|status] Set, clear, or view session cookie (auto‑enables injection)
code <index\|id> Display Lua source code of a rule
info <index\|id> Show rule metadata (tags, severity, confidence, indicators)
settings Open interactive TUI to configure UA, threads, proxies, etc.
search <text> Search rules by name, tag, or description
back Clear selected rules
help Show command list
exit / quit Exit console

---

🧠 Rule System

Rules are defined as YAML + Lua files stored in rules/. Each rule consists of:

· Metadata: id, name, description, author, rank, severity, confidence, tags
· Match Config: Conditions for target selection (schemes, required tags, parameter requirements)
· Lua Script: run_batch(targets) function that returns an array of payloads
· Indicators (optional):
  · success_indicator: Array of literal: or regex: patterns that confirm success
  · failure_indicator: Array of patterns that trigger immediate Rejected verdict

Example Rule: file_etc_passwd.yaml

```yaml
meta:
  id: file_etc_passwd
  confidence: 80
  severity: critical
  success_indicator:
    - "literal:root:x:0:0"
  failure_indicator:
    - "literal:no such file"
    - "literal:cannot open"
```

When this rule runs:

· If response contains root:x:0:0 → Confirmed (with bonus)
· If response contains no such file → Rejected
· If neither (but status is 200) → Suspicious (because success_indicator didn't match)

---

🔬 How the Verdict System Works

The verdict engine combines multiple evidence sources:

1. Transport errors → Error
2. 4xx status codes → Rejected (immediate)
3. Failure indicators → Rejected (immediate)
4. Success indicators → +30 bonus (if matched)
5. Missing success indicator → Cap at Suspicious (prevents false positives)
6. Status code + metadata score → final verdict threshold

Score Range Verdict
70+ Confirmed
50–69 Likely
30–49 Suspicious
0–29 Rejected

---

🛠️ Custom Rules

Create a New Rule

```bash
cargo run --bin new_rule
```

The interactive generator will ask for:

· Rule name, description, tags
· Severity and rank
· Confidence (0–100)
· Success and failure indicators
· Lua script source (type END on new line to finish)

Test a Rule

```bash
cargo run --bin test_rule -- rules/25_file_etc_passwd.yaml
```

This runs the Lua script against mock targets and displays generated payloads.

---

🔐 Cookie Injection

Set a session cookie once, and both the crawler and scanner will use it automatically:

```
ssrfdevil > cookie
🍪 Enter session cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
[✅] Cookie set and enabled for all requests!
```

This allows authenticated crawling and scanning of protected endpoints.

---

📁 Project Structure

```
SSRFdevil/
├── src/
│   ├── bin/
│   │   ├── new_rule.rs         # Rule generator
│   │   └── test_rule.rs        # Lua script tester
│   ├── crawler/                # Web crawler engine
│   ├── engine/                 # Core engine (requests, rules, UA, proxy, cookie)
│   ├── lua_engine/             # Lua execution environment
│   ├── scanner/                # Scanner + verdict system
│   ├── console.rs              # Interactive console
│   └── main.rs                 # Entry point
├── rules/                      # YAML rule definitions
├── Cargo.toml
└── README.md
```

---

📚 References & Acknowledgments

· HackTricks SSRF Bypass
· AWS Metadata
· GCP Metadata
· Azure Metadata

---

📄 License

MIT © r3dparr0t

---

⭐ Star the Project

If you find this useful, give it a star on GitHub and share it with your network!

Happy hacking! 🚀

```