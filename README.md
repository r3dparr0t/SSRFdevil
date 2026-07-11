# SSRFdevil
Rule-Based SSRF Discovery & Exploitation Framework.
SSRF scanner and attacker going to be fully automated soon!

هنوز در حال توسعه هست...
— فعلاً اینترنت را می‌خزد؛ بعد نوبت اسکن است. 😁

> **SSRF Detection & Exploitation Framework** — ولی فعلاً فقط قورت‌دهنده‌ی رول‌ها! :))

SSRFdevil یه موتور هوشمند برای شناسایی و دور زدن آسیب‌پذیری‌های SSRF هست.  
این پروژه با **Rust** نوشته شده و از معماری **Rule-Based** با قابلیت اجرای اسکریپت‌های **Lua** برای تولید پیلودهای پویا استفاده می‌کنه.

---

## 🚧 Current Status (Phase 1)

Core framework is operational.

Implemented:

✅ Interactive Console
✅ Rule Engine (YAML)
✅ Payload Database
✅ Target Database
✅ Lua Rule Support (WIP)
✅ High-speed Web Crawler
✅ Resource Classification
✅ URL Parameter Extraction

In Progress:
🚧 Scanner Engine
🚧 False Positive Reduction
🚧 Lua Runtime
🚧 Crawl Configuration

---

## ⚙️ نحوه‌ی اجرا (همین الان!)

```bash
# ۱. کلون کردن پروژه
git clone https://github.com/r3dparr0t/SSRFdevil.git
cd SSRFdevil

# ۲. اجرا (نیاز به Rust داره)
cargo run -- <target_url>
