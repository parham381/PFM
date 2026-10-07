<p align="center">
  <pre>
   ██████╗ ███████╗███╗   ███╗
   ██╔══██╗██╔════╝████╗ ████║
   ██████╔╝█████╗  ██╔████╔██║
   ██╔═══╝ ██╔══╝  ██║╚██╔╝██║
   ██║     ██║     ██║ ╚═╝ ██║
   ╚═╝     ╚═╝     ╚═╝     ╚═╝
  </pre>
  <h3>Port Forward Manager</h3>
  <p>Port Forwarding Tool with Per-Port Bandwidth Monitoring</p>

  <a href="https://t.me/AbrAfagh"><img src="https://img.shields.io/badge/Telegram-Channel-blue?logo=telegram" alt="Telegram"></a>
  <img src="https://img.shields.io/badge/Version-1.7-green" alt="Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow" alt="License">
  <img src="https://img.shields.io/badge/OS-Ubuntu%2FDebian-orange" alt="OS">
</p>

---

<div dir="rtl" align="right">

## 🇮🇷 فارسی

### پی‌اف‌ام چیست؟

PFM یک ابزار مدیریت پورت فوروارد با قابلیت مانیتورینگ ترافیک روی هر پورت است. این ابزار به شما اجازه میدهد پورت‌های سرور ایران را به سرور خارج فوروارد کنید و مصرف ترافیک هر کاربر را به صورت دقیق پیگیری و محدود کنید.

### ✨ امکانات

- **سه موتور** — iptables، HAProxy و Realm (بهترین عملکرد)
- **مانیتورینگ ترافیک** — مشاهده مصرف دانلود روی هر پورت به صورت لحظه‌ای
- **محدودیت ترافیک** — تعیین سقف مصرف بر حسب گیگابایت و قطع خودکار
- **مدیریت کاربران** — اختصاص پورت به کاربران با لینک آیدی تلگرام
- **ربات تلگرام** — مدیریت کامل از راه دور با ربات تلگرام
- **بکاپ خودکار** — گزارش بکاپ ترافیک هر ۶ ساعت
- **هلث‌چک Realm / HAProxy** — ریستارت خودکار سرویس‌های خراب یا سرویسی که بالاست ولی پورت را گوش نمی‌دهد
- **تایید واقعی تانل** — بعد از افزودن تانل بررسی می‌شود پورت واقعاً باز است؛ در غیر این صورت علت نمایش داده می‌شود و تانل ناقص ساخته نمی‌شود
- **ترمیم خودکار** — اگر ufw/Docker/اسکریپت دیگری قوانین iptables را پاک کند، `pfm sync` (کرون هر ۵ دقیقه) آن‌ها را برمی‌گرداند
- **تشخیص مشکل** — دستور `pfm doctor` دلیل کار نکردن هر تانل را نشان می‌دهد
- **پشتیبانی IPv4 و IPv6**

### 🚀 نصب سریع

<div dir="ltr" align="left">

```bash
bash <(curl -s https://raw.githubusercontent.com/SadraHimself/PFM/main/pfm.sh) install
```

</div>

### 🤖 نصب ربات تلگرام

<div dir="ltr" align="left">

```bash
bash <(curl -s https://raw.githubusercontent.com/SadraHimself/PFM/main/pfm-bot-setup.sh)
```

</div>

### 🩺 تانل اضافه شده ولی ترافیک رد نمی‌شود؟

<div dir="ltr" align="left">

```bash
pfm doctor          # بررسی همه تانل‌ها
pfm doctor 443      # بررسی فقط یک پورت
```

</div>

دلایل رایج که حالا خودکار شناسایی یا رفع می‌شوند:

- پورت قبلاً توسط برنامه دیگری گرفته شده (Realm در این حالت بدون خطا زنده می‌ماند ولی پورت را گوش نمی‌دهد)
- یک تانل HAProxy با مقصد نامعتبر کل کانفیگ را خراب می‌کرد و تانل‌های بعدی بی‌صدا بالا نمی‌آمدند
- `FORWARD`/`INPUT` روی DROP است (ufw، Docker) — PFM حالا برای هر تانل قانون ACCEPT مخصوص خودش را می‌گذارد
- قوانین iptables توسط برنامه دیگری پاک شده یا `ip_forward` صفر شده
- مقصد از روی همین سرور قابل دسترسی نیست (IP/پورت اشتباه یا مسدود بودن سرور)

### 📬 ارتباط با ما

- کانال تلگرام: [@AbrAfagh](https://t.me/AbrAfagh)

</div>

---

## 🇬🇧 English

### ✨ Features

- **Multi-Engine** — iptables, HAProxy (splice), Realm (zero-copy)
- **Per-Port Bandwidth Monitoring** — Track download usage per port in real-time
- **Traffic Limits** — Set GB limits per port, auto-block when exceeded
- **User Management** — Assign ports to users with Telegram ID linking
- **Telegram Bot** — Full remote management via Telegram bot
- **Auto Backup** — 6-hour automatic traffic backup reports
- **Realm / HAProxy Health Check** — Auto-restart crashed services, and services that are "active" but do not actually own their port
- **Verified Tunnels** — A new tunnel is checked to really be listening / in place; if not, the real reason is shown and nothing half-configured is left behind
- **Self-Healing** — If ufw/Docker/another script flushes the iptables rules, `pfm sync` (cron, every 5 min) puts them back
- **Diagnostics** — `pfm doctor` explains why a tunnel does not forward
- **MTU Management** — Persistent MTU settings per interface
- **IPv4 & IPv6** — Full dual-stack support
- **Menu-Driven** — Easy interactive CLI interface

## 🚀 Quick Install

```bash
bash <(curl -s https://raw.githubusercontent.com/SadraHimself/PFM/main/pfm.sh) install
```

## 📦 Manual Install

```bash
curl -o /usr/local/bin/pfm https://raw.githubusercontent.com/SadraHimself/PFM/main/pfm.sh
chmod +x /usr/local/bin/pfm
pfm install
```

## 🤖 Telegram Bot Setup

The bot allows you to manage all your PFM servers remotely from Telegram.

```bash
bash <(curl -s https://raw.githubusercontent.com/SadraHimself/PFM/main/pfm-bot-setup.sh)
```

**Bot Features:**
- 📊 View traffic usage per user/port across all servers
- 🔄 Sync traffic data
- 🔴🟢 Block/Unblock ports
- 📝 Set/Edit traffic limits
- ➕➖ Add/Subtract traffic
- 📦 Manual & automatic backups (every 6h)
- ⚙️ Edit server connections from Telegram
- 👤 Users can check their own usage via bot

## 📸 Screenshots

<details>
<summary>CLI Menu</summary>

```
  ──────────────────────────────────────────
         PFM - Port Forward Manager v1.7
              https://t.me/AbrAfagh
  ──────────────────────────────────────────

  1)  Add Tunnel
  2)  Manage Tunnels
  3)  View Traffic
  4)  Monitor (Live)
  5)  Users
  6)  MTU Settings
  7)  Install / Update
  8)  Uninstall
  0)  Exit
```

</details>

<details>
<summary>Traffic View</summary>

```
  Traffic  (Download Only)

  a_real_shit [ON]  TG:1605183796

  PORT    DESTINATION        ENGINE    USED          LIMIT         REMAIN     STATUS
  ──────────────────────────────────────────────────────────────────────────────
  6003    91.107.251.41:6003 realm     2.72 MB       1.16 TB       1.16 TB    Active
  6004    91.107.251.41:6004 realm     381.09 KB     846.00 GB     846.00 GB  Active
  TOTAL                                3.10 MB       2.00 TB       2.00 TB
```

</details>

## ⚙️ Engines

| Engine | Type | Use Case |
|--------|------|----------|
| **iptables** | Kernel NAT | Default, simple port forwarding |
| **HAProxy** | Splice (TCP) | High-performance TCP proxy |
| **Realm** | Zero-copy | Best performance, TCP + UDP |

## 📁 File Structure

```
/usr/local/bin/pfm          # Main script
/usr/local/bin/pfm-cmd      # Bot command helper
/etc/pfm/
├── users/                  # User configs
├── ports/                  # Port configs
├── usage/                  # Traffic data (bytes)
├── mtu/                    # MTU settings
└── realm/                  # Realm TOML configs
```

## 🔧 Commands

```bash
pfm                  # Open interactive menu
pfm install          # Install/Update PFM
pfm restore          # Restore rules after reboot
pfm sync             # Sync traffic counters (+ health check / self-heal)
pfm doctor [port]    # Diagnose tunnels that do not forward
pfm json             # JSON output (for bot)
pfm monitor          # Live traffic monitor
pfm uninstall        # Remove PFM
```

## 🩺 Troubleshooting

Tunnel added but no traffic? Run `pfm doctor` (or `pfm doctor <port>`). Typical causes it detects:

- The listen port is already used by another process (Realm keeps running without owning the port)
- One HAProxy tunnel with an unresolvable destination used to invalidate the whole config, so later tunnels silently never started
- `FORWARD`/`INPUT` default policy is `DROP` (ufw, Docker) — PFM now installs its own per-tunnel `ACCEPT` rules
- iptables rules flushed by something else, or `net.ipv4.ip_forward` reset to 0
- The destination is not reachable from this server (wrong IP/port, or the destination blocks this server)

## 📋 Requirements

- Ubuntu 18+ / Debian 10+
- Root access
- `curl` or `wget`
- `sshpass` (for bot password auth)

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

## 📄 License

[MIT](LICENSE)

## 📬 Contact

- Telegram Channel: [@AbrAfagh](https://t.me/AbrAfagh)
