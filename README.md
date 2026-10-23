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
  <img src="https://img.shields.io/badge/Version-2.0-green" alt="Version">
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
- **تشخیص قانون بیگانه روی پورت** — اگر ابزار دیگری (تانل‌منیجر دیگر، Docker، firewalld، قانون تست فراموش‌شده) همان پورت را DNAT/REDIRECT کند و ترافیک را قبل از تانل بدزدد، `pfm doctor` خود قانون، تعداد بسته‌ها و دستور حذفش را نشان می‌دهد؛ هنگام افزودن تانل هم قبلش هشدار می‌دهد
- **شمارنده «رسید / تحویل شد»** — برای هر تانل شمرده می‌شود چند بسته از بیرون به سرور رسیده و چندتا واقعاً به تانل رسیده است؛ اگر بسته‌ها می‌رسند ولی به تانل نمی‌رسند (قانون بیگانه، rp_filter، فایروال) هشدار داده می‌شود و `pfm sync` آن را در لاگ می‌نویسد
- **پشتیبانی IPv4 و IPv6**
- **تست کامل تانل (Bench Test)** — برای هر تانل: تأخیر، جیتر، پکت‌لاس، پایداری، MTU، مسیر (MTR)، سرعت دانلود/آپلود، Bufferbloat و سربار موتور؛ خروجی آمادهٔ اسکرین‌شات با نمره و پیشنهاد قدم بعدی
- **دستیار بهینه‌سازی** — BBR، بافرها و محدودیت‌های سرور، کارت شبکه، تست و انتخاب بهترین DNS، پیدا کردن و اعمال بهترین MTU، پروفایل هر تانل (گیمینگ / حداکثر پهنای باند / متعادل / کاربر زیاد) و برگشت کامل به حالت اول
- **دستور سریع `PFM`** — در هر جای سرور فقط `PFM` را بنویسید تا پنل باز شود
- **سوییچ بین نسخه‌ها** — نسخه‌های قبلی گیتهاب را ببینید و به هرکدام برگردید؛ برنامهٔ جایگزین‌شده همیشه ذخیره می‌شود و بعد از هر تغییر همهٔ تانل‌ها بررسی می‌شوند

### 🚀 نصب سریع

<div dir="ltr" align="left">

```bash
bash <(curl -s https://raw.githubusercontent.com/parham381/PFM/main/pfm.sh) install
```

</div>

> برای آپدیت از نسخه‌های قبلی همین دستور را یک‌بار دیگر بزنید. از آن به بعد کافی است `PFM` بنویسید.

### ⚡ دستور سریع `PFM`

بعد از نصب، در هر جای سرور فقط بنویسید:

<div dir="ltr" align="left">

```bash
PFM
```

</div>

پنل باز می‌شود (حروف بزرگ؛ `pfm` با حروف کوچک هم کار می‌کند). این با `PFM install` فرق دارد: `PFM` فقط پنل را باز می‌کند و `PFM install` نصب/آپدیت می‌کند. اگر با کاربر غیر root وارد شده باشید، خودش از `sudo` استفاده می‌کند. تکمیل خودکار با Tab فعال است (`PFM ben<Tab>`) و `PFM help` همه‌ی دستورها را نشان می‌دهد.

### 📊 تست کامل تانل (Bench Test)

مسیر: **مدیریت تانل‌ها ← انتخاب تانل ← ۱۰) Bench Test** — یا دستور `pfm bench <پورت> [quick|full]`.

| چه چیزی سنجیده می‌شود | سریع (~۴۰ ثانیه) | کامل (~۳ دقیقه) |
|---|:---:|:---:|
| تأخیر، جیتر و پکت‌لاس (ICMP) | ۸ ثانیه | ۶۰ ثانیه + نمودار پایداری و شمارش جهش‌های تأخیر |
| هندشیک TCP به پورت مقصد (MSS و RTT از دید کرنل) | ✔ | ✔ |
| MTU واقعی مسیر با بسته‌های DF و تشخیص «MTU black hole» | ✔ | ✔ |
| مسیر (MTR) و هاپ‌ها | ✔ | ✔ |
| ترافیکی که همین الان از تانل رد می‌شود | ✔ | ✔ |
| سرعت دانلود و آپلود (۴ اتصال و ۱ اتصال)، جریان UDP شبیه بازی، تأخیر زیر بار (Bufferbloat)، سربار خود موتور، CPU و دراپ کارت شبکه | — | ✔ با Helper |

**تست سرعت به یک Helper در سرور مقصد نیاز دارد**؛ چون سرعت یک تانل را فقط با دو سرش می‌شود اندازه گرفت. دستور آماده در خود برنامه (گزینه ۴ منوی Bench) نشان داده می‌شود:

<div dir="ltr" align="left">

```bash
bash <(curl -sL https://raw.githubusercontent.com/parham381/PFM/main/pfm.sh) bench-server 5201 <IP سرور PFM>
```

</div>

iperf3 را نصب می‌کند، فقط به همان IP اجازهٔ اتصال می‌دهد و بعد از ۱۵ دقیقه (قابل تنظیم، ۱ تا ۱۲۰) خودش خاموش می‌شود و قوانین فایروالِ موقت را پاک می‌کند. **محدودیت IP قبل از شروع در فایروال بررسی می‌شود**؛ اگر نشد، Helper راه نمی‌افتد (باز گذاشتن پورت برای همه فقط با اجرای بدون IP). پورتی که سرویس دیگری (TCP یا UDP، مثلاً WireGuard) استفاده می‌کند رد می‌شود، و قوانین به‌جامانده از Helperای که با `kill -9` متوقف شده در اجرای بعدی پاک می‌شوند (تا وقتی iperf3 آن هنوز روی پورت گوش می‌دهد قوانین می‌مانند تا پورت باز نشود)؛ یک تایمر مستقل هم قوانین را سر موعد برمی‌دارد. بدون Helper، تست کامل فقط بخش سرعت را رد می‌کند؛ سنجش سرعت خود سرور به اینترنت (دانلود تا ۱۰۰ مگابایت از Cloudflare) فقط با `--inet` یا پاسخ y در منو انجام می‌شود. اگر همین الان کاربرانی از تانل استفاده می‌کنند، قبل از تست سرعت هشدار می‌دهد و تأیید می‌گیرد؛ پاسخ پیش‌فرض «نه» است (تست سرعت تا حدود ۴ گیگابایت ترافیک روی خط ۱ گیگابیتی مصرف می‌کند). گزینه‌های `--peer` و `--inet` یعنی تست کامل.

**خروجی** (برای اسکرین‌شات طراحی شده، کمتر از ۹۰ ستون):

- نمرهٔ ۰ تا ۱۰۰ و درجهٔ A تا F — هر مشکل جدی (پکت‌لاس، جیتر، Bufferbloat، MTU black hole) سقف نمره را پایین می‌آورد. **تعداد پکت‌های گمشده مهم است نه فقط درصد**: یک پینگ گمشده از ۴۰ تا (۲٫۵٪) الگو حساب نمی‌شود و نمره را نمی‌شکند؛ حداقل ۳ پکت گمشده لازم است. اگر هیچ پینگی زیر بار برنگردد (یا ≥۳۰٪ آن‌ها گم شوند)، نتیجه «بد» است، نه «تأخیر ثابت»؛ اتصال‌های TCP ناموفق به پورت سرویس با وجود پینگِ سالم هم یافتهٔ جدا و سقف نمره دارد؛ اگر هیچ چیز جواب ندهد (مثلاً سرویس فقط UDP) «قابل اندازه‌گیری نیست» نشان داده می‌شود، نه ۰ از ۱۰۰. تانل بلاک‌شده یا خاموش اول از همه گزارش می‌شود
- وضعیت تانل برای هر نوع استفاده: گیمینگ، استریم/دانلود، تماس صوتی/تصویری، استفادهٔ روزمره (در تست سریع «استریم/دانلود» **n/a** است چون سرعت اندازه نمی‌گیرد). گزارش صریح می‌گوید فقط بخش «سرور ← مقصد» را پوشش می‌دهد
- جدول اعداد، نمودار پایداری و «یافته‌ها» به زبان ساده
- **قدم‌های بعدی**: هر پیشنهاد مستقیماً به دستیار بهینه‌سازی وصل است — شمارهٔ آن را بزنید تا همان‌جا اجرا شود، سپس با `r` دوباره تست کنید. گزارش جدید فرق با تست قبلی و کارهایی که دستیار در این فاصله انجام داده را نشان می‌دهد
- کلید `m` آدرس‌های IP و همچنین نام میزبانِ مقصد/سرور و نام مالک را مخفی می‌کند (برای فرستادن عکس به یک متخصص شبکه)، `d` صفحهٔ جزئیات (جدول MTR و اعداد خام) و `s` نسخهٔ متنی را ذخیره می‌کند؛ ۱۰ گزارش آخر هر تانل در `/etc/pfm/bench/<پورت>/` می‌ماند (فقط برای root خوانا، چون IP واقعی دارد)

> **درستی اندازه‌گیری:** تست از روی سرور PFM انجام می‌شود؛ یعنی مسیر «سرور PFM ← مقصد» و رفتار خود سرور را می‌سنجد. مسیر «کاربر ← سرور PFM» از همین‌جا قابل سنجش نیست و گزارش دربارهٔ آن ادعایی نمی‌کند.

<details>
<summary>نمونهٔ گزارش</summary>

<div dir="ltr" align="left">

```
  PFM BENCH TEST  PFM v2.0 · 2026-10-18 21:40 · full · 178s
  ────────────────────────────────────────────────────────────────────────────
  Tunnel  :8443 → 203.0.113.45:443   engine realm · profile balanced ·
          owner ali
  Server  ir-edge1 · Ubuntu 22.04.5 LTS · 2 vCPU / 3920 MB · kvm · kernel
          5.15.0-125-generic
  Path    eth0 (veth, MTU 1500) · src 198.51.100.20 · cc cubic · qdisc
          pfifo_fast
  ────────────────────────────────────────────────────────────────────────────
  OVERALL  ████████████████░░░░  83/100  Grade B
  covers the server → destination leg only
  Use: Gaming OK · Streaming/Download GREAT · Calls GREAT · Daily GREAT
  ────────────────────────────────────────────────────────────────────────────
  QUALITY (this server → destination)
   Latency      avg 61.3 ms (min 58.9 / p95 69.8 / max 143.2)      ● EXCELLENT
   Jitter       4.8 ms avg change between packets                  ● EXCELLENT
   Packet loss  0.33% (1/300 lost, longest gap 1) - isolated       ● GOOD
   Stability    ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▁▁▁▁▁▁▁▁▁▁▁▁▁           1 spike
   TCP connect  10/10 ok, handshake 60.5 ms, MSS 1448              
   MTU          path 1420 / interface 1500, TCP MSS 1380           ● GOOD
  ────────────────────────────────────────────────────────────────────────────
  THROUGHPUT
   Download     412.6 Mbit/s (4 streams)  ·  58.2 Mbit/s (1 stream) ● EXCELLENT
   Upload       377.9 Mbit/s (4 streams)  ·  retransmits 88       
   UDP 1 Mbit/s loss 0.12%  jitter 2.1 ms (200-byte packets)       
   Under load   +61 ms (worst ping: idle 70, down 131, up 97 ms)   ● FAIR
   Engine       realm 398.0 Mbit/s = 96% of direct 412.6 Mbit/s, its CPU 38% 
   Live now     down 3.1 / up 0.4 Mbit/s, 9 connections            
  ────────────────────────────────────────────────────────────────────────────
  FINDINGS
   ! Path MTU is 1420 but eth0 uses 1500: oversize packets get fragmented
     or need an extra round trip.
   ! One connection reaches only 58.2 Mbit/s while 4 together reach 412.6
     Mbit/s: single downloads are held back by loss or too-small TCP
     windows.
   i 1 of 300 probes got no answer (0.33%). That is too few to call it a
     pattern - a rate-limited ping or a single drop looks the same. The
     Full test (60 s) settles it.
   i Latency rises by +61 ms under load - acceptable.
   ✓ The realm engine adds almost nothing (96% of direct speed).
   ✓ UDP stream is clean (loss 0.12%, jitter 2.1 ms).
  ────────────────────────────────────────────────────────────────────────────
  NEXT STEPS (Optimization Assistant: PFM → 10)
   1) MTU auto-tune              match the interface MTU to the 1420-byte path
   2) Size TCP buffers           bigger TCP windows for the latency of this path
   3) Enable BBR + fq            BBR fills the pipe with a single connection
  After applying, run this test again - the report shows what changed.

  PFM BENCH TEST - details  :8443 → 203.0.113.45:443
  ────────────────────────────────────────────────────────────────────────────
  ROUTE (MTR from this server, 10 probes per hop)
   hop  host                                loss%   avg ms     best    worst   stdev
   1    gw.ir-dc.example                      0.0      0.6      0.4      1.1     0.2
   2    core1.ir-dc.example                   0.0      1.3      1.1      2.9     0.5
   3    ae3-12.tehran.example.net             0.0      9.6      8.9     14.2     1.4
   4    ffm-b4.example.net                    0.0     57.7     56.9     69.0     3.2
   5    203.0.113.45                          0.0     61.0     58.9     72.4     3.6
   Loss on middle hops only (not at the last hop) is ICMP rate-limiting.
  ────────────────────────────────────────────────────────────────────────────
  RAW NUMBERS
   ICMP   sent 300 recv 299 · min 58.9 avg 61.3 p50 - p95 69.8 max 143.2 ms
          · stdev - · loss events 0
   TCP    10/10 ok · min - avg 61.9 max - ms · kernel: mss 1448 pmtu - rtt
          60.5 ms cwnd - cc -
   MTU    interface 1500 · path 1420 · router frag-needed message: no ·
          tunnel overhead 0 B
   Route  dev eth0 (veth) via - · tunnel remote - local -
   iperf3 down1 58.2 · down4 412.6 (retr 212) · up4 377.9 (retr 88) Mbit/s
   Host   CPU during download: all -% · busiest 63% (cpu1) · softirq -% ·
          TCP retrans -%
   Drops  NIC 0 · backlog 0 · budget squeeze 0
   Engine realm 398 Mbit/s · direct (best run) 412.6 Mbit/s · process CPU
          38% · busiest core 41%
   Host   load 0.4 on 2 CPU · conntrack 2210/262144 (0%) · TCP rmem max 6 MB
```

</div>

</details>

### 🛠 دستیار بهینه‌سازی (Optimization Assistant)

مسیر: **منوی اصلی ← ۱۰) Optimization Assistant**. بالای منو وضعیت فعلی سرور دیده می‌شود (✓ خوب، ! قابل بهبود) و پیشنهادهایی که Bench Test داده است.

| گزینه | کار |
|---|---|
| ۱ بهینه‌سازی سریع | BBR + fq، سقف بافر TCP (۳۲ مگابایت)، محدودیت‌های conntrack / backlog / فایل (**فقط بالا می‌برد، هیچ‌وقت پایین نمی‌آورد**)، RPS و آفلودهای کارت شبکه. **هرچه اعمال می‌شود در جدول تأیید دیده می‌شود.** صف کارت شبکه فقط وقتی پیش‌فرض کرنل (pfifo_fast) باشد به fq عوض می‌شود؛ صفی که خودتان تنظیم کرده‌اید (htb، netem، cake، fq_codel …) دست نمی‌خورد. اگر سیستم (مثلاً کانتینر) اجازهٔ تغییر ندهد، پیام «چیزی تغییر نکرد» می‌دهد، نه «انجام شد» |
| ۲ تنظیم یک تانل (Tune) | پروفایل کاربرد: **گیمینگ / تماس**، **حداکثر پهنای باند**، **متعادل**، **کاربر زیاد** (جدول زیر) |
| ۳ MTU خودکار | MTU واقعی مسیر را اندازه می‌گیرد. روی اینترفیس تانلی (GRE، IPIP، WireGuard، VXLAN …) خود MTU را با احتساب سربار پایین می‌آورد؛ روی بقیه فقط MTU مسیر مقصد قفل می‌شود (ترافیک دیگر دست نمی‌خورد)؛ برای تانل iptables ‏MSS هم کلمپ می‌شود |
| ۴ بنچمارک DNS | Cloudflare، Google، Quad9، OpenDNS، AdGuard، CleanBrowsing و DNSهای فعلی سرور را (سرعت کش و سرعت واقعی) می‌سنجد. DNSی که برای نام عمومی آدرس خصوصی بدهد (فیلتر/هایجک) یا NXDOMAIN را جعل کند رد می‌شود. اگر تانل‌ها نام دامنه به‌عنوان مقصد دارند، DNSی که آن نام‌ها را resolve نکند رد می‌شود. دو DNS برتر اعمال می‌شود (systemd-resolved، NetworkManager یا resolv.conf ساده — فقط در حالت resolv.conf ساده اولین DNS قبلی به‌عنوان پشتیبان در انتهای لیست می‌ماند؛ اگر NetworkManager با dnsmasq/stub محلی کار می‌کند دست زده نمی‌شود و فقط راهنمایی می‌شود)، اگر بعد از تغییر نام‌ها resolve نشد خودکار برمی‌گردد و `pfm sync` بازنویسی توسط DHCP را ترمیم می‌کند |
| ۵ BBR / بافر / محدودیت‌ها | هرکدام جدا، با توضیح و تأیید |
| ۶ کارت شبکه | RPS برای کارت تک‌صفه (VPS)، GRO/GSO/TSO روشن و LRO خاموش، در صورت دراپ: بافر حلقه |
| ۷ Bench Test | همان تست کامل |
| ۸ وضعیت و برگشت | فهرست همهٔ تغییرها و برگرداندن همه‌چیز به مقدار اصلی |

**پروفایل هر تانل**

| پروفایل | مسیر به مقصد | Realm | HAProxy |
|---|---|---|---|
| گیمینگ / تماس | quickack، initcwnd 10، BBR | connect‏ ۳ث، keepalive ‏۱۰ث×۳، `Nice=-10` (فقط روی سرور واقعی، نه کانتینر) | keepalive دو طرف، connect ۳ث |
| حداکثر پهنای باند | initcwnd 24، initrwnd 48، BBR | `Nice=-5` | keepalive و تایم‌اوت یک‌ساعته |
| کاربر زیاد | BBR | تایم‌اوت کوتاه‌تر برای آزاد کردن اتصال‌های بیکار | maxconn 20000، تایم‌اوت ۱۲۰ث |
| متعادل | پیش‌فرض | پیش‌فرض | پیش‌فرض |

- روی موتور **iptables** (NAT کرنل) تنظیم اختصاصی هر تانل وجود ندارد جز MSS؛ انتخاب پروفایل برای آن توضیح می‌دهد و چیزی ذخیره نمی‌کند. برای کنترل پینگ/پهنای باند هر تانل از Realm یا HAProxy استفاده کنید. روی تانل بلاک‌شده پروفایل فقط ذخیره می‌شود (موتور روشن نمی‌شود).
- **BBR** فقط روی اتصال‌هایی اثر دارد که خود سرور تمامشان می‌کند (Realm / HAProxy)؛ ترافیکِ NAT‌شده با iptables فقط عبور می‌کند.
- اگر Realm/HAProxy پروفایلی را قبول نکند، تغییر **خودکار برگردانده می‌شود** و تانل هرگز خاموش نمی‌ماند.

**ایمنی:** هر تغییر قبل از اعمال با دلیلش نشان داده می‌شود، مقدار اصلی ذخیره می‌شود، بعد از ریبوت دوباره اعمال می‌شود (`pfm restore`)، اگر چیزی (مثلاً `sysctl -p`) آن را بهم بزند `pfm sync` درستش می‌کند و از «وضعیت و برگشت» همه‌چیز برمی‌گردد. خط فرمان: `pfm optimize [quick|scan|status|revert|dns|bbr|nic|mtu <port>|profile <port> gaming|bandwidth|balanced|multiuser]`.

### 🔁 سوییچ بین نسخه‌ها

مسیر: **منوی اصلی ← ۱۱) Versions & Update**.

- فهرست نسخه‌های منتشرشده در گیتهاب (با تاریخ، نسخهٔ نصب‌شده علامت دارد)؛ شمارهٔ هر نسخه را بزنید تا به آن برگردید، `i2` توضیحات نسخه را نشان می‌دهد، `u` آخرین نسخه را نصب می‌کند، `r` به نسخهٔ قبل از آخرین تغییر برمی‌گردد
- قبل از هر تغییر، برنامهٔ فعلی و **فهرست تانل‌ها** در `/etc/pfm/backups` ذخیره می‌شود (۶ مورد آخر)؛ پس حتی اگر گیتهاب در دسترس نباشد، نسخه‌های ذخیره‌شده در همان منو دیده می‌شوند و قابل نصب‌اند
- نصب با خود نصب‌کنندهٔ همان نسخه انجام می‌شود (قوانین، سرویس‌ها و کرون همان نسخه) و بلافاصله **همهٔ تانل‌ها بررسی می‌شوند**؛ اگر چیزی خراب بود پیشنهاد برگشت با یک کلید داده می‌شود
- برگشت به نسخه‌ای قدیمی‌تر از ۲.۰ که دستیار بهینه‌سازی را نمی‌شناسد: می‌پرسد تنظیمات دستیار (کرنل، کارت شبکه، DNS، پروفایل‌ها) به حالت اول برگردد یا نه
- نسخه‌های قبل از ۲.۰ دستور `switch` و `rollback` ندارند؛ بعد از برگشت به آن‌ها همین برنامه دستور دقیق بازگشت را چاپ می‌کند: `bash /etc/pfm/backups/pfm-v2.0-….sh install` (بدون اینترنت) یا همان دستور نصب سریع
- فقط فایل کامل و سالم نصب می‌شود (سینتکس و هدر نسخه بررسی می‌شود؛ صفحهٔ خطا یا فایل ناقص رد می‌شود) و جایگزینی اتمیک است
- خط فرمان: `pfm versions` · `pfm switch v1.9` · `pfm update` · `pfm rollback`

**سرور بدون دسترسی مستقیم به گیتهاب؟** در `/etc/pfm/pfm.conf` (با آپدیت پاک نمی‌شود) آینه یا پروکسی تنظیم کنید:

<div dir="ltr" align="left">

```bash
PFM_REPO_RAW="https://mirror.example/parham381/PFM/main"       # محل دریافت pfm.sh هر نسخه
PFM_CURL_OPTS="--proxy socks5h://127.0.0.1:1080"
PFM_REALM_URL="https://mirror.example/realm/latest/download"   # محل دریافت باینری realm
#PFM_API="https://mirror.example/repos/parham381/PFM"          # آینهٔ سازگار با API گیتهاب (فهرست نسخه‌ها و توضیحات)
```

</div>

`pfm switch <نسخه>` فقط با آینهٔ raw هم کار می‌کند؛ ولی «فهرست» نسخه‌ها به API گیتهاب (یا `PFM_API`) نیاز دارد، وگرنه فقط نسخه‌های ذخیره‌شده روی سرور نشان داده می‌شوند.

### 🤖 نصب ربات تلگرام

<div dir="ltr" align="left">

```bash
bash <(curl -s https://raw.githubusercontent.com/parham381/PFM/main/pfm-bot-setup.sh)
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

#### تست محلی سالم است ولی از بیرون کار نمی‌کند؟

`nc 127.0.0.1 <port>` و بقیهٔ تست‌های محلی از `PREROUTING` عبور نمی‌کنند، پس حتی وقتی ابزار دیگری ترافیک بیرونی را می‌دزدد سالم به نظر می‌رسند. `pfm doctor <port>` حالا این حالت را مستقیم نشان می‌دهد:

- قانون NAT بیگانه روی همان پورت (iptables، ip6tables و nftables؛ شامل قوانین زنجیره‌های Docker و بازه‌ها و چند‌پورتی) همراه با تعداد بسته و دستور حذف. PFM هیچ‌وقت قانون ابزار دیگر را خودکار پاک نمی‌کند — قبل از حذف حتماً بکاپ بگیرید: `iptables-save > /root/iptables.bak`
- شمارنده بسته‌های رسیده در برابر بسته‌های تحویل‌شده به تانل — بعد از وصل شدن یک کلاینت واقعی دوباره `pfm doctor <port>` را بزنید

برای بررسی دستی بدون PFM:

<div dir="ltr" align="left">

```bash
iptables-save -t nat | grep -- '--dport <port>'      # چه کسی این پورت را DNAT می‌کند؟
tcpdump -ni any "tcp port <port>" -c 10             # بسته می‌رسد؟ از کدام اینترفیس برمی‌گردد؟
```

</div>

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
- **Foreign NAT detection** — if another tool (a different tunnel manager, Docker, firewalld, a forgotten test rule) DNATs/REDIRECTs the same port and takes the traffic before the tunnel, `pfm doctor` shows the rule, its packet count and the command that removes it; adding a tunnel on such a port warns first
- **Arrived / delivered counters** — per tunnel PFM counts the packets that reach the server and the ones that actually reach the tunnel; when packets arrive but do not get there (foreign rule, rp_filter, firewall) `pfm doctor` says so and `pfm sync` writes it to the log
- **MTU Management** — Persistent MTU settings per interface
- **IPv4 & IPv6** — Full dual-stack support
- **Bench Test** — per tunnel: latency, jitter, loss, stability, MTU, route (MTR), download / upload speed, bufferbloat and what the engine costs; a screenshot-friendly report with a score and next steps
- **Optimization Assistant** — BBR, buffers and server limits, network card, DNS benchmark, automatic best MTU, per-tunnel profiles (gaming / max bandwidth / balanced / many users), everything revertible
- **`PFM` shortcut** — type `PFM` anywhere on the server to open the panel
- **Version switching** — list the GitHub releases and go back to any of them; the replaced program is always saved and every tunnel is checked after a change
- **Menu-Driven** — Easy interactive CLI interface

## 🚀 Quick Install

```bash
bash <(curl -s https://raw.githubusercontent.com/parham381/PFM/main/pfm.sh) install
```

Upgrading from an earlier version: run the same command once. From then on just type `PFM`.

## 📦 Manual Install

```bash
curl -o /usr/local/bin/pfm https://raw.githubusercontent.com/parham381/PFM/main/pfm.sh
chmod +x /usr/local/bin/pfm
pfm install
```

## ⚡ The `PFM` command

After installing, type this anywhere on the server:

```bash
PFM
```

The panel opens (capital letters; lower-case `pfm` works too). It is different from `PFM install`: `PFM` only opens the panel, `PFM install` installs / updates. As a normal user it asks `sudo` for you. Tab completion is installed (`PFM ben<Tab>`), and `PFM help` lists every command.

## 📊 Bench Test

Find out how good a tunnel really is and where it loses. **Manage Tunnels → pick a tunnel → 10) Bench Test**, or `pfm bench <port> [quick|full]`.

| What is measured | Quick (~40 s) | Full (~3 min) |
|---|:---:|:---:|
| Latency, jitter and packet loss (ICMP) | 8 s | 60 s + stability graph and spike count |
| TCP handshake to the destination port (MSS and RTT as the kernel sees them) | ✔ | ✔ |
| Real path MTU with DF-bit probes, MTU black-hole detection | ✔ | ✔ |
| Route (MTR) and every hop | ✔ | ✔ |
| Traffic flowing through the tunnel right now | ✔ | ✔ |
| Download / upload speed (4 streams and 1 stream), game-like UDP stream, latency under load (bufferbloat), what the forwarding engine adds, CPU and NIC drops | — | ✔ with helper |

**The speed test needs a helper on the destination server** - a tunnel can only be speed-tested together with its other end. The menu shows the exact command (option 4 of the Bench menu):

```bash
bash <(curl -sL https://raw.githubusercontent.com/parham381/PFM/main/pfm.sh) bench-server 5201 <IP of the PFM server>
```

It installs iperf3, accepts only that IP and stops by itself after 15 minutes (adjustable, 1-120), removing its temporary firewall rules. **The restriction is checked in the firewall before the helper starts**; if it cannot be installed the helper does not start (open to everybody only if you run it without an IP). A port that another service uses (TCP or UDP, e.g. WireGuard) is refused, and rules left by a helper that was killed with `kill -9` are swept at the next start (but kept while its orphaned iperf3 still serves the port, so the port is never opened to everybody); a timer process of its own also removes them at the deadline. Without a helper the full test only skips the speed part; this server's own internet speed (downloads up to 100 MB from Cloudflare) is measured only with `--inet` or a `y` in the menu. If users are connected through the tunnel right now, the test warns and asks before the speed test (it moves about 4 GB at 1 Gbit/s; the default answer is no). `--peer` / `--inet` mean the full test.

**The report** is designed to be screenshotted (under 90 columns):

- score 0-100 and grade A-F - a serious problem (packet loss, jitter, bufferbloat, MTU black hole) caps the score whatever else is fine. **How many probes were lost matters, not just the percentage**: one lost ping of 40 (2.5%) is no pattern and does not break the grade; it takes 3 lost probes. If no ping gets through while the line is busy (or 30% or more are lost), that is "bad", not "flat latency"; TCP connections to the service port that fail although ping works are a finding of their own and cap the grade; if nothing answers at all (e.g. a UDP-only service) the report says "not measurable", not 0/100. A blocked or stopped tunnel is reported first
- how good the tunnel is for gaming, streaming/downloads, calls and daily use (in a quick test "streaming/downloads" is **n/a** - no speed was measured). The report states that it covers the *server → destination* leg only
- the numbers, a stability graph and plain-language **findings**
- **next steps** wired to the Optimization Assistant: press the number of a suggestion to apply it right there, then `r` to test again - the new report shows the difference to the previous test and what the assistant changed in between
- `m` hides IP addresses plus the destination / server host names and the owner (to send the picture to a network expert), `d` shows the details page (MTR table, raw numbers), `s` saves a plain-text copy; the last 10 reports of each tunnel stay in `/etc/pfm/bench/<port>/` (readable by root only - they contain the real addresses)

> **Honest measurement:** the test runs on the PFM server, so it measures *PFM server → destination* and the server itself. The *user → PFM server* leg cannot be measured from here and the report does not pretend to.

<details>
<summary>Sample report</summary>

```
  PFM BENCH TEST  PFM v2.0 · 2026-10-18 21:40 · full · 178s
  ────────────────────────────────────────────────────────────────────────────
  Tunnel  :8443 → 203.0.113.45:443   engine realm · profile balanced ·
          owner ali
  Server  ir-edge1 · Ubuntu 22.04.5 LTS · 2 vCPU / 3920 MB · kvm · kernel
          5.15.0-125-generic
  Path    eth0 (veth, MTU 1500) · src 198.51.100.20 · cc cubic · qdisc
          pfifo_fast
  ────────────────────────────────────────────────────────────────────────────
  OVERALL  ████████████████░░░░  83/100  Grade B
  covers the server → destination leg only
  Use: Gaming OK · Streaming/Download GREAT · Calls GREAT · Daily GREAT
  ────────────────────────────────────────────────────────────────────────────
  QUALITY (this server → destination)
   Latency      avg 61.3 ms (min 58.9 / p95 69.8 / max 143.2)      ● EXCELLENT
   Jitter       4.8 ms avg change between packets                  ● EXCELLENT
   Packet loss  0.33% (1/300 lost, longest gap 1) - isolated       ● GOOD
   Stability    ▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁▁█▁▁▁▁▁▁▁▁▁▁▁▁▁           1 spike
   TCP connect  10/10 ok, handshake 60.5 ms, MSS 1448              
   MTU          path 1420 / interface 1500, TCP MSS 1380           ● GOOD
  ────────────────────────────────────────────────────────────────────────────
  THROUGHPUT
   Download     412.6 Mbit/s (4 streams)  ·  58.2 Mbit/s (1 stream) ● EXCELLENT
   Upload       377.9 Mbit/s (4 streams)  ·  retransmits 88       
   UDP 1 Mbit/s loss 0.12%  jitter 2.1 ms (200-byte packets)       
   Under load   +61 ms (worst ping: idle 70, down 131, up 97 ms)   ● FAIR
   Engine       realm 398.0 Mbit/s = 96% of direct 412.6 Mbit/s, its CPU 38% 
   Live now     down 3.1 / up 0.4 Mbit/s, 9 connections            
  ────────────────────────────────────────────────────────────────────────────
  FINDINGS
   ! Path MTU is 1420 but eth0 uses 1500: oversize packets get fragmented
     or need an extra round trip.
   ! One connection reaches only 58.2 Mbit/s while 4 together reach 412.6
     Mbit/s: single downloads are held back by loss or too-small TCP
     windows.
   i 1 of 300 probes got no answer (0.33%). That is too few to call it a
     pattern - a rate-limited ping or a single drop looks the same. The
     Full test (60 s) settles it.
   i Latency rises by +61 ms under load - acceptable.
   ✓ The realm engine adds almost nothing (96% of direct speed).
   ✓ UDP stream is clean (loss 0.12%, jitter 2.1 ms).
  ────────────────────────────────────────────────────────────────────────────
  NEXT STEPS (Optimization Assistant: PFM → 10)
   1) MTU auto-tune              match the interface MTU to the 1420-byte path
   2) Size TCP buffers           bigger TCP windows for the latency of this path
   3) Enable BBR + fq            BBR fills the pipe with a single connection
  After applying, run this test again - the report shows what changed.

  PFM BENCH TEST - details  :8443 → 203.0.113.45:443
  ────────────────────────────────────────────────────────────────────────────
  ROUTE (MTR from this server, 10 probes per hop)
   hop  host                                loss%   avg ms     best    worst   stdev
   1    gw.ir-dc.example                      0.0      0.6      0.4      1.1     0.2
   2    core1.ir-dc.example                   0.0      1.3      1.1      2.9     0.5
   3    ae3-12.tehran.example.net             0.0      9.6      8.9     14.2     1.4
   4    ffm-b4.example.net                    0.0     57.7     56.9     69.0     3.2
   5    203.0.113.45                          0.0     61.0     58.9     72.4     3.6
   Loss on middle hops only (not at the last hop) is ICMP rate-limiting.
  ────────────────────────────────────────────────────────────────────────────
  RAW NUMBERS
   ICMP   sent 300 recv 299 · min 58.9 avg 61.3 p50 - p95 69.8 max 143.2 ms
          · stdev - · loss events 0
   TCP    10/10 ok · min - avg 61.9 max - ms · kernel: mss 1448 pmtu - rtt
          60.5 ms cwnd - cc -
   MTU    interface 1500 · path 1420 · router frag-needed message: no ·
          tunnel overhead 0 B
   Route  dev eth0 (veth) via - · tunnel remote - local -
   iperf3 down1 58.2 · down4 412.6 (retr 212) · up4 377.9 (retr 88) Mbit/s
   Host   CPU during download: all -% · busiest 63% (cpu1) · softirq -% ·
          TCP retrans -%
   Drops  NIC 0 · backlog 0 · budget squeeze 0
   Engine realm 398 Mbit/s · direct (best run) 412.6 Mbit/s · process CPU
          38% · busiest core 41%
   Host   load 0.4 on 2 CPU · conntrack 2210/262144 (0%) · TCP rmem max 6 MB
```

</details>

## 🛠 Optimization Assistant

**Main menu → 10) Optimization Assistant.** The top of the menu shows a scan of the server (✓ fine, ! can be improved) and what your latest Bench Tests recommended.

| Option | What it does |
|---|---|
| 1 Quick Optimize | BBR + fq, TCP buffer limit (32 MB), conntrack / backlog / file limits (**only ever raised, never lowered**), RPS and offloads of the network card. **Everything that is applied is in the table you confirm.** The card's queue becomes fq only when it is the kernel default (pfifo_fast); a queue you configured (htb, netem, cake, fq_codel ...) is never touched. If the system refuses the writes (containers) it says "nothing was changed", not "done" |
| 2 Tune a tunnel | pick the use of a tunnel: **Gaming / calls**, **Max bandwidth**, **Balanced**, **Many users** (table below) |
| 3 MTU auto-tune | measures the real path MTU. On tunnel interfaces (GRE, IPIP, WireGuard, VXLAN …) it lowers the interface MTU, underlay overhead included; elsewhere it pins the MTU on the route to the destination only (other traffic is untouched); kernel-NAT tunnels also get a TCP MSS clamp |
| 4 DNS benchmark | measures Cloudflare, Google, Quad9, OpenDNS, AdGuard, CleanBrowsing and the server's current resolvers (cached and uncached speed). A resolver that answers a public name with a private address (filtering / hijack) or invents answers for missing names is rejected. If your tunnels use host names as destinations, a resolver that cannot resolve them is rejected too. The best two are applied (systemd-resolved, NetworkManager or plain resolv.conf - only in the plain resolv.conf mode your first current resolver stays behind them as a fallback; NetworkManager with a local dnsmasq / stub is left alone and only explained); if names stop resolving the change rolls back by itself, and `pfm sync` repairs a DHCP client rewriting resolv.conf |
| 5 BBR / buffers / limits | each one separately, with an explanation and a confirmation |
| 6 Network card | RPS for single-queue cards (typical VPS), GRO/GSO/TSO on and LRO off, ring buffers when packets are dropped |
| 7 Bench Test | the test above |
| 8 Status & revert | every change listed; put everything back to the original values |

**Per-tunnel profiles**

| Profile | Route to the destination | Realm | HAProxy |
|---|---|---|---|
| Gaming / calls | quick ACKs, initcwnd 10, BBR | 3 s connect timeout, keep-alive 10 s × 3, `Nice=-10` (real hosts only, not containers) | keep-alive both sides, 3 s connect timeout |
| Max bandwidth | initcwnd 24, initrwnd 48, BBR | `Nice=-5` | keep-alive and 1 h timeouts |
| Many users | BBR | shorter timeouts so idle connections are freed | maxconn 20000, 120 s timeouts |
| Balanced | defaults | defaults | defaults |

- The **iptables** engine (kernel NAT) has no per-tunnel knobs except the TCP MSS; choosing a profile for it explains this and stores nothing. For per-tunnel latency / bandwidth control use Realm or HAProxy. On a blocked tunnel a profile is only stored (its engine is not started).
- **BBR** only acts on connections the server itself terminates (Realm / HAProxy); connections NAT-ed by iptables are just passed along.
- If Realm / HAProxy rejects a profile the change is **rolled back automatically** - a tunnel is never left dead.

**Safety:** every change is shown with its reason before it is applied, the original value is stored, it is re-applied after reboot (`pfm restore`), `pfm sync` repairs it if something (e.g. `sysctl -p`) undoes it, and *Status & revert* restores everything. CLI: `pfm optimize [quick|scan|status|revert|dns|bbr|nic|mtu <port>|profile <port> gaming|bandwidth|balanced|multiuser]`.

## 🔁 Versions & Update

**Main menu → 11) Versions & Update.**

- Lists the releases published on GitHub (installed one marked). Type a number to switch to it, `i2` shows the notes of a release, `u` installs the newest, `r` rolls back to what you had before the last change
- Before any change the running program and the **tunnel list** are saved in `/etc/pfm/backups` (last 6). Even without GitHub those saved versions show up in the same menu and can be installed
- The version is installed by *its own* installer (its rules, services and cron), then **every tunnel is checked**; if something is broken you are offered the way back with one key
- Going below 2.0, which does not know the Optimization Assistant, asks whether the assistant's changes (kernel, NIC, DNS, profiles) should be put back to the original values (a non-interactive `-y` run keeps them)
- Releases before 2.0 have no `switch` / `rollback` command; after switching to one, the exact way back is printed: `bash /etc/pfm/backups/pfm-v2.0-….sh install` (works offline) or the Quick Install command
- Only a complete, valid script is installed (syntax and version header are checked; an error page or truncated download is refused) and the file is replaced atomically
- CLI: `pfm versions` · `pfm switch v1.9` · `pfm update` · `pfm rollback`

**No direct access to GitHub?** Set a mirror or proxy in `/etc/pfm/pfm.conf` (updates never overwrite it):

```bash
PFM_REPO_RAW="https://mirror.example/parham381/PFM/main"       # where pfm.sh of every tag is fetched from
PFM_CURL_OPTS="--proxy socks5h://127.0.0.1:1080"
PFM_REALM_URL="https://mirror.example/realm/latest/download"   # where the realm binary is fetched from
#PFM_API="https://mirror.example/repos/parham381/PFM"          # GitHub-API compatible mirror (release list + notes)
```

`pfm switch <tag>` works with only the raw mirror; the release *list* needs the GitHub API (or `PFM_API`), otherwise the saved versions are listed.

## 🤖 Telegram Bot Setup

The bot allows you to manage all your PFM servers remotely from Telegram.

```bash
bash <(curl -s https://raw.githubusercontent.com/parham381/PFM/main/pfm-bot-setup.sh)
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
         PFM - Port Forward Manager v2.0
              https://t.me/AbrAfagh
  ──────────────────────────────────────────

  1)  Add Tunnel
  2)  Manage Tunnels
  3)  View Traffic
  4)  Live Monitor
  5)  Users
  6)  MTU Settings
  7)  Delete All Tunnels
  8)  Uninstall Completely
  9)  Diagnose (why is a tunnel not working?)
  10) Optimization Assistant (BBR, MTU, DNS, network card, gaming / bandwidth profiles)
  11) Versions & Update (switch to an earlier version if the newest has a problem)
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
/usr/local/bin/PFM          # Shortcut (symlink to pfm)
/usr/local/bin/pfm-cmd      # Bot command helper
/etc/pfm/
├── pfm.conf                # Your settings: GitHub mirror / proxy (never overwritten)
├── users/                  # User configs
├── ports/                  # Port configs
├── usage/                  # Traffic data (bytes)
├── mtu/                    # MTU settings
├── health/                 # Counter snapshots of the last `pfm sync`
├── realm/                  # Realm TOML configs
├── bench/<port>/           # Bench Test reports and history
├── tune/                   # What the Optimization Assistant changed (+ the original values)
└── backups/                # Earlier versions of pfm + tunnel list copies (for switching back)
```

## 🔧 Commands

```bash
PFM                  # Open the panel (anywhere on the server; also: pfm)
PFM install          # Install/Update PFM
PFM help             # All commands
pfm restore          # Restore rules after reboot
pfm sync             # Sync traffic counters (+ health check / self-heal)
pfm doctor [port]    # Diagnose tunnels that do not forward
pfm bench <port> [quick|full] [--peer PORT] [--inet] [--yes] [--mask]   # Bench Test
pfm bench-server [port] [client-ip] [minutes 1-120]   # Helper for the speed test (run on the DESTINATION)
pfm optimize [quick|scan|status|revert|dns|bbr|nic|mtu <port>|profile <port> <name>]
pfm versions         # Releases on GitHub + saved versions
pfm switch <tag>     # Install any release (v1.9, v2.0 ...)
pfm update           # Install the newest release
pfm rollback         # Go back to the version used before the last switch
pfm json             # JSON output (for bot)
pfm monitor          # Live traffic monitor
pfm uninstall        # Remove PFM (and everything the assistant changed)
```

## 🩺 Troubleshooting

Tunnel works but is slow or unstable? Run the **Bench Test** (`pfm bench <port>`) - it names the bottleneck and the assistant action that addresses it.

Tunnel added but no traffic? Run `pfm doctor` (or `pfm doctor <port>`). Typical causes it detects:

- The listen port is already used by another process (Realm keeps running without owning the port)
- One HAProxy tunnel with an unresolvable destination used to invalidate the whole config, so later tunnels silently never started
- `FORWARD`/`INPUT` default policy is `DROP` (ufw, Docker) — PFM now installs its own per-tunnel `ACCEPT` rules
- iptables rules flushed by something else, or `net.ipv4.ip_forward` reset to 0
- The destination is not reachable from this server (wrong IP/port, or the destination blocks this server)
- **Another tool also handles the port** — a DNAT/REDIRECT rule from something else (other tunnel managers, Docker, firewalld, a leftover test rule) runs in `PREROUTING` *before* the packet reaches realm/haproxy or PFM's own rule, so the tunnel looks perfect from the inside (listening, rules in place, local `nc 127.0.0.1` works) while nothing from outside ever arrives

### Works locally but not from outside?

Local tests never pass through `PREROUTING`, so they cannot see this. `pfm doctor <port>` checks it directly:

- It lists every non-PFM NAT rule that matches the tunnel port (iptables, ip6tables and native nftables; Docker chains, port ranges and multiport lists included) with its packet counter and the exact command that removes it. PFM never deletes another tool's rules on its own — take a backup first: `iptables-save > /root/iptables.bak`
- It compares the packets that *arrived* on the port with the ones *handed to the tunnel*. Run it again after a real client has connected. `pfm sync` (cron) keeps the previous counters and writes a `WARN` line to `/var/log/pfm.log` when a tunnel starts or stops being diverted

By hand, without PFM:

```bash
iptables-save -t nat | grep -- '--dport <port>'      # who else DNATs this port?
tcpdump -ni any "tcp port <port>" -c 10             # do packets arrive, and where do they leave again?
```

## 📋 Requirements

- Ubuntu 18+ / Debian 10+
- Root access
- `curl` or `wget`
- `sshpass` (for bot password auth)
- Installed on demand when a feature needs them: `iperf3` (speed test), `mtr` (route), `dig` (DNS benchmark), `ping`; `python3` or `jq` are optional (release notes in the version list)
- Kernel 4.9+ for BBR; a container may lock some kernel settings - the assistant says so and skips them

## 🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

## 📄 License

[MIT](LICENSE)

## 📬 Contact

- Telegram Channel: [@AbrAfagh](https://t.me/AbrAfagh)
