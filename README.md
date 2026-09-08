<div align="center">

<img src="static/img/logo.png" width="120" alt="TiTaN logo">

# ⚡ TiTaN Panel

### پنل مدیریت پروکسی چندپروتکله — سبک، سریع و زیبا
**A fast, single-service multi-protocol proxy panel (VLESS · VMess · Trojan · Shadowsocks)**

[English](#english) · [فارسی](#فارسی)

</div>

---

# فارسی

## TiTaN چیست؟

TiTaN یک پنل تک‌سرویسه برای ساخت و مدیریت **کانفیگ‌های پروکسی** است. با یک دیپلوی ساده روی Railway یا Render، یک سرور کامل پروکسی با پنل مدیریتی می‌گیرید. برخلاف پنل‌های مشابه، TiTaN:

- از **۴ پروتکل** پشتیبانی می‌کند: VLESS، VMess، Trojan، Shadowsocks
- از **۳ روش انتقال** پشتیبانی می‌کند: WebSocket، XHTTP، gRPC
- از **SQLite** استفاده می‌کند (سریع‌تر و امن‌تر از فایل JSON)
- رابط کاربری مدرن، دوزبانه (فارسی/انگلیسی) و ریسپانسیو دارد

## ویژگی‌ها

| | |
|---|---|
| 🪄 **۴ پروتکل + ۳ انتقال** | VLESS / VMess / Trojan / Shadowsocks روی WS / XHTTP / gRPC |
| 🗄 **SQLite** | بدون نیاز به دیتابیس خارجی، با WAL و نوشتن اتمیک |
| 👤 **ورود بدون ثبت‌نام** | اولین ورود با نام کاربری پیش‌فرض `TiTaN` و بدون رمز — سپس از تنظیمات رمز بسازید |
| 📊 **محدودیت حجم و انقضا** | حجم (GB) و تاریخ انقضا با قطع خودکار اعمال می‌شوند. سقف دستگاه و IP مجاز فعلاً فقط **ذخیره** می‌شوند (اعمالشان به پروتکل شناسایی IP واقعی نیاز دارد — ببینید «محدودیت‌های شناخته‌شده») |
| 🛡 **مسیریابی و فیلتر** | مسدودسازی تبلیغات، سایت‌های ایرانی و IPهای خصوصی |
| 📈 **داشبورد زنده** | نمودار ترافیک ۲۴ ساعته، CPU/RAM/دیسک، موقعیت سرور |
| 🔗 **لینک اشتراک + QR** | خروجی استاندارد v2rayNG با header مصرف و انقضا |
| 🛑 **ابطال آنی لینک** | چرخش UUID با یک کلیک |
| 📱 **صفحه وضعیت عمومی** | `/status/<uid>` برای رصد مصرف بدون ورود |
| 🌗 **دارک/لایت + دو زبانه** | فارسی و انگلیسی با فونت محلی وزیرمتن |
| 📜 **گزارش رویدادها** | لاگ ورود، ساخت/حذف کاربر، تغییرات و… |
| 💾 **پشتیبان‌گیری خودکار** | بکاپ دوره‌ای SQLite + دانلود/بازیابی |
| 🔄 **راه‌اندازی مجدد درون‌پنلی** | ری‌استارت پنل با یک کلیک |
| 🌍 **DoH داخلی** | DNS-over-HTTPS پروکسی برای کلاینت‌ها |
| ⏱ **بیدارباش خودکار** | پینگ داخلی برای سرویس‌های ابری |

## نصب سریع

### 🚂 Railway (توصیه‌شده)
1. ریپازیتوری را Fork یا push کنید.
2. در [railway.app](https://railway.app) → **New Project → Deploy from GitHub repo**.
3. Railway فایل `railway.json` را می‌شناسد و همه‌چیز (Python + nginx + Xray) را خودش بالا می‌آورد.
4. به آدرس سرویس + `/login` بروید و با نام کاربری `TiTaN` (بدون رمز) وارد شوید.

### 🌐 Render
1. در [render.com](https://render.com) → **New → Web Service** → ریپازیتوری را وصل کنید.
2. `render.yaml` با runtime داکر شناسایی می‌شود.
3. بعد از دیپلوی به `/login` بروید و با `TiTaN` (بدون رمز) وارد شوید.

### 💻 اجرای محلی
```bash
git clone <your-repo-url> titan
cd titan
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
# → http://localhost:8000/login  (نام کاربری: TiTaN — بدون رمز)
```
> بدون Xray، پنل در حالت mock کار می‌کند (همه امکانات مدیریتی فعال است؛ فقط ترافیک واقعی عبور نمی‌کند).

## ورود اولیه

1. `<your-domain>/login` → ورود با نام کاربری پیش‌فرض `TiTaN` (رمز لازم نیست)
2. ⚠️ از **تنظیمات → امنیت** یک رمز اختصاصی تعیین کنید (در حالت پیش‌فرض، «رمز عبور فعلی» را خالی بگذارید)
3. ورود و ساخت کاربر در بخش **کاربران**
4. در **تنظیمات → پیشرفته** پروتکل انتقال پیش‌فرض و Fingerprint را تنظیم کنید
5. لینک یا QR را به کلاینت (v2rayNG، Nekobox، Streisand و…) بدهید

## معماری

```
کلاینت (v2rayNG)
      │
      ▼
Cloudflare / پلتفرم ابری (TLS)
      │
      ▼
Nginx (PORT) ──┬─ /vl-ws  ──► Xray VLESS WS  (10001)
               ├─ /vm-ws  ──► Xray VMess WS  (10002)
               ├─ /tr-ws  ──► Xray Trojan WS (10003)
               ├─ /xhttp  ──► Xray VLESS/VMess XHTTP (10004)
               ├─ /titan  ──► Xray VLESS/VMess gRPC (10005)
               └─ /      ──► TiTaN panel (FastAPI, 10000) + DoH
```

- **پنل (FastAPI)** مدیریت کاربران، لینک‌ها و آمار را انجام می‌دهد.
- فرانت‌های External Proxy (مثل `externalProxy` در 3x-ui): چند آدرس میانی برای یک inbound — لینک و ورودی اشتراک جدا برای هر جلوه، با SNI/فینگرپرینت/ALPN و `force_tls` مخصوص خودشان
- **Xray-core** موتور پروکسی واقعی است؛ پنل بعد از هر تغییر، `config.json` آن را بازتولید و Xray را ری‌استارت می‌کند.
- آمار ترافیک هر ۵ ثانیه از API آمار Xray خوانده و در SQLite ذخیره می‌شود.

## متغیرهای محیطی

| متغیر | پیش‌فرض | توضیح |
|---|---|---|
| `PORT` | `8000` | پورت عمومی (توسط Railway/Render تزریق می‌شود) |
| `TITAN_RAW_ENTRY` | `auto` | مسیراب پورت خام (`1`/`0`); روی Railway با TCP Proxy لازم است — ببین `DEPLOY.md` گام ۴.۵ |
| `TITAN_RAW_ENTRY_PORT` | `10999` | پورت داخلی که TCP Proxy ریلوی باید به آن وصل شود |
| `TITAN_TCP_PROXY_HOST` / `TITAN_TCP_PROXY_PORT` | خالی | override دستی نشانی raw (Render/Fly/VPS یا متغیرهای خالی ریلوی) |
| `TITAN_REALITY_PRIV` | خالی | کلید خصوصی x25519 (base64url) برای پین کردن جفت‌کلید Reality — بدون آن، روی Railway بدون Volume هر redeploy همهٔ لینک‌ها را می‌کشد |
| `TITAN_DATA_DIR` | `data/` | محل دیتابیس و بکاپ |
| `PANEL_PORT` | `10000` | پورت داخلی پنل |
| `XRAY_BIN` | `/usr/local/bin/xray` | مسیر باینری Xray |

## API

| مسیر | متد | توضیح |
|---|---|---|
| `/api/login` / `/api/logout` / `/api/change-password` | POST | احراز هویت |
| `/api/me` | GET | وضعیت نشست و تنظیمات |
| `/api/settings` | GET/POST | تنظیمات عمومی و پیشرفته |
| `/api/reality/key` | POST | پین کردن جفت‌کلید Reality (کلید خصوصی فقط نوشته می‌شود، هرگز خوانده/لاگ نمی‌شود) |
| `/api/network/status` | GET | وضعیت TCP Proxy، مسیریاب پورت خام، self-test و هشدارها |
| `/api/network/selftest` | POST | اجرای دوبهٔ رفت‌وبرگشت روی پورت خام |
| `/api/users` | GET/POST | لیست/ساخت کاربر |
| `/api/users/<uid>` | GET/PATCH/DELETE | جزئیات/ویرایش/حذف |
| `/api/users/<uid>/toggle` | POST | فعال/غیرفعال |
| `/api/users/<uid>/regenerate` | POST | چرخش UUID |
| `/api/users/<uid>/reset` | POST | صفر کردن مصرف |
| `/api/users/<uid>/links` | GET | لینک‌ها |
| `/api/users/<uid>/qr` | GET | تصویر QR |
| `/sub/<uid>` | GET | اشتراک (عمومی) |
| `/api/status/<uid>` | GET | وضعیت عمومی |
| `/api/stats` | GET | آمار سیستم |
| `/api/nodes` | GET/POST | لیست/افزودن سرور |
| `/api/nodes/<id>` | PATCH/DELETE | ویرایش/حذف سرور |
| `/api/nodes/<id>/ping` | POST | بررسی اتصال سرور |
| `/api/reports?days=7` | GET | آمار و گزارش‌ها |
| `/api/admin-info` | GET | اطلاعات حساب ادمین |
| `/api/events` | GET/DELETE | گزارش رویدادها |
| `/api/backup` | GET | دانلود بکاپ |
| `/api/backup/restore` | POST | بازیابی بکاپ |
| `/api/restart` | POST | ری‌استارت پنل |
| `/dns-query` | GET/POST | DoH |

## ساختار پروژه

```
titan/
├── app/                 # بک‌اند FastAPI
│   ├── main.py          # روت‌ها و منطق API
│   ├── db.py            # لایه SQLite
│   ├── security.py      # هش رمز و نشست‌ها
│   ├── links.py         # ساخت لینک‌های اتصال
│   ├── xray.py          # تولید کانفیگ و آمار Xray
│   ├── tasks.py         # تسک‌های پس‌زمینه
│   ├── state.py         # وضعیت زنده
│   ├── colo_map.py      # نقشه مکان سرور
│   └── config.py        # تنظیمات
├── templates/           # صفحات HTML
├── static/              # CSS، JS، فونت، لوگو
├── scripts/             # ابزارهای توسعه و تست
├── Dockerfile
├── nginx.conf
├── entrypoint.sh
├── Procfile / railway.json / render.yaml
└── requirements.txt
```

## نکات امنیتی

- رمز قوی انتخاب کنید؛ بعد از ۳ تلاش ناموفق، پاسخِ اشتباه بعدی تأخیر تصاعدی می‌گیرد (سقف ۱۵ ثانیه) و بعد از ۳۰ تلاش، ۱۰ دقیقه قفل می‌شود.
- پنل از `X-Forwarded-For` فقط برای **نمایش** IP استفاده می‌کند؛ شمارندهٔ قفل روی آدرس واقعی سوکت است، پس با هدر جعلی دور زده نمی‌شود.
- داکیومنت Swagger به‌صورت پیش‌فرض بسته است. برای توسعه با `TITAN_DOCS=1` فعالش کنید.
- درخواست‌های تغییردهندهٔ حالت، `Origin` را می‌سنجند؛ اگر پنل را پشت یک دامنه/CDN دوم قرار می‌دهید، آن دامنه را در «تنظیمات → عمومی → دامنهٔ عمومی» ثبت کنید وگرنه مرورگر ۴۰۳ می‌گیرد.

## محدودیت‌های شناخته‌شده

بیایید صادق باشیم — این‌ها را README قول نمی‌دهد مگر با همین توضیح:

| مورد | وضعیت امروز |
|---|---|
| سقف حجم / تاریخ انقضا | ✅ اعمال می‌شود (کاربر غیرفعال و از کانفیگ Xray حذف می‌شود) |
| سقف دستگاه (`max_devices`) | ⚠️ ذخیره می‌شود، **اعمال نمی‌شود**. نیاز دارد Xray IP واقعی کلاینت را ببیند؛ روی Railway (TLS در لبه، بدون PROXY protocol) این IP وجود ندارد |
| لینک‌های TCP / Reality روی Railway | ✅ با TCP Proxy کار می‌کند (گام ۴.۵ `DEPLOY.md`): پنل یک پورت مشترک را با تفکیک بایت اول مسیردهی می‌کند. تا آن را روشن نکنی، این لینک‌ها از بیرون مرده‌اند |
| هیستریا۲ / WireGuard روی Railway | ❌ ساختنی نیست: TCP Proxy ریلوی UDP ندارد. این دو فقط روی VPS |
| فیلتر اپراتور روی دامنهٔ `up.railway.app` | ⚠️ لینک‌های WS/xHTTP از لبهٔ HTTPS ریلوی می‌آیند و SNI‌شان همان دامنه است؛ بعضی اپراتورها (گزارش ایرانسل) این را می‌شکنند. راه‌حل: TCP Proxy + Reality، یا دامنهٔ خودت پشت Cloudflare |
| IPهای مجاز (`allowed_ips`) | ⚠️ مثل بالا |
| سقف درخواست (`max_requests`) | ⚠️ مثل بالا |
| پنل خودکاربر | ❌ هنوز فقط ادمین هست؛ کاربر فقط صفحهٔ `/status/<uid>` را می‌بیند |
| حذف شدن نشست‌ها با هر دیپلوی | ⚠️ طبیعی است: `secret_key` در همان ولوم است؛ اگر Volume وصل نکنید **همه‌چیز** از جمله Reality key و لینک‌ها از بین می‌رود |

اگر `TITAN_TRUST_PROXY_HEADERS=0` را روی یک VPS با nginx+PROXY protocol تنظیم کنید، مسیر اعمال
محدودیت دستگاه باز می‌شود؛ فعلاً این فیلدها را در UI به‌عنوان «پیکربندی ذخیره‌شده» ببینید.
- در صورت نشت لینک اشتراک، از دکمه **تغییر UUID** استفاده کنید.
- از HTTPS (Cloudflare یا خود پلتفرم) استفاده کنید.
- بکاپ دوره‌ای را فعال نگه دارید.

---

# English

## What is TiTaN?

A single-service panel for creating and managing proxy configs. Deploy once on Railway or Render and get a full proxy server with an admin dashboard. It supports **4 protocols** (VLESS, VMess, Trojan, Shadowsocks), **3 transports** (WebSocket, XHTTP, gRPC), stores everything in **SQLite**, and ships a modern bilingual (FA/EN) responsive UI.

## Quick start

- **Railway:** Fork → New Project → Deploy from GitHub → open `/login` (username `TiTaN`)
- **Render:** New Web Service → connect repo (`render.yaml` handles it) → `/login` (username `TiTaN`)
- **Local:** `pip install -r requirements.txt && uvicorn app.main:app --port 8000`

## License

MIT — see [LICENSE](LICENSE). Font: Vazirmatn (OFL). Built with ❤️.

---

<div align="center"><b>TiTaN</b> — fast, lightweight, magical ⚡</div>
