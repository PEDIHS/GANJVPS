# GANJ VPS — آزمایشگاه نصب و تحویل نود

**وضعیت:** پیش‌بررسی و مجوزهای مدیریت ساخته شده؛ نصب واقعی هنوز انجام نشده است.

## مرز محیط اجرا
- سرور مدیریت VPS و سرویس ترید میزبان تست نیستند. هیچ Docker، تغییر شبکه یا نصب Node روی آن‌ها اجرا نشود.
- یک VPS کاملاً مجزا با مالکیت و اجازه آزمایش، IP ثبت‌شده نزد Provider و دسترسی Agent محدود لازم است.
- تا تأیید Agent امضاشده، نسخه installer ثابت، صحت فایل و اتصال واقعی پنل، دو تنظیم DRY_RUN=true و ENABLE_HOST_OPERATIONS=false حفظ شوند.
- APIهای فعلی فقط گزارش و پیش‌بررسی هستند؛ هیچ فرمان سیستم اجرا نمی‌کنند.

## گیت پذیرش PasarGuard
1. میزبان آزمایشی Ubuntu/Debian، معماری معتبر، cgroup v2، Docker/Compose و RAM کافی پس از کسر سربار داشته باشد.
2. Agent با احراز هویت متقابل، مجوز حداقلی و allowlist متصل شود؛ ثبت Host در DB به‌تنهایی کافی نیست.
3. بسته نصب با commit/release تغییرناپذیر و SHA256 معتبر دریافت و کنترل شود؛ اجرای مستقیم اسکریپت متغیر از اینترنت ممنوع است.
4. هر slot نام مستقل، config/data/certificate، cgroup و شبکه/پورت جداگانه دریافت کند.
5. Port Registry، سوکت Host، Docker و NAT قبل از رزرو نهایی بررسی شوند؛ Reserve/Test/Switch/Release و rollback تراکنشی لازم‌اند.
6. روی میزبان تست نمونه اول نصب و با پنل مقصد تست شود؛ سپس نمونه دوم نصب، update و uninstall شود بدون اثر بر نمونه اول.
7. Resume، idempotency و شکست میانی تست شوند؛ نتیجه مرحله‌ها با شناسه Job و Audit و بدون افشای secret ثبت شوند.
8. تحویل به مشتری فقط IP/پورت، گواهی عمومی و روش امن دریافت API token باشد؛ root/SSH و کلید خصوصی میزبان هرگز تحویل نشود.

## Runtimeها
- PasarGuard: گام اول؛ نام نمونه یکتا و نسخه و checksum ثابت، بعد تست عملی.
- Rebecca: PoC گواهی/token، سرویس مستقل، عدم بازنویسی فایل‌ها و عدم تداخل با PasarGuard.
- Marzban: PoC با SERVICE_PORT و XRAY_API_PORT یکتا و SSL_CLIENT_CERT_FILE مستقل، تنظیم inbound و NAT معتبر.

## عملیات و مالی
- خاموش/روشن/Restart/Change IP مشترک نیازمند اجماع کامل، بازاعتبارسنجی قبل از اجرا، Provider API واقعی، Audit و امکان rollback است.
- روشن کردن میزبان خاموش نیازمند Provider خارجی است و با Agent داخل همان میزبان ممکن نیست.
- Telegram Stars، سبد خرید، فاکتور و رسید هنوز پیاده‌سازی نشده‌اند؛ قبل از فعال‌شدن باید سیاست فروش خدمات دیجیتال داخل تلگرام رعایت شود.

## رابط مدیریتی فعلی
- ربات → مدیریت → صف نصب نودها؛ دسترسی متناسب با مجوز nodes.provision.
- GET /api/v1/admin/provisioning/jobs
- GET /api/v1/admin/provisioning/orders/{order_id}/preflight
- پاسخ پیش‌بررسی، وضعیت و علت توقف، سهم پیشنهادی منابع و پورت‌های پیشنهادی، نه رزروشده، را نشان می‌دهد.

## منابع
سند GANJ VPS Complete Blueprint FA بخش‌های ۱۸ تا ۳۰.
PasarGuard https://docs.pasarguard.org/en/node/installation/
Rebecca https://github.com/rebeccapanel/Rebecca
Marzban https://github.com/Gozargah/gozargah.github.io/blob/master/marzban/en/docs/marzban-node.md
