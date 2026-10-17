"""Telegram Bot API webhook / interactive shopping and unanimous voting."""
from __future__ import annotations
import hmac
import html
import logging
from datetime import timedelta
from sqlalchemy import select, func, or_
from fastapi import HTTPException, Request
import httpx
from app.config import config
from app.db import SessionLocal
from app.models import (User, Plan, Host, Slot, Subscription, Operation, OperationVote,
                        BotState, ProcessedUpdate, TelegramOutbox, WalletEntry, Ticket, TicketMessage, Order)
from app.services import (user_get_or_create, available_slots, get_balance,
                         request_operation, vote, owner_ids, purchase)

log = logging.getLogger("ganj.telegram")


def kb(rows):
    """Color is used only for one primary/positive/destructive action per screen.

    Telegram style buttons are theme-dependent, so neutral navigation stays unstyled.
    """
    result = []
    for row in rows:
        buttons = []
        for item in row:
            title, action, *style = item
            button = {"text": title, "callback_data": action}
            if style and style[0] in {"primary", "success", "danger"}:
                button["style"] = style[0]
            buttons.append(button)
        result.append(buttons)
    return {"inline_keyboard": result}



def home_keyboard(uid: int):
    # Telegram inline keyboards support branding through concise labels and
    # layout; custom CSS, fonts, rounded cards and arbitrary colors do not.
    rows = [
        [('🛍 خرید نود خارج', 'shop', 'primary')],
        [('📦 سرویس‌های من', 'mine'), ('💳 کیف پول', 'wallet')],
        [('🎧 پشتیبانی', 'support'), ('👤 حساب من', 'account')],
        [('🗳 درخواست‌های مشترک', 'votebox'), ('📖 راهنما', 'guide')],
    ]
    if uid == config.owner_id:
        rows.append([('⚙️ مدیریت گنج VPS', 'admin')])
    board = kb(rows)
    if config.public_base_url.startswith('https://'):
        board['inline_keyboard'].append([
            {'text': '✨ ورود به داشبورد اختصاصی',
             'web_app': {'url': config.public_base_url}}
        ])
    return board

HOME = home_keyboard(0)  # safe fallback for legacy tests and errors

ACTIONS_FA = {'restart_host': 'ریستارت سرور', 'power_on': 'روشن‌کردن سرور',
              'power_off': 'خاموش‌کردن سرور', 'change_shared_ip': 'تغییر IP مشترک'}


SEPARATOR = "━━━━━━━━━━━━━━━━"
REGION_FLAGS = {'DE': '🇩🇪', 'FR': '🇫🇷', 'TR': '🇹🇷',
                'US': '🇺🇸', 'FI': '🇫🇮', 'NL': '🇳🇱',
                'GB': '🇬🇧', 'UK': '🇬🇧', 'AE': '🇦🇪'}


def region_badge(region: str) -> str:
    code = (region or '').strip().upper()
    return REGION_FLAGS.get(code, '🌐')


def titlebar(label: str, tag: str = 'GANJ VPS') -> str:
    return f'<b>◆ {html.escape(label)}</b>\n<code>{html.escape(tag)}</code>\n{SEPARATOR}\n'


def status_fa(status: str) -> str:
    return {'active': '🟢 فعال', 'provisioning': '🟡 در حال آماده‌سازی',
            'pending': '🟡 در انتظار', 'open': '🔵 باز',
            'waiting_support': '🟡 در انتظار پشتیبانی',
            'answered': '🟢 پاسخ داده‌شده', 'in_progress': '🔵 در حال بررسی',
            'closed': '⚪ بسته', 'expired': '⚪ پایان‌یافته',
            'suspended': '🔴 متوقف'}.get(status, html.escape(status or 'نامشخص'))


def navigation(back: str = 'home', *, home: bool = True):
    rows = [[('↩️ بازگشت', back)]]
    if home and back != 'home':
        rows[0].append(('🏠 خانه', 'home'))
    return rows


def catalog_view(db, capacity: str = 'all', page: int = 0):
    # Never invent offers or inventory. Reuse the existing allocation source.
    if capacity not in {'all', '2', '3'}:
        capacity = 'all'
    plans = db.scalars(select(Plan).where(Plan.enabled == True)
                       .order_by(Plan.price_toman, Plan.name)).all()
    in_stock = []
    for plan in plans:
        if capacity != 'all' and plan.capacity != int(capacity):
            continue
        available = len(available_slots(db, plan))
        if available:
            in_stock.append((plan, available))
    page_size = 5
    pages = max(1, (len(in_stock) + page_size - 1) // page_size)
    page = min(max(page, 0), pages - 1)
    filtered = in_stock[page * page_size:(page + 1) * page_size]
    rows = [
        [('✨ همه نودها', 'shopcat:all:0'),
         ('👥 دو نفره', 'shopcat:2:0'),
         ('👥 سه نفره', 'shopcat:3:0')],
    ]
    for plan, available in filtered:
        text = (f'{region_badge(plan.region)} {plan.name[:24]}'
                f' · {plan.price_toman:,} ت')
        rows.append([(text, 'plan:' + plan.id)])
    if pages > 1:
        arrows = []
        if page > 0:
            arrows.append(('◀️ قبلی', f'shopcat:{capacity}:{page-1}'))
        if page + 1 < pages:
            arrows.append(('بعدی ▶️', f'shopcat:{capacity}:{page+1}'))
        rows.append(arrows)
    rows.extend(navigation('home', home=False))
    heading = titlebar('فروشگاه نودهای خارج', 'GANJ / NODE MARKET')
    label = {'all': 'تمام ظرفیت‌ها', '2': 'دو نفره', '3': 'سه نفره'}[capacity]
    text = (heading +
            'نود مناسب کسب‌وکارت را انتخاب کن.\n'
            'قیمت نهایی و نوع پنل قبل از پرداخت نمایش داده می‌شود.\n\n'
            f'📍 دسته‌بندی: <b>{label}</b>\n'
            f'📦 پلن‌های موجود: <b>{len(in_stock)}</b>\n')
    if in_stock:
        text += f'📄 صفحه <b>{page + 1}</b> از <b>{pages}</b>\n\n'
        text += '<i>برای مشاهده مشخصات کامل، روی پلن بزن.</i>'
    else:
        text += ('\nفعلاً پلنی با این ظرفیت موجود نیست. '
                 'با تغییر دسته‌بندی، سایر نودها را ببین.\n'
                 'موجودی فقط از سرورهای ثبت‌شده نمایش داده می‌شود.')
    return text, kb(rows)



def menu_message(uid: int, db):
    active = db.scalar(select(func.count()).select_from(Subscription).where(
        Subscription.user_id == uid, Subscription.status.in_(["active", "provisioning"]))) or 0
    pending = db.scalar(select(func.count()).select_from(Subscription).where(
        Subscription.user_id == uid, Subscription.status == 'provisioning')) or 0
    balance = get_balance(db, uid)
    return (titlebar('گنج VPS | فضای ابری اختصاصی', 'GANJ CLOUD • PRIVATE CONSOLE') +
            '\n<b>به گنج VPS خوش اومدی!</b>\n'
            'اینجا خرید نود، مدیریت سرویس و پشتیبانی در دسترس توست.\n\n'
            '📊 <b>خلاصه حساب</b>\n'
            f'📦 سرویس‌های من: <b>{active}</b>\n'
            f'💳 موجودی کیف پول: <b>{balance:,} تومان</b>\n'
            f'⏳ در انتظار آماده‌سازی: <b>{pending}</b>\n\n'
            '<i>از فروشگاه شروع کن یا سرویس‌های فعلی را مدیریت کن.</i>')

def emit(target, text, keyboard=None):
    return {"chat_id": target, "text": text, "parse_mode": "HTML", "reply_markup": keyboard}


def find_state(db, uid):
    return db.get(BotState, uid)


def set_state(db, uid, action, resource_id):
    old = find_state(db, uid)
    if old:
        old.action, old.resource_id = action, resource_id
    else:
        db.add(BotState(user_id=uid, action=action, resource_id=resource_id))


def clear_state(db, uid):
    state = find_state(db, uid)
    if state:
        db.delete(state)


def process_update(db, update: dict):
    """Returns messages; all mutations commit before network delivery."""
    message = update.get("message") or {}
    callback = update.get("callback_query") or {}
    actor_data = (callback.get("from") if callback else message.get("from")) or {}
    user_id = int(actor_data.get("id", 0))
    if user_id <= 0:
        return []
    user_get_or_create(db, user_id, actor_data.get("first_name", ""))
    chat = (callback.get("message") or message).get("chat") or {}
    # All account-sensitive actions only in user's private chat.
    if int(chat.get("id", 0)) != user_id or chat.get("type") != "private":
        return []
    data = callback.get("data", "")
    content = message.get("text") or ""
    if content.startswith("/start") or data == "home":
        clear_state(db, user_id)
        return [emit(user_id, menu_message(user_id, db), home_keyboard(user_id))]

    if content == '/admin' or data == 'admin':
        if user_id != config.owner_id:
            return [emit(user_id, 'این بخش تنها برای مدیر مجاز است.',
                         home_keyboard(user_id))]
        hosts = db.scalar(select(func.count()).select_from(Host)) or 0
        users = db.scalar(select(func.count()).select_from(User)) or 0
        orders = db.scalar(select(func.count()).select_from(Order)) or 0
        tickets = db.scalar(select(func.count()).select_from(Ticket).where(
            Ticket.status != 'closed')) or 0
        body = (titlebar('مرکز مدیریت گنج VPS', 'GANJ / ADMIN CONSOLE') +
                '\n<b>نمای کلی سیستم</b>\n'
                f'🖥 سرورهای ثبت‌شده: <b>{hosts}</b>\n'
                f'👥 کاربران: <b>{users}</b>\n'
                f'🧾 سفارش‌ها: <b>{orders}</b>\n'
                f'🎧 تیکت‌های باز: <b>{tickets}</b>\n\n'
                '<i>گزارش‌های فوری اینجا قابل مشاهده‌اند؛ تغییر محصولات و امور مالی در داشبورد امن وب انجام می‌شود.</i>')
        board = kb([[('📊 گزارش فروش', 'admin:finance'), ('🧾 سفارش‌ها', 'admin:orders')],
                    [('🖥 سرورها', 'admin:hosts'), ('👥 کاربران', 'admin:users')],
                    [('🎧 پشتیبانی', 'admin:tickets')]] + navigation())
        if config.public_base_url.startswith('https://'):
            board['inline_keyboard'].insert(0, [{
                'text':'✨ بازکردن داشبورد مدیریت',
                'web_app':{'url':config.public_base_url}}])
        return [emit(user_id, body, board)]
    if data.startswith('admin:'):
        if user_id != config.owner_id:
            return [emit(user_id, 'دسترسی مجاز نیست.', home_keyboard(user_id))]
        key = data.split(':', 1)[1]
        if key == 'finance':
            paid = db.scalar(select(func.sum(Order.amount_toman)).where(
                Order.status == 'paid')) or 0
            count = db.scalar(select(func.count()).select_from(Order).where(
                Order.status == 'paid')) or 0
            body = (titlebar('خلاصه فروش', 'FINANCIAL SNAPSHOT') +
                    f'🧾 تعداد سفارش‌های پرداخت‌شده: <b>{count}</b>\n'
                    f'💰 مجموع ثبت‌شده: <b>{paid:,} تومان</b>\n\n'
                    '<i>این مبلغ فروش ثبت‌شده است، نه سود خالص یا موجودی بانکی.</i>')
        elif key == 'orders':
            latest = db.scalars(select(Order).order_by(
                Order.created_at.desc()).limit(5)).all()
            body = (titlebar('سفارش‌های اخیر', 'ORDER ACTIVITY') +
                    ('\n'.join(f'• <code>{o.id[:10]}</code> · {o.amount_toman:,} ت'
                               f' · {status_fa(o.status)}' for o in latest) or
                     'سفارشی ثبت نشده است.'))
        elif key == 'hosts':
            rows = db.scalars(select(Host).order_by(Host.created_at.desc()).limit(6)).all()
            body = (titlebar('سرورهای ثبت‌شده', 'INFRASTRUCTURE') +
                    ('\n'.join('• ' + html.escape(h.name[:45]) +
                               ' · ' + html.escape(h.region[:12]) for h in rows) or
                     'سروری ثبت نشده است.'))
        elif key == 'users':
            count = db.scalar(select(func.count()).select_from(User)) or 0
            body = titlebar('مدیریت کاربران', 'CUSTOMERS') + f'👥 کاربران ثبت‌شده: <b>{count}</b>\n\nجزئیات و عملیات مدیریتی در داشبورد امن وب در دسترس است.'
        elif key == 'tickets':
            count = db.scalar(select(func.count()).select_from(Ticket).where(
                Ticket.status != 'closed')) or 0
            body = titlebar('درخواست‌های پشتیبانی', 'SUPPORT DESK') + f'🎧 تیکت‌های باز: <b>{count}</b>\n\nبرای پاسخ به مشتریان وارد پنل مدیریت وب شو.'
        else:
            return [emit(user_id, 'این بخش پیدا نشد.', kb(navigation('admin')))]
        buttons = kb(navigation('admin'))
        if config.public_base_url.startswith('https://'):
            buttons['inline_keyboard'].insert(0, [{'text':'✨ مدیریت در داشبورد',
                           'web_app':{'url':config.public_base_url}}])
        return [emit(user_id, body, buttons)]
    if data == 'guide':
        text = (titlebar('راهنمای خرید و مدیریت', 'HOW IT WORKS') +
                '\n<b>۱. انتخاب نود</b>\n'
                'در فروشگاه، ظرفیت و لوکیشن را بررسی و نوع پنل را انتخاب کن.\n\n'
                '<b>۲. پرداخت با کیف پول</b>\n'
                'اگر اعتبار کافی داشته باشی، سفارش از کیف پول ثبت می‌شود. '
                'درگاه شارژ خودکار هنوز فعال نشده است.\n\n'
                '<b>۳. پیگیری تحویل</b>\n'
                'تا زمان آماده‌سازی و تست فنی، سفارش تحویل‌شده محسوب نمی‌شود.\n\n'
                '<b>۴. پشتیبانی</b>\n'
                'سؤال یا مشکل را از بخش تیکت‌ها ثبت و پیگیری کن.\n\n'
                '🔒 <i>در نود اشتراکی، رمز root و SSH ارائه نمی‌شود.</i>')
        return [emit(user_id, text,
                     kb([[('🛍 مشاهده فروشگاه', 'shop', 'primary')],
                         [('🎧 پشتیبانی', 'support')] ] + navigation()))]

    if data == 'account':
        user = db.get(User, user_id)
        count = db.scalar(select(func.count()).select_from(Subscription).where(
            Subscription.user_id == user_id)) or 0
        active = db.scalar(select(func.count()).select_from(Subscription).where(
            Subscription.user_id == user_id, Subscription.status == 'active')) or 0
        body = (titlebar('پروفایل کاربری', 'GANJ / MY ACCOUNT') +
                '\n👤 <b>' + html.escape((user.display_name or 'کاربر گنج')[:80]) + '</b>\n'
                f'🆔 شناسه تلگرام: <code>{user_id}</code>\n\n'
                f'📦 کل سرویس‌ها: <b>{count}</b>\n'
                f'🟢 سرویس‌های فعال: <b>{active}</b>\n'
                f'💳 موجودی کیف پول: <b>{get_balance(db, user_id):,} تومان</b>\n\n'
                '<i>اطلاعات مالی صرفاً از حساب ثبت‌شده شما خوانده می‌شود.</i>')
        return [emit(user_id, body, kb([[('📦 سرویس‌های من', 'mine'),
                      ('💳 کیف پول', 'wallet')], [('🎧 پشتیبانی', 'support')]] +
                      navigation()))]

    if data == 'support':
        tickets = db.scalars(select(Ticket).where(
            Ticket.user_id == user_id, Ticket.status != 'draft')
            .order_by(Ticket.created_at.desc()).limit(5)).all()
        preview = '\n'.join('• ' + html.escape(t.subject[:49]) +
                           ' — ' + status_fa(t.status) for t in tickets)
        buttons = [[('📝 ثبت تیکت جدید', 'newticket', 'primary')]]
        buttons += [[('🎫 ' + t.subject[:31], 'tinfo:' + t.id)] for t in tickets]
        buttons += navigation('home')
        body = (titlebar('مرکز پشتیبانی', 'GANJ / SUPPORT DESK') +
                '\n<b>همراهت هستیم.</b>\n'
                'پیگیری درخواست‌ها و گفت‌وگو با پشتیبانی از همین بخش انجام می‌شود.\n\n'
                '🎟 <b>آخرین تیکت‌ها</b>\n' +
                (preview or 'هنوز درخواستی ثبت نشده است.') +
                '\n\n<i>برای مشاهده گفت‌وگو، تیکت را انتخاب کن.</i>')
        return [emit(user_id, body, kb(buttons))]
    if data.startswith("tinfo:"):
        ticket = db.get(Ticket, data[6:])
        if not ticket or ticket.user_id != user_id:
            return [emit(user_id, "تیکت پیدا نشد.", home_keyboard(user_id))]
        messages = db.scalars(select(TicketMessage).where(TicketMessage.ticket_id == ticket.id)
                      .order_by(TicketMessage.created_at.desc()).limit(5)).all()
        preview = "\n\n".join(
            ("<b>پشتیبانی</b>" if m.is_staff else "<b>شما</b>") + ": " + html.escape(m.body[:400])
            for m in reversed(messages))
        intro = ("<b>◇ " + html.escape(ticket.subject[:120]) + "</b>\n" +
                 "وضعیت: " + html.escape(ticket.status) + "\n\n" +
                 "<b>درخواست اولیه:</b>\n" + html.escape(ticket.message[:700]))
        rows = []
        if ticket.status != "closed":
            rows.append([('پاسخ به تیکت', 'treply:' + ticket.id, 'primary')])
        rows.append([('بازگشت', 'support')])
        return [emit(user_id, intro + ("\n\n<b>پاسخ‌ها:</b>\n" + preview if preview else ""), kb(rows))]
    if data.startswith("treply:"):
        ticket = db.get(Ticket, data[7:])
        if not ticket or ticket.user_id != user_id or ticket.status == "closed":
            return [emit(user_id, "این تیکت برای پاسخ‌دادن در دسترس نیست.", home_keyboard(user_id))]
        set_state(db, user_id, "reply_ticket", ticket.id)
        return [emit(user_id, "پاسخ خود را در یک پیام بنویسید (حداکثر ۴۰۰۰ کاراکتر).",
                     kb([[('انصراف', 'support')]]))]
    if data == "newticket":
        set_state(db, user_id, 'new_ticket', 'new')
        return [emit(user_id, "<b>ثبت تیکت جدید</b>\n\nدر یک پیام، موضوع را در خط اول و توضیحات را در خطوط بعد بنویسید.\nمثال:\n<code>اختلال در نود آلمان\nاز ساعت ۱۰ اتصال برقرار نمی‌شود...</code>",
                     kb([[('انصراف', 'home')]]))]

    if data == 'wallet':
        history = db.scalars(select(WalletEntry).where(WalletEntry.user_id == user_id)
                    .order_by(WalletEntry.created_at.desc()).limit(5)).all()
        transactions = '\n'.join(('🟢 +' if t.delta_toman > 0 else '🔴 −') +
            f' <b>{abs(t.delta_toman):,}</b> ت · {html.escape(t.reason[:48])}'
            for t in history)
        text = (titlebar('کیف پول گنج', 'GANJ / YOUR WALLET') +
                '\n<b>موجودی قابل استفاده</b>\n'
                f'💳 <b>{get_balance(db, user_id):,} تومان</b>\n\n'
                f'{SEPARATOR}\n'
                '🧾 <b>آخرین تراکنش‌ها</b>\n' +
                (transactions or 'هنوز تراکنشی ثبت نشده است.') +
                '\n\n<i>شارژ آنلاین کیف پول هنوز فعال نشده است. '
                'اعتبار فقط پس از تأیید پرداخت مجاز ثبت می‌شود.</i>')
        return [emit(user_id, text, kb([[('🛍 مشاهده فروشگاه', 'shop'),
                 ('👤 حساب من', 'account')]] + navigation()))]
    if data == "shop" or data.startswith('shopcat:'):
        capacity, page = 'all', 0
        if data.startswith('shopcat:'):
            parts = data.split(':')
            if len(parts) == 3 and parts[1] in {'all', '2', '3'}:
                capacity = parts[1]
                try:
                    page = int(parts[2])
                except ValueError:
                    page = 0
        text, keyboard = catalog_view(db, capacity, page)
        return [emit(user_id, text, keyboard)]

    if data.startswith('plan:'):
        plan = db.get(Plan, data[5:])
        if not plan or not plan.enabled:
            return [emit(user_id, 'این پلن دیگر فعال نیست.', kb(navigation('shop')))]
        count = len(available_slots(db, plan))
        if not count:
            return [emit(user_id, 'ظرفیت این پلن تمام شده است.', kb(navigation('shop')))]
        body = (titlebar('مشخصات پلن', 'PLAN DETAILS') +
                '\n' + region_badge(plan.region) + ' <b>' +
                html.escape(plan.name) + '</b>\n'
                f'🌐 موقعیت: <b>{html.escape(plan.region)}</b>\n'
                f'👥 ظرفیت نود: <b>{plan.capacity} نفره</b>\n'
                f'📅 مدت اعتبار: <b>{plan.term_days} روز</b>\n'
                f'📦 ظرفیت قابل سفارش: <b>{count}</b>\n'
                f'💰 قیمت: <b>{plan.price_toman:,} تومان</b>\n\n'
                f'{SEPARATOR}\n'
                'پنل موردنظرت را انتخاب کن:'
                '\n<i>بعد از انتخاب پنل، فاکتور و مبلغ نهایی نمایش داده می‌شود.</i>')
        rows = [[('🟢 پاسارگارد', f'runtime:{plan.id}:pasarguard'),
                 ('🔷 ربکا', f'runtime:{plan.id}:rebecca')],
                [('🟣 مرزبان', f'runtime:{plan.id}:marzban')]]
        return [emit(user_id, body, kb(rows + navigation('shop')))]

    if data.startswith('runtime:'):
        try:
            _, pid, runtime = data.split(':')
        except ValueError:
            return [emit(user_id, 'درخواست معتبر نیست.', kb(navigation('shop')))]
        plan = db.get(Plan, pid)
        runtime_names = {'pasarguard': 'پاسارگارد', 'rebecca': 'ربکا',
                         'marzban': 'مرزبان'}
        if not plan or not plan.enabled or runtime not in runtime_names:
            return [emit(user_id, 'پلن یا نوع پنل معتبر نیست.',
                         kb(navigation('shop')))]
        if not available_slots(db, plan):
            return [emit(user_id, 'ظرفیت این پلن تمام شده است.',
                         kb(navigation('shop')))]
        balance = get_balance(db, user_id)
        body = (titlebar('پیش‌فاکتور خرید', 'SECURE CHECKOUT') +
                '\n<b>خلاصه سفارش</b>\n'
                f'📦 نود: <b>{html.escape(plan.name)}</b>\n'
                f'⚙️ نوع پنل: <b>{runtime_names[runtime]}</b>\n'
                f'📅 اعتبار: <b>{plan.term_days} روز</b>\n'
                f'💰 مبلغ نهایی: <b>{plan.price_toman:,} تومان</b>\n'
                f'💳 موجودی کیف پول: <b>{balance:,} تومان</b>\n\n'
                f'{SEPARATOR}\n'
                '🛡 <i>ثبت سفارش به معنی تحویل آنی سرور نیست. '
                'تحویل فقط پس از آماده‌سازی و تست فنی تأیید می‌شود.</i>')
        if balance < plan.price_toman:
            clear_state(db, user_id)
            text = body + ('\n\n<b>اعتبار کیف پول کافی نیست.</b>\n'
                     'شارژ آنلاین هنوز فعال نشده است؛ برای راهنمایی تیکت ثبت کن.')
            return [emit(user_id, text, kb([[('🎧 پشتیبانی', 'support'),
                     ('💳 کیف پول', 'wallet')]] + navigation('plan:' + pid)))]
        set_state(db, user_id, 'confirm_' + runtime, plan.id)
        return [emit(user_id, body, kb([[('✅ تأیید و پرداخت از کیف پول',
                        f'pay:{plan.id}:{runtime}', 'success')]] +
                        navigation('plan:' + pid)))]
    if data.startswith("pay:"):
        try:
            _, pid, runtime = data.split(":")
        except ValueError:
            return [emit(user_id, "درخواست نامعتبر", HOME)]
        state = find_state(db, user_id)
        if not state or state.resource_id != pid or state.action != "confirm_" + runtime:
            return [emit(user_id, "این فاکتور قبلاً استفاده یا منقضی شده؛ دوباره از فروشگاه اقدام کنید.", HOME)]
        msg_id = int((callback.get("message") or {}).get("message_id", 0))
        order, _ = purchase(db, user_id, pid, runtime, f"tg:{user_id}:{msg_id}:{pid}:{runtime}")
        clear_state(db, user_id)
        return [emit(user_id, f"<b>پرداخت ثبت شد.</b>\nشماره سفارش: <code>{order.id}</code>\n" +
                     "وضعیت: منتظر آماده‌سازی فنی (هنوز نود تحویل نشده است).", HOME)]

    if data == 'mine':
        subscriptions = db.scalars(select(Subscription).where(
            Subscription.user_id == user_id).order_by(
            Subscription.started_at.desc()).limit(8)).all()
        buttons = [[('📦 ' + (sub.runtime_type or 'نود').upper() + ' · ' +
                     ('فعال' if sub.status == 'active' else 'در حال آماده‌سازی'
                      if sub.status == 'provisioning' else sub.status[:15]),
                     'sub:' + sub.id)] for sub in subscriptions]
        buttons += [[('🛍 خرید نود جدید', 'shop', 'primary')]]
        buttons += navigation('home')
        body = (titlebar('سرویس‌های من', 'MY CLOUD NODES') +
                '\n<b>اشتراک‌ها و وضعیت تحویل</b>\n' +
                ('\n'.join('• <b>' + html.escape(sub.runtime_type or 'نود') +
                            '</b> · ' + status_fa(sub.status)
                            for sub in subscriptions) or
                 'هنوز سرویسی ثبت نشده است. از فروشگاه شروع کن.') +
                '\n\n<i>جزئیات هر سرویس را با دکمه مربوط به آن ببین.</i>')
        return [emit(user_id, body, kb(buttons))]

    if data.startswith('sub:'):
        sub = db.get(Subscription, data[4:])
        if not sub or sub.user_id != user_id:
            return [emit(user_id, 'اشتراک پیدا نشد.', kb(navigation('mine')))]
        slot = db.get(Slot, sub.slot_id)
        host = db.get(Host, slot.host_id) if slot else None
        if not host:
            return [emit(user_id, 'اطلاعات میزبان در دسترس نیست.',
                         kb(navigation('mine')))]
        body = (titlebar('جزئیات نود اختصاصی', 'SERVICE DETAILS') +
                '\n📦 نوع پنل: <b>' + html.escape(sub.runtime_type or 'نامشخص') +
                '</b>\n'
                '📊 وضعیت: ' + status_fa(sub.status) + '\n'
                '🖥 میزبان: <b>' + html.escape(host.name) + '</b>\n'
                '📅 پایان اعتبار: <b>' + str(sub.ends_at.date()) + '</b>\n'
                '🌐 آدرس IP: <code>' +
                html.escape(sub.public_ip or 'در انتظار تحویل') + '</code>\n\n'
                '🔒 <i>دسترسی SSH و root در سرویس اشتراکی تحویل داده نمی‌شود.</i>')
        buttons = []
        if sub.public_ip:
            buttons.append([{'text':'📋 کپی آدرس IP',
                              'copy_text':{'text':sub.public_ip}}])
        actions = kb([[('🔄 درخواست ریستارت', 'op:restart_host:' + host.id),
                       ('🌐 درخواست تغییر IP', 'op:change_shared_ip:' + host.id)],
                      [('⏻ خاموش‌کردن', 'op:power_off:' + host.id),
                       ('⏽ روشن‌کردن', 'op:power_on:' + host.id)]] +
                      navigation('mine'))
        actions['inline_keyboard'] = buttons + actions['inline_keyboard']
        return [emit(user_id, body + '\n\n<i>عملیات مشترک فقط پس از رأی همه مالکان و بررسی فنی قابل اجراست.</i>',
                     actions)]
    if data.startswith("op:"):
        try:
            _, action, host_id = data.split(":")
        except ValueError:
            return [emit(user_id, "درخواست نامعتبر", HOME)]
        if action not in ACTIONS_FA or user_id not in owner_ids(db, host_id):
            return [emit(user_id, "این اقدام برای شما مجاز نیست", HOME)]
        set_state(db, user_id, "operation_" + action, host_id)
        return [emit(user_id, f"<b>{html.escape(ACTIONS_FA[action])}</b>\n\n" +
                     "دلیل درخواست را در یک پیام بنویسید (حداقل ۸ کاراکتر).\n" +
                     "این دلیل برای سایر مالکان همان سرور ارسال می‌شود.\n" +
                     "هیچ دستور واقعی پیش از تأیید همه مالکان و تست فنی اجرا نمی‌شود.",
                     kb([[('انصراف','home')]]))]

    if data == 'votebox':
        ops = db.scalars(select(Operation).where(
            Operation.status == 'pending_approval')
            .order_by(Operation.created_at.desc()).limit(100)).all()
        visible = [op for op in ops if user_id in op.owners_snapshot
                   and op.requester_id != user_id]
        rows = [[('🗳 ' + ACTIONS_FA.get(op.action, op.action)[:26] +
                 ' · ' + op.id[:6], 'vinfo:' + op.id)] for op in visible[:8]]
        rows += navigation('home')
        body = (titlebar('مدیریت مشترک نودها', 'SHARED OPERATIONS') +
                '\n<b>درخواست‌های نیازمند رأی شما</b>\n'
                f'🗳 تعداد درخواست‌ها: <b>{len(visible)}</b>\n\n'
                + ('برای مشاهده دلیل و ثبت رأی، درخواست را انتخاب کن.'
                   if visible else 'در حال حاضر درخواست منتظر رأی ندارید.') +
                '\n\n<i>هیچ عملیات واقعی بدون توافق مالکان و تست اتصال اجرا نمی‌شود.</i>')
        return [emit(user_id, body, kb(rows))]
    if data.startswith("vinfo:"):
        op = db.get(Operation, data[6:])
        if not op or user_id not in op.owners_snapshot or user_id == op.requester_id:
            return [emit(user_id, "درخواست یافت نشد", HOME)]
        if op.status != "pending_approval":
            return [emit(user_id, f"وضعیت درخواست: {html.escape(op.status)}", HOME)]
        return [emit(user_id, f"<b>درخواست عملیات مشترک</b>\nعملیات: {html.escape(op.action)}\n" +
                     f"دلیل: {html.escape(op.reason)}\n" +
                     "با تأیید همه مالکان، درخواست برای بررسی و اجرای فنی مجاز می‌شود؛ اجرای خودکار هنوز غیرفعال است.",
                     kb([[("تأیید", "va:" + op.id, 'success'), ("رد با دلیل", "vr:" + op.id, 'danger')],
                         [('بازگشت', 'votebox')]]))]
    if data.startswith("va:"):
        op = vote(db, user_id, data[3:], "approve")
        return [emit(user_id, "رأی شما ثبت شد. وضعیت: " + html.escape(op.status), HOME),
                emit(op.requester_id, f"رأی یکی از مالکان ثبت شد. وضعیت درخواست <code>{op.id[:8]}</code>: {html.escape(op.status)}")]
    if data.startswith("vr:"):
        op = db.get(Operation, data[3:])
        if not op or op.status != "pending_approval" or user_id not in op.owners_snapshot or op.requester_id == user_id:
            return [emit(user_id, "درخواست معتبر نیست", HOME)]
        set_state(db, user_id, "reject_vote", op.id)
        return [emit(user_id, "دلیل رد را بنویسید تا برای درخواست‌کننده ارسال شود.")]
    if content and not content.startswith("/"):
        state = find_state(db, user_id)
        if state and state.action == 'reply_ticket':
            ticket = db.get(Ticket, state.resource_id)
            if not ticket or ticket.user_id != user_id or ticket.status == "closed":
                clear_state(db, user_id)
                return [emit(user_id, "این تیکت برای پاسخ‌دادن در دسترس نیست.", home_keyboard(user_id))]
            if not 2 <= len(content.strip()) <= 4000:
                return [emit(user_id, "پاسخ باید بین ۲ تا ۴۰۰۰ کاراکتر باشد.")]
            db.add(TicketMessage(ticket_id=ticket.id, author_id=user_id,
                                 body=content.strip(), is_staff=False))
            ticket.status = "waiting_support"
            clear_state(db, user_id)
            return [emit(user_id, "پاسخ شما در تیکت ثبت شد.", home_keyboard(user_id)),
                    emit(config.owner_id, "مشتری به تیکت گنج VPS پاسخ داد: " + ticket.id[:12])]
        if state and state.action == 'new_ticket':
            lines = content.strip().splitlines()
            subject = (lines[0] if lines else '').strip()
            description = '\n'.join(lines[1:]).strip()
            if not 4 <= len(subject) <= 200 or not 10 <= len(description) <= 4000:
                return [emit(user_id, 'موضوع باید بین ۴ تا ۲۰۰ کاراکتر و توضیح حداقل ۱۰ کاراکتر باشد.\nدر خط اول موضوع و در خط‌های بعد توضیحات را بنویسید.',
                             kb([[('انصراف', 'home')]]))]
            ticket = Ticket(user_id=user_id, subject=subject, message=description)
            db.add(ticket)
            db.flush()
            clear_state(db, user_id)
            return [emit(user_id, '<b>درخواست پشتیبانی ثبت شد.</b>\nشناسه: <code>' + ticket.id + '</code>\nوضعیت: در انتظار بررسی', home_keyboard(user_id))]
        if state and state.action.startswith("operation_"):
            action = state.action[len("operation_"):]
            op = request_operation(db, user_id, state.resource_id, action, content)
            clear_state(db, user_id)
            result = [emit(user_id, "درخواست عملیات ثبت شد؛ وضعیت: " + html.escape(op.status), HOME)]
            for other in op.owners_snapshot:
                if other != user_id:
                    result.append(emit(other, f"<b>درخواست جدید روی سرور مشترک</b>\nعملیات: {html.escape(op.action)}\n" +
                                       f"دلیل: {html.escape(op.reason)}\nبرای رأی وارد «درخواست‌های مشترک» شوید.", HOME))
            return result
        if state and state.action == "reject_vote":
            op = vote(db, user_id, state.resource_id, "reject", content)
            clear_state(db, user_id)
            return [emit(user_id, "درخواست با ثبت دلیل رد شد.", HOME),
                    emit(op.requester_id, f"درخواست عملیات <code>{op.id[:8]}</code> رد شد. دلیل: {html.escape(content[:500])}", HOME)]
    return [emit(user_id, "برای ادامه از منوی گنج VPS استفاده کنید.", home_keyboard(user_id))]


async def telegram_request(method: str, payload: dict) -> bool:
    """Best-effort Telegram delivery; never leak token, payload or user details to logs."""
    if not config.telegram_bot_token:
        return False
    url = f"https://api.telegram.org/bot{config.telegram_bot_token}/{method}"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return bool(response.json().get("ok"))
    except (httpx.HTTPError, ValueError):
        log.warning("Telegram %s delivery failed", method)
        return False


async def send_message(message: dict) -> bool:
    """Try editMessageText first, then fall back to sendMessage on failure.

    Returning True is essential for safely acknowledging the durable outbox.
    """
    payload = dict(message)
    target_message = payload.pop("_edit_message_id", None)
    if target_message:
        payload["message_id"] = target_message
        if await telegram_request("editMessageText", payload):
            return True
        payload.pop("message_id", None)
    return await telegram_request("sendMessage", payload)


async def deliver_outbox(max_messages: int = 8) -> dict:
    """Claim rows with a time-bounded lease and retry failures.

    The send-and-ack boundary can permit duplicate Telegram messages if the
    process exits just after delivery. The database never silently forgets
    undelivered messages, and webhook update IDs remain deduplicated.
    """
    from app.models import utcnow
    if not config.telegram_bot_token:
        return {"sent": 0, "pending_token": True}
    done = 0
    limit = max(0, min(max_messages, 50))
    for _ in range(limit):
        with SessionLocal() as db:
            now = utcnow()
            query = select(TelegramOutbox).where(
                TelegramOutbox.status.in_(["pending", "sending"]),
                TelegramOutbox.available_at <= now,
            ).order_by(TelegramOutbox.available_at, TelegramOutbox.created_at)
            if db.bind.dialect.name == "postgresql":
                query = query.with_for_update(skip_locked=True)
            else:
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            item = db.scalar(query.limit(1))
            if not item:
                return {"sent": done, "pending_token": False}
            item.attempts += 1
            item.status = "sending"
            item.available_at = now + timedelta(minutes=2)
            payload = dict(item.payload)
            row_id = item.id
            db.commit()
        try:
            delivered = bool(await send_message(payload))
        except Exception:
            # Do not expose chat IDs, message text, or bot credentials in logs.
            log.warning("Telegram outbound delivery raised an exception")
            delivered = False
        with SessionLocal() as db:
            row = db.get(TelegramOutbox, row_id)
            if not row or row.status != "sending":
                continue
            if delivered:
                row.status = "sent"
                row.delivered_at = utcnow()
                row.last_error_code = None
                done += 1
            elif row.attempts >= 8:
                row.status = "failed"
                row.last_error_code = "delivery_failed_max_attempts"
            else:
                row.status = "pending"
                row.last_error_code = "delivery_failed"
                row.available_at = utcnow() + timedelta(seconds=min(3600, 10 * (2 ** row.attempts)))
            db.commit()
    return {"sent": done, "pending_token": False}


async def process_webhook(request: Request):
    secret = request.headers.get("x-telegram-bot-api-secret-token", "")
    if not config.webhook_secret or not config.telegram_bot_token:
        raise HTTPException(503, "وبهوک ربات هنوز فعال نشده")
    if not secret or not hmac.compare_digest(config.webhook_secret, secret):
        raise HTTPException(403, "وبهوک نامعتبر")
    data = await request.json()
    if not isinstance(data, dict) or not isinstance(data.get("update_id"), int):
        raise HTTPException(400, "ساختار آپدیت نامعتبر")
    with SessionLocal() as db:
        try:
            if db.bind.dialect.name == "sqlite":
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")
            if db.get(ProcessedUpdate, data["update_id"]):
                return {"ok": True, "replayed": True}
            outgoing = process_update(db, data)
        except HTTPException as exc:
            db.rollback()
            user = ((data.get("callback_query") or {}).get("from") or
                    (data.get("message") or {}).get("from") or {})
            chat = ((data.get("callback_query") or {}).get("message") or
                    data.get("message") or {}).get("chat") or {}
            outgoing = []
            if user.get("id") and user.get("id") == chat.get("id") and chat.get("type") == "private":
                outgoing = [emit(user["id"], "درخواست انجام نشد: " + html.escape(str(exc.detail)), HOME)]
            if db.bind.dialect.name == "sqlite":
                db.connection().exec_driver_sql("BEGIN IMMEDIATE")
        except Exception:
            db.rollback()
            log.exception("Telegram update handler failed (secrets redacted)")
            raise HTTPException(500, "پردازش پیام با خطا روبه‌رو شد")
        callback = data.get("callback_query") or {}
        source = callback.get("message") or {}
        origin_chat = source.get("chat") or {}
        user = callback.get("from") or {}
        if outgoing and callback and origin_chat.get("id") == user.get("id"):
            if outgoing[0].get("chat_id") == user.get("id") and source.get("message_id"):
                outgoing[0]["_edit_message_id"] = source["message_id"]
        # Save responses and deduplication in the SAME transaction.
        for message in outgoing:
            db.add(TelegramOutbox(payload=message))
        db.add(ProcessedUpdate(update_id=data["update_id"]))
        db.commit()
    if callback.get("id"):
        await telegram_request("answerCallbackQuery", {"callback_query_id": callback["id"]})
    await deliver_outbox(max_messages=min(len(outgoing), 8))
    return {"ok": True}
