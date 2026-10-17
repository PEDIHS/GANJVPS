"""Telegram Bot API webhook / interactive shopping and unanimous voting."""
from __future__ import annotations
import hmac
import html
import logging
from sqlalchemy import select, func
from fastapi import HTTPException, Request
import httpx
from app.config import config
from app.db import SessionLocal
from app.models import (User, Plan, Host, Slot, Subscription, Operation, OperationVote,
                        BotState, ProcessedUpdate, WalletEntry, Ticket, Order)
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
    rows = [[('▦ خرید نود', 'shop', 'primary'), ('▤ سرویس‌های من', 'mine')],
            [('◈ کیف پول', 'wallet'), ('◎ درخواست‌های مشترک', 'votebox')],
            [('◇ پشتیبانی', 'support'), ('◫ حساب کاربری', 'account')]]
    if uid == config.owner_id:
        rows.append([('▧ مدیریت', 'admin')])
    keyboard = kb(rows)
    if config.public_base_url.startswith("https://"):
        keyboard["inline_keyboard"].append([
            {"text": "◆ داشبورد پیشرفته", "web_app": {"url": config.public_base_url}}])
    return keyboard

HOME = home_keyboard(0)  # safe fallback for legacy tests and errors

ACTIONS_FA = {'restart_host': 'ریستارت سرور', 'power_on': 'روشن‌کردن سرور',
              'power_off': 'خاموش‌کردن سرور', 'change_shared_ip': 'تغییر IP مشترک'}


def menu_message(uid: int, db):
    active = db.scalar(select(func.count()).select_from(Subscription).where(
        Subscription.user_id == uid, Subscription.status.in_(["active", "provisioning"]))) or 0
    pending = db.scalar(select(func.count()).select_from(Subscription).where(
        Subscription.user_id == uid, Subscription.status == "provisioning")) or 0
    return ("<b>◆ گنج VPS | مدیریت نودهای خارج</b>\n"
            "<i>زیرساخت حرفه‌ای، مدیریت ساده</i>\n\n"
            f"▤ سرویس‌های فعال یا درحال آماده‌سازی: <b>{active}</b>\n"
            f"◈ موجودی کیف پول: <b>{get_balance(db, uid):,} تومان</b>\n"
            f"◷ سفارش‌های در حال آماده‌سازی: <b>{pending}</b>\n\n"
            "از منوی زیر بخش موردنظر را انتخاب کنید.")


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
    if content == "/admin" or data == "admin":
        if user_id != config.owner_id:
            return [emit(user_id, "این بخش فقط برای مدیران مجاز فعال است.", home_keyboard(user_id))]
        hosts = db.scalar(select(func.count()).select_from(Host)) or 0
        users = db.scalar(select(func.count()).select_from(User)) or 0
        orders = db.scalar(select(func.count()).select_from(Order)) or 0
        return [emit(user_id, "<b>▧ مدیریت گنج VPS</b>\n\n" +
                     f"◉ سرورهای ثبت‌شده: <b>{hosts}</b>\n" +
                     f"◉ کاربران: <b>{users}</b>\n" +
                     f"◉ سفارش‌ها: <b>{orders}</b>\n\n" +
                     "مدیریت مالی، تعریف سرور و پلن در داشبورد امن وب انجام می‌شود.",
                     kb([[('بازگشت', 'home')]]))]
    if data == "account":
        user = db.get(User, user_id)
        count = db.scalar(select(func.count()).select_from(Subscription).where(Subscription.user_id == user_id)) or 0
        return [emit(user_id, "<b>◫ حساب کاربری گنج VPS</b>\n\n" +
                     f"شناسه تلگرام: <code>{user_id}</code>\n" +
                     f"نام: {html.escape(user.display_name or 'کاربر گنج')}\n" +
                     f"تعداد سرویس‌ها: <b>{count}</b>\n" +
                     f"اعتبار کیف پول: <b>{get_balance(db, user_id):,} تومان</b>",
                     kb([[('پشتیبانی', 'support'), ('کیف پول', 'wallet')], [('بازگشت', 'home')]]))]
    if data == "support":
        tickets = db.scalars(select(Ticket).where(Ticket.user_id == user_id,
                       Ticket.status != 'draft').order_by(Ticket.created_at.desc()).limit(5)).all()
        preview = '\n'.join(f"• {html.escape(t.subject[:55])} — {html.escape(t.status)}" for t in tickets)
        return [emit(user_id, "<b>◇ مرکز پشتیبانی</b>\n\n" +
                      (preview or "تیکتی ثبت نشده است.") + "\n\n" +
                      "برای ثبت درخواست جدید موضوع و توضیحات را در یک پیام ارسال کنید.",
                      kb([[('ثبت تیکت جدید', 'newticket', 'primary')], [('بازگشت', 'home')]]))]
    if data == "newticket":
        set_state(db, user_id, 'new_ticket', 'new')
        return [emit(user_id, "<b>ثبت تیکت جدید</b>\n\nدر یک پیام، موضوع را در خط اول و توضیحات را در خطوط بعد بنویسید.\nمثال:\n<code>اختلال در نود آلمان\nاز ساعت ۱۰ اتصال برقرار نمی‌شود...</code>",
                     kb([[('انصراف', 'home')]]))]
    if data == "wallet":
        history = db.scalars(select(WalletEntry).where(WalletEntry.user_id == user_id)
                    .order_by(WalletEntry.created_at.desc()).limit(5)).all()
        lines = '\n'.join(("＋" if t.delta_toman > 0 else "−") +
                          f" {abs(t.delta_toman):,} تومان | {html.escape(t.reason[:55])}" for t in history)
        return [emit(user_id, "<b>◈ کیف پول گنج VPS</b>\n\n" +
                     f"موجودی: <b>{get_balance(db, user_id):,} تومان</b>\n\n" +
                     "<b>تراکنش‌های اخیر</b>\n" + (lines or "تراکنشی ثبت نشده است.") +
                     "\n\nشارژ موجودی پس از اتصال روش پرداخت مجاز فعال خواهد شد.",
                     kb([[('بازگشت', 'home')]]))]
    if data == "shop":
        plans = db.scalars(select(Plan).where(Plan.enabled == True).order_by(Plan.price_toman)).all()
        rows = [[(f"{p.name} | {p.price_toman:,} تومان", "plan:" + p.id)] for p in plans if available_slots(db, p)]
        rows.append([("بازگشت", "home")])
        return [emit(user_id, "<b>▦ فروشگاه نود خارج</b>\n\n" +
                     ("پلن موجود را انتخاب کنید. قیمت و ظرفیت قبل از خرید نمایش داده می‌شود." if len(rows) > 1 else
                      "در حال حاضر نودی برای فروش ثبت نشده است. پس از اضافه‌شدن سرور، موجودی اینجا به‌روزرسانی می‌شود."), kb(rows))]
    if data.startswith("plan:"):
        p = db.get(Plan, data[5:])
        if not p or not p.enabled or not available_slots(db, p):
            return [emit(user_id, "این پلن موجود نیست.", HOME)]
        rows = [[("پاسارگارد", f"runtime:{p.id}:pasarguard"),
                 ("ربکا", f"runtime:{p.id}:rebecca")],
                [("مرزبان", f"runtime:{p.id}:marzban")], [("بازگشت", "shop")]]
        return [emit(user_id, f"<b>{html.escape(p.name)}</b>\nقیمت: {p.price_toman:,} تومان\nمدت: {p.term_days} روز\nنوع پنل را انتخاب کنید:", kb(rows))]
    if data.startswith("runtime:"):
        try:
            _, pid, runtime = data.split(":")
        except ValueError:
            return [emit(user_id, "درخواست نامعتبر", HOME)]
        p = db.get(Plan, pid)
        if not p or not p.enabled or runtime not in {"pasarguard", "rebecca", "marzban"}:
            return [emit(user_id, "پلن یا پنل معتبر نیست", HOME)]
        set_state(db, user_id, "confirm_" + runtime, p.id)
        return [emit(user_id, f"<b>تأیید نهایی خرید</b>\nپلن: {html.escape(p.name)}\n" +
                     f"پنل: {runtime}\nمبلغ: {p.price_toman:,} تومان\n" +
                     "پس از پرداخت، نصب واقعی تا فعال‌شدن اتصال فنی در وضعیت آماده‌سازی خواهد بود.",
                     kb([[("تأیید و پرداخت از کیف پول", f"pay:{p.id}:{runtime}", 'success')], [("لغو", "home")]]))]
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
    if data == "mine":
        rows = db.scalars(select(Subscription).where(Subscription.user_id == user_id).order_by(
            Subscription.started_at.desc())).all()
        options = [[(f"{s.runtime_type or 'نود'} • {s.status}", "sub:" + s.id)] for s in rows]
        options.append([("بازگشت", "home")])
        return [emit(user_id, "<b>▤ سرویس‌های من</b>\n\n" +
                     ("یک سرویس را برای مشاهده مشخصات و وضعیت انتخاب کنید." if len(options) > 1 else
                      "هنوز سرویس فعالی ندارید. از فروشگاه نود موردنظر را انتخاب کنید."), kb(options))]
    if data.startswith("sub:"):
        sub = db.get(Subscription, data[4:])
        if not sub or sub.user_id != user_id:
            return [emit(user_id, "اشتراک یافت نشد", HOME)]
        slot = db.get(Slot, sub.slot_id)
        host = db.get(Host, slot.host_id)
        detail = (f"<b>اشتراک نود</b>\nنوع: {html.escape(sub.runtime_type or '')}\n" +
                  f"وضعیت: {html.escape(sub.status)}\nسرور: {html.escape(host.name)}\n" +
                  f"تاریخ پایان: {sub.ends_at.date()}\nIP: <code>{html.escape(sub.public_ip or 'در انتظار تحویل')}</code>\n" +
                  "رمز SSH یا root برای نود اشتراکی ارائه نمی‌شود.")
        actions = [[("ریستارت مشترک", "op:restart_host:" + host.id),
                    ("تغییر IP", "op:change_shared_ip:" + host.id)],
                   [("خاموش‌کردن میزبان", "op:power_off:" + host.id),
                    ("روشن‌کردن میزبان", "op:power_on:" + host.id)],
                   [("بازگشت", "mine")]]
        keyboard = kb(actions)
        if sub.public_ip:
            keyboard['inline_keyboard'].insert(0,[{
                'text': 'کپی آدرس IP', 'copy_text': {'text': sub.public_ip}}])
        return [emit(user_id, detail, keyboard)]
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
    if data == "votebox":
        ops = db.scalars(select(Operation).where(Operation.status == "pending_approval").order_by(
            Operation.created_at.desc()).limit(100)).all()
        rows = [[(f"{op.action} - {op.id[:6]}", "vinfo:" + op.id)] for op in ops
                if user_id in op.owners_snapshot and op.requester_id != user_id]
        rows.append([("بازگشت", "home")])
        return [emit(user_id, "<b>رأی‌های در انتظار شما</b>", kb(rows))]
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


async def send_message(message: dict):
    """Edit navigational callbacks in place; never edit messages sent to another user."""
    payload = dict(message)
    target_message = payload.pop("_edit_message_id", None)
    if target_message:
        payload["message_id"] = target_message
        if await telegram_request("editMessageText", payload):
            return
        payload.pop("message_id", None)
    await telegram_request("sendMessage", payload)


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
            db.add(ProcessedUpdate(update_id=data["update_id"]))
            db.commit()
        except HTTPException as exc:
            # A business-rule error should be communicated to the user rather
            # than causing Telegram to retry forever. Webhook auth is checked
            # outside this transaction and is never swallowed.
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
            db.add(ProcessedUpdate(update_id=data["update_id"]))
            db.commit()
        except Exception:
            db.rollback()
            log.exception("Telegram update handler failed (secrets redacted)")
            raise HTTPException(500, "پردازش پیام با خطا روبه‌رو شد")
    callback = data.get("callback_query") or {}
    source = callback.get("message") or {}
    origin_chat = source.get("chat") or {}
    user = callback.get("from") or {}
    # For normal navigation, edit the previously shown bot message instead of
    # producing an endless stack. Other-user notifications remain new messages.
    if outgoing and callback and origin_chat.get("id") == user.get("id"):
        if outgoing[0].get("chat_id") == user.get("id") and source.get("message_id"):
            outgoing[0]["_edit_message_id"] = source["message_id"]
    if callback.get("id"):
        await telegram_request("answerCallbackQuery", {"callback_query_id": callback["id"]})
    for item in outgoing:
        await send_message(item)
    return {"ok": True}
