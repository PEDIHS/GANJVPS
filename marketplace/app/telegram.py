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
                        BotState, ProcessedUpdate)
from app.services import (user_get_or_create, available_slots, get_balance,
                         request_operation, vote, owner_ids, purchase)

log = logging.getLogger("ganj.telegram")


def kb(rows):
    return {"inline_keyboard": [[{"text": title, "callback_data": action} for title, action in row] for row in rows]}

HOME = kb([[('خرید نود', 'shop'), ('سرویس‌های من', 'mine')],
           [('کیف پول', 'wallet'), ('درخواست‌های مشترک', 'votebox')]])


if config.public_base_url.startswith("https://"):
    HOME["inline_keyboard"].append([{"text": "پنل پیشرفته", "web_app": {"url": config.public_base_url}}])


def menu_message(uid: int, db):
    active = db.scalar(select(func.count()).select_from(Subscription).where(
        Subscription.user_id == uid, Subscription.status.in_(["active", "provisioning"]))) or 0
    return f"<b>گنج VPS | داشبورد</b>\nسرویس‌های شما: {active}\nموجودی کیف پول: {get_balance(db, uid):,} تومان\nبرای ادامه یک گزینه انتخاب کنید."


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
    content = message.get("text", "")
    if content.startswith("/start") or data == "home":
        clear_state(db, user_id)
        return [emit(user_id, menu_message(user_id, db), HOME)]
    if content == "/admin":
        if user_id != config.owner_id:
            return [emit(user_id, "دسترسی مدیریت ندارید.", HOME)]
        return [emit(user_id, "<b>مدیریت گنج VPS</b>\nتنظیمات سرورها، محصولات و مالی از پنل امن وب انجام می‌شود.\n" +
                     html.escape(config.public_base_url), HOME)]
    if data == "wallet":
        return [emit(user_id, f"موجودی فعلی: <b>{get_balance(db, user_id):,} تومان</b>\nشارژ موجودی صرفاً پس از تأیید پرداخت مجاز ثبت می‌شود.", HOME)]
    if data == "shop":
        plans = db.scalars(select(Plan).where(Plan.enabled == True).order_by(Plan.price_toman)).all()
        rows = [[(f"{p.name} | {p.price_toman:,} تومان", "plan:" + p.id)] for p in plans if available_slots(db, p)]
        rows.append([("بازگشت", "home")])
        return [emit(user_id, "<b>خرید نود خارج</b>\nپلن موردنظر را انتخاب کنید:", kb(rows))]
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
                     kb([[("تأیید و پرداخت از کیف پول", f"pay:{p.id}:{runtime}")], [("لغو", "home")]]))]
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
        return [emit(user_id, "<b>اشتراک‌های من</b>", kb(options))]
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
        actions = [[("درخواست ریستارت سرور مشترک", "op:restart_host:" + host.id)],
                   [("درخواست تغییر IP مشترک", "op:change_shared_ip:" + host.id)],
                   [("بازگشت", "mine")]]
        return [emit(user_id, detail, kb(actions))]
    if data.startswith("op:"):
        try:
            _, action, host_id = data.split(":")
        except ValueError:
            return [emit(user_id, "درخواست نامعتبر", HOME)]
        if action not in {"restart_host", "change_shared_ip"} or user_id not in owner_ids(db, host_id):
            return [emit(user_id, "این اقدام برای شما مجاز نیست", HOME)]
        set_state(db, user_id, "operation_" + action, host_id)
        return [emit(user_id, "دلیل درخواست را در یک پیام بنویسید (حداقل ۸ کاراکتر).\n" +
                     "این دلیل برای سایر مالکان همان سرور ارسال می‌شود.")]
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
                     kb([[("تأیید", "va:" + op.id), ("رد با دلیل", "vr:" + op.id)]]))]
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
    return [emit(user_id, "گزینه مورد نظر را از منوی اصلی انتخاب کنید.", HOME)]


async def send_message(message: dict):
    if not config.telegram_bot_token:
        return
    url = f"https://api.telegram.org/bot{config.telegram_bot_token}/sendMessage"
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(url, json=message)
            response.raise_for_status()
    except httpx.HTTPError:
        log.warning("Telegram delivery failed; check outgoing bot connectivity")


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
    for item in outgoing:
        await send_message(item)
    return {"ok": True}
