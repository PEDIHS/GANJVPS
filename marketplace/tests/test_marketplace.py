from __future__ import annotations
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from urllib.parse import urlencode
from uuid import uuid4

os.environ['DATABASE_URL'] = 'sqlite:////tmp/ganj_marketplace_test_%s.db' % os.getpid()
os.environ['SESSION_SECRET'] = 'dev-test-' + '9' * 64
os.environ['ADMIN_API_KEY'] = 'test-only-' + '0' * 64
os.environ['TELEGRAM_BOT_TOKEN'] = '123456:FAKE_TEST_TOKEN'
os.environ['TELEGRAM_WEBHOOK_SECRET'] = 'a-random-test-webhook-secret'
os.environ['COOKIE_SECURE'] = 'true'

import pytest
from fastapi.testclient import TestClient
from app.models import Base, WalletEntry, Operation, OperationVote, Slot, Subscription
from app.db import engine, SessionLocal
from app.main import app
from app.auth import validate_webapp_init_data
from sqlalchemy import select, func

client = TestClient(app, base_url='https://testserver')
admin = {'X-Admin-Key': os.environ['ADMIN_API_KEY']}


def initdata(uid: int):
    user = json.dumps({'id': uid, 'first_name': 'tester'}, separators=(',', ':'), ensure_ascii=False)
    items = {'auth_date': str(int(datetime.now(timezone.utc).timestamp())), 'user': user}
    check = '\n'.join(f'{key}={value}' for key, value in sorted(items.items()))
    secret = hmac.new(b'WebAppData', os.environ['TELEGRAM_BOT_TOKEN'].encode(), hashlib.sha256).digest()
    items['hash'] = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
    return urlencode(items)


def login(uid):
    c = TestClient(app, base_url='https://testserver')
    response = c.post('/api/v1/auth/telegram', json={'init_data': initdata(uid)})
    assert response.status_code == 200, response.text
    c.headers.update({'X-CSRF-Token': c.get('/api/v1/me').json()['csrf']})
    return c


@pytest.fixture(autouse=True)
def fresh_db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    yield


def setup_host(capacity=2):
    h = client.post('/api/v1/admin/hosts', json={
        'name': 'Test Host', 'region': 'DE', 'ip': '198.51.100.2', 'capacity': capacity,
        'cpu': 3, 'ram_mb': 4096, 'reserved_ram_mb': 256, 'monthly_cost': 450000
    }, headers=admin)
    assert h.status_code == 200, h.text
    p = client.post('/api/v1/admin/plans', json={'name': 'DE Node', 'region': 'DE',
                'capacity': capacity, 'price_toman': 300000, 'term_days': 30}, headers=admin)
    assert p.status_code == 200, p.text
    return h.json()['id'], p.json()['id']


def credit(uid, value=800000):
    result = client.post('/api/v1/admin/wallet-adjustments', json={
        'user_id': uid, 'amount_toman': value, 'reason': 'test deposit',
        'reference': 'ref-' + uuid4().hex}, headers=admin)
    assert result.status_code == 200, result.text


def buy(uid, plan):
    c = login(uid)
    r = c.post('/api/v1/orders', json={'plan_id': plan, 'runtime': 'pasarguard',
                   'idempotency_key': uuid4().hex})
    assert r.status_code == 200, r.text
    return c, r.json()


def test_login_signature_tamper_and_csrf():
    content = initdata(19283)
    assert validate_webapp_init_data(content, token=os.environ['TELEGRAM_BOT_TOKEN'])['id'] == 19283
    with pytest.raises(Exception):
        validate_webapp_init_data(content.replace('19283', '19284'), token=os.environ['TELEGRAM_BOT_TOKEN'])
    c = login(19283)
    assert c.get('/api/v1/me').status_code == 200
    c.headers.pop('X-CSRF-Token')
    assert c.post('/api/v1/tickets', json={'subject': 'test title', 'message': 'detail text long'}).status_code == 403


def test_payment_is_atomic_idempotent_and_never_falsely_ready():
    _, pid = setup_host()
    credit(70001)
    c = login(70001)
    body = {'plan_id': pid, 'runtime': 'rebecca', 'idempotency_key': 'idem-operation-0001'}
    r1 = c.post('/api/v1/orders', json=body)
    r2 = c.post('/api/v1/orders', json=body)
    assert r1.status_code == r2.status_code == 200, (r1.text, r2.text)
    assert r1.json()['id'] == r2.json()['id']
    assert r2.json()['replayed'] is True
    assert r1.json()['provisioning_status'] == 'awaiting_connector'
    assert c.get('/api/v1/me').json()['balance_toman'] == 500000
    assert len(c.get('/api/v1/subscriptions').json()) == 1
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(WalletEntry).where(WalletEntry.user_id == 70001)) == 2


def test_stock_cannot_oversell():
    _, plan = setup_host(capacity=2)
    for uid in [80001, 80002, 80003]:
        credit(uid)
    buy(80001, plan)
    buy(80002, plan)
    c = login(80003)
    r = c.post('/api/v1/orders', json={'plan_id': plan, 'runtime': 'marzban',
                 'idempotency_key': 'unique-third-order'})
    assert r.status_code == 409
    assert c.get('/api/v1/me').json()['balance_toman'] == 800000


def test_unanimous_voting_and_rejection():
    host, plan = setup_host(capacity=3)
    for uid in [10001, 10002, 10003]:
        credit(uid)
    c1, _ = buy(10001, plan)
    c2, _ = buy(10002, plan)
    c3, _ = buy(10003, plan)
    op = c1.post('/api/v1/operations', json={'host_id': host, 'action': 'restart_host',
                 'reason': 'service maintenance required'})
    assert op.status_code == 200, op.text
    operation_id = op.json()['id']
    assert op.json()['status'] == 'pending_approval'
    assert c2.post(f'/api/v1/operations/{operation_id}/votes',
            json={'choice': 'approve'}).json()['status'] == 'pending_approval'
    denied = c3.post(f'/api/v1/operations/{operation_id}/votes',
            json={'choice': 'reject', 'reason': 'Busy sending data'})
    assert denied.status_code == 200 and denied.json()['status'] == 'rejected'
    assert denied.json()['executed'] is False
    assert c2.post(f'/api/v1/operations/{operation_id}/votes',
            json={'choice': 'approve'}).status_code == 409
    with SessionLocal() as db:
        operation = db.get(Operation, operation_id)
        assert operation.status == 'rejected'
        assert db.scalar(select(func.count()).select_from(OperationVote).where(
            OperationVote.operation_id == operation_id)) == 2


def test_approval_never_executes_host_action():
    host, plan = setup_host()
    for uid in [11001, 11002]: credit(uid)
    c1, _ = buy(11001, plan)
    c2, _ = buy(11002, plan)
    op = c1.post('/api/v1/operations', json={'host_id': host, 'action': 'power_off',
                 'reason': 'planned maintenance window'}).json()
    approved = c2.post(f'/api/v1/operations/{op["id"]}/votes', json={'choice': 'approve'})
    assert approved.status_code == 200
    assert approved.json() == {'id': op['id'], 'status': 'approved', 'executed': False}
    assert c2.post('/api/v1/operations', json={'host_id': host, 'action': 'power_off',
              'reason': 'unauthorized second action'}).status_code == 409


def test_wallet_adjustment_dedupes():
    body = {'user_id': 100001, 'amount_toman': 25000, 'reason': 'manual reconciled transfer',
            'reference': 'payment-test-1'}
    a = client.post('/api/v1/admin/wallet-adjustments', json=body, headers=admin)
    b = client.post('/api/v1/admin/wallet-adjustments', json=body, headers=admin)
    assert a.status_code == b.status_code == 200
    assert a.json()['id'] == b.json()['id']
    bad = dict(body, amount_toman=99999)
    assert client.post('/api/v1/admin/wallet-adjustments', json=bad, headers=admin).status_code == 409


def test_single_owner_approval_stays_disabled():
    host, plan = setup_host()
    credit(13001)
    c1, _ = buy(13001, plan)
    op = c1.post('/api/v1/operations', json={'host_id': host,
          'action': 'restart_host', 'reason': 'server route is broken'})
    assert op.status_code == 200 and op.json()['status'] == 'approved'
    assert op.json()['execution'] == 'disabled_until_provider_adapter_verified'


def test_owner_change_invalidates_previous_votes():
    host, plan = setup_host(capacity=3)
    for uid in [14001, 14002, 14003]: credit(uid)
    c1, _ = buy(14001, plan)
    c2, _ = buy(14002, plan)
    op = c1.post('/api/v1/operations', json={'host_id': host,
          'action': 'restart_host', 'reason': 'maintenance of shared host'}).json()
    buy(14003, plan)
    r = c2.post(f'/api/v1/operations/{op["id"]}/votes', json={'choice': 'approve'})
    assert r.status_code == 200 and r.json()['status'] == 'cancelled'


def test_webhook_secret_and_update_deduplication(monkeypatch):
    from app import telegram
    deliveries = []
    async def fake_send(x): deliveries.append(x)
    monkeypatch.setattr(telegram, 'send_message', fake_send)
    payload = {'update_id': 920001, 'message': {'text': '/start',
           'from': {'id': 15101, 'first_name': 'Tester'},
           'chat': {'id': 15101, 'type': 'private'}}}
    assert client.post('/telegram/webhook', json=payload).status_code == 403
    hdr = {'X-Telegram-Bot-Api-Secret-Token': os.environ['TELEGRAM_WEBHOOK_SECRET']}
    first = client.post('/telegram/webhook', json=payload, headers=hdr)
    again = client.post('/telegram/webhook', json=payload, headers=hdr)
    assert first.status_code == 200, first.text
    assert again.json()['replayed'] is True
    assert len(deliveries) == 1
    assert 'گنج VPS' in deliveries[0]['text']


def test_customer_wallet_ledger_and_admin_reporting():
    host, plan = setup_host(capacity=2)
    credit(18001, value=600000)
    customer, order = buy(18001, plan)
    ledger = customer.get('/api/v1/wallet/transactions')
    assert ledger.status_code == 200
    assert [x['delta_toman'] for x in ledger.json()] == [-300000, 600000]
    assert customer.get('/api/v1/admin/users').status_code == 403
    for route in ('users', 'orders', 'tickets', 'audit', 'finance'):
        assert customer.get('/api/v1/admin/' + route).status_code == 403
    users = client.get('/api/v1/admin/users', headers=admin)
    assert users.status_code == 200
    assert any(u['id'] == 18001 and u['balance_toman'] == 300000 for u in users.json())
    orders = client.get('/api/v1/admin/orders', headers=admin)
    assert orders.status_code == 200
    assert orders.json()[0]['id'] == order['id']
    finance = client.get('/api/v1/admin/finance', headers=admin)
    assert finance.status_code == 200
    assert finance.json()['paid_order_total_toman'] == 300000
    assert finance.json()['monthly_host_cost_toman'] == 450000
    assert finance.json()['total_wallet_liability_toman'] == 300000
    assert finance.json()['hosts'][0]['occupied'] == 1


def test_telegram_bot_account_wallet_support_and_colored_buttons():
    from app.telegram import process_update
    with SessionLocal() as db:
        uid = 18101
        message = lambda text: {'message': {'text': text, 'from': {'id': uid,
                 'first_name': 'Tester'}, 'chat': {'id': uid, 'type': 'private'}}}
        callback = lambda data: {'callback_query': {'data': data, 'from': {'id': uid},
                 'message': {'message_id': 101, 'chat': {'id': uid, 'type': 'private'}}}}
        start = process_update(db, message('/start'))
        assert 'گنج VPS' in start[0]['text']
        buttons = [b for row in start[0]['reply_markup']['inline_keyboard'] for b in row]
        assert any(x.get('style') == 'primary' for x in buttons)
        assert all(x.get('style') in (None, 'primary', 'success', 'danger') for x in buttons)
        assert 'موجودی' in process_update(db, callback('wallet'))[0]['text']
        assert 'شناسه تلگرام' in process_update(db, callback('account'))[0]['text']
        support = process_update(db, callback('newticket'))
        assert 'توضیحات' in support[0]['text']
        db.commit()  # Telegram webhook commits each processed update.
        ticket = process_update(db, message('اختلال در نود آلمان\nنود من مدتی است به پنل وصل نمی‌شود'))
        assert 'درخواست پشتیبانی ثبت شد' in ticket[0]['text']
        db.commit()
        assert db.scalar(select(func.count()).select_from(__import__('app.models',fromlist=['Ticket']).Ticket)) == 1


def test_concurrent_purchases_cannot_spend_single_wallet_balance_twice():
    from concurrent.futures import ThreadPoolExecutor
    _host, plan = setup_host(capacity=2)
    credit(17001, value=300000)
    def attempt(i):
        customer = login(17001)
        return customer.post('/api/v1/orders', json={'plan_id': plan,
            'runtime': 'pasarguard', 'idempotency_key': f'parallel-purchase-{i}-unique'}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(attempt, [1, 2]))
    assert statuses == [200, 409]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Subscription)) == 1
        assert sum(x.delta_toman for x in db.scalars(select(WalletEntry).where(WalletEntry.user_id == 17001))) == 0


def test_concurrent_host_requests_allow_only_one_pending_operation():
    from concurrent.futures import ThreadPoolExecutor
    host, plan = setup_host()
    for uid in (17101, 17102):
        credit(uid)
        buy(uid, plan)
    def attempt(i):
        customer = login(17101)
        return customer.post('/api/v1/operations', json={'host_id': host,
            'action': 'restart_host', 'reason': f'planned maintenance request number {i}'}).status_code
    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = sorted(pool.map(attempt, [1, 2]))
    assert statuses == [200, 409]
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Operation)) == 1



def test_plan_pause_edit_and_price_history():
    _, plan_id = setup_host()
    credit(21001)
    customer, order = buy(21001, plan_id)
    new_price = 450000
    updated = client.patch('/api/v1/admin/plans/' + plan_id, headers=admin,
                           json={'name': 'DE Premium', 'price_toman': new_price,
                                 'term_days': 45, 'enabled': False})
    assert updated.status_code == 200, updated.text
    plans = client.get('/api/v1/admin/plans', headers=admin).json()
    assert plans[0]['name'] == 'DE Premium'
    assert plans[0]['enabled'] is False
    assert plans[0]['price_toman'] == new_price
    assert client.get('/api/v1/catalog').json() == []
    assert customer.get('/api/v1/orders/' + order['id']).json()['amount_toman'] == 300000
    assert customer.post('/api/v1/orders', json={'plan_id': plan_id,
        'runtime': 'marzban', 'idempotency_key': 'new-purchase-disabled-plan'}).status_code == 404
    assert client.patch('/api/v1/admin/plans/' + plan_id, headers=admin,
                        json={'price_toman': -1}).status_code == 422
    assert client.patch('/api/v1/admin/plans/' + plan_id, headers=admin,
                        json={'name': None}).status_code == 422
    assert client.patch('/api/v1/admin/plans/' + plan_id, headers=admin,
                        json={'enabled': True}).json()['enabled'] is True
    assert len(client.get('/api/v1/catalog').json()) == 1


def test_support_thread_reply_status_and_customer_access():
    customer = login(22001)
    new = customer.post('/api/v1/tickets', json={
        'subject': 'Cannot connect to node',
        'message': 'Since this afternoon the node is not responding.'})
    assert new.status_code == 200
    ticket_id = new.json()['id']
    peer = login(22002)
    assert peer.get('/api/v1/tickets/' + ticket_id).status_code == 403
    assert peer.post('/api/v1/tickets/' + ticket_id + '/messages',
                     json={'message': 'I should not access this'}).status_code == 404
    assert peer.post('/api/v1/admin/tickets/' + ticket_id + '/reply',
                     json={'message': 'I am not staff'}).status_code == 403
    admin_reply = client.post('/api/v1/admin/tickets/' + ticket_id + '/reply',
                              json={'message': 'Please retry now.'}, headers=admin)
    assert admin_reply.status_code == 200, admin_reply.text
    assert admin_reply.json()['is_staff'] is True
    thread = customer.get('/api/v1/tickets/' + ticket_id).json()
    assert thread['status'] == 'answered'
    assert len(thread['messages']) == 1
    assert thread['messages'][0]['body'] == 'Please retry now.'
    user_reply = customer.post('/api/v1/tickets/' + ticket_id + '/messages',
                               json={'message': 'Still not working.'})
    assert user_reply.status_code == 200
    thread = customer.get('/api/v1/tickets/' + ticket_id).json()
    assert thread['status'] == 'waiting_support'
    assert len(thread['messages']) == 2
    assert client.patch('/api/v1/admin/tickets/' + ticket_id + '/status',
                        json={'status': 'closed'}, headers=admin).status_code == 200
    assert customer.post('/api/v1/tickets/' + ticket_id + '/messages',
                         json={'message': 'After closure'}).status_code == 409
    assert client.post('/api/v1/admin/tickets/' + ticket_id + '/reply',
                       json={'message': 'Should reopen'}, headers=admin).status_code == 409
    assert client.patch('/api/v1/admin/tickets/' + ticket_id + '/status',
                        json={'status': 'open'}, headers=admin).status_code == 200
    assert customer.post('/api/v1/tickets/' + ticket_id + '/messages',
                         json={'message': 'Reopened thread message'}).status_code == 200


def test_admin_support_and_plan_rbac_and_invalid_status():
    _, plan_id = setup_host()
    customer = login(23001)
    opened = customer.post('/api/v1/tickets', json={
        'subject': 'Subscription questions',
        'message': 'I have some questions about my subscription.'})
    tid = opened.json()['id']
    for path in ('/api/v1/admin/plans',):
        assert customer.get(path).status_code == 403
    assert customer.patch('/api/v1/admin/plans/' + plan_id,
                          json={'enabled': False}).status_code == 403
    assert customer.patch('/api/v1/admin/tickets/' + tid + '/status',
                          json={'status': 'closed'}).status_code == 403
    assert client.patch('/api/v1/admin/tickets/' + tid + '/status',
                        json={'status': 'invalid'}, headers=admin).status_code == 422
    assert client.post('/api/v1/admin/tickets/' + tid + '/reply',
                       json={'message': ' '}, headers=admin).status_code == 422
    assert len(customer.get('/api/v1/tickets/' + tid).json()['messages']) == 0
# Append the following pytest cases to marketplace/tests/test_marketplace.py
# (they reuse the module's fixtures, TestClient, SessionLocal and imports).


def test_durable_bot_outbox_marks_delivery_and_replay_dedupes(monkeypatch):
    from app import telegram
    from app.models import TelegramOutbox
    calls = []
    async def send(message):
        calls.append(message)
        return True
    monkeypatch.setattr(telegram, 'send_message', send)
    update = {'update_id': 990011, 'message': {'text': '/start',
              'from': {'id': 99001, 'first_name': 'tester'},
              'chat': {'id': 99001, 'type': 'private'}}}
    headers = {'X-Telegram-Bot-Api-Secret-Token': os.environ['TELEGRAM_WEBHOOK_SECRET']}
    assert client.post('/telegram/webhook', json=update, headers=headers).status_code == 200
    replay = client.post('/telegram/webhook', json=update, headers=headers)
    assert replay.status_code == 200 and replay.json()['replayed'] is True
    with SessionLocal() as db:
        msgs = db.scalars(select(TelegramOutbox)).all()
        assert len(msgs) == 1 and msgs[0].status == 'sent'
    assert len(calls) == 1


def test_outbox_keeps_message_until_retry_succeeds(monkeypatch):
    import asyncio
    from app import telegram
    from app.models import TelegramOutbox, utcnow
    async def fail(_): return False
    monkeypatch.setattr(telegram, 'send_message', fail)
    update = {'update_id': 990012, 'message': {'text': '/start',
              'from': {'id': 99002, 'first_name': 'tester'},
              'chat': {'id': 99002, 'type': 'private'}}}
    headers = {'X-Telegram-Bot-Api-Secret-Token': os.environ['TELEGRAM_WEBHOOK_SECRET']}
    assert client.post('/telegram/webhook', json=update, headers=headers).status_code == 200
    with SessionLocal() as db:
        msg = db.scalar(select(TelegramOutbox))
        assert msg.status == 'pending' and msg.attempts == 1
        msg.available_at = utcnow()
        db.commit()
    async def success(_): return True
    monkeypatch.setattr(telegram, 'send_message', success)
    assert asyncio.run(telegram.deliver_outbox())['sent'] == 1
    with SessionLocal() as db:
        msg = db.scalar(select(TelegramOutbox))
        assert msg.status == 'sent' and msg.attempts == 2


def test_premium_bot_menu_guide_and_safe_keyboard():
    from app.telegram import process_update
    with SessionLocal() as db:
        uid = 74001
        def msg(text):
            return {'message': {'text': text, 'from': {
                'id': uid, 'first_name': 'Customer'},
                'chat': {'id': uid, 'type': 'private'}}}
        def cb(code):
            return {'callback_query': {'data': code, 'from': {'id': uid},
                    'message': {'message_id': 31,
                                'chat': {'id': uid, 'type': 'private'}}}}
        home = process_update(db, msg('/start'))[0]
        assert 'گنج VPS' in home['text']
        assert 'موجودی کیف پول' in home['text']
        buttons = [button for row in home['reply_markup']['inline_keyboard']
                   for button in row]
        assert any(button.get('callback_data') == 'shop' and
                   button.get('style') == 'success' for button in buttons)
        assert all(button.get('style') == 'primary' for button in buttons
                   if button.get('callback_data') in {'wallet', 'mine'})
        assert not any(button.get('callback_data') == 'votebox' for button in buttons)
        assert any(button.get('callback_data') == 'guide' for button in buttons)
        assert all(len(button.get('callback_data', '')) <= 64 for button in buttons)
        guide = process_update(db, cb('guide'))[0]
        assert 'درگاه شارژ' in guide['text']
        assert 'SSH' in guide['text']


def test_premium_bot_catalog_filters_are_real_and_wallet_checkout_guard():
    from app.telegram import process_update
    _, plan = setup_host(capacity=2)
    uid = 74002
    def cb(code):
        return {'callback_query': {'data': code, 'from': {'id': uid,
                  'first_name': 'Customer'},
                'message': {'message_id': 32,
                            'chat': {'id': uid, 'type': 'private'}}}}
    with SessionLocal() as db:
        all_items = process_update(db, cb('shop'))[0]
        assert 'جمع موجودی قابل سفارش: <b>2 نود</b>' in all_items['text']
        board = all_items['reply_markup']['inline_keyboard']
        assert [r[0]['callback_data'] for r in board[:3]] == [
            'shopcat:2:0', 'shopcat:3:0', 'shopcat:all:0']
        assert [r[1]['callback_data'] for r in board[:3]] == [
            'shopcat:2:0', 'shopcat:3:0', 'shopcat:all:0']
        assert [r[0]['text'] for r in board[:3]] == ['2 عدد', '0 عدد', '2 عدد']
        assert not any(b.get('callback_data') == 'plan:' + plan
                       for row in board for b in row)
        selected = process_update(db, cb('shopcat:2:0'))[0]
        assert 'پلن‌های موجود: <b>1</b>' in selected['text']
        assert any(b.get('callback_data') == 'plan:' + plan
                   for row in selected['reply_markup']['inline_keyboard']
                   for b in row)
        assert any(b.get('style') == 'danger' for row in board
                   for b in row if 'بازگشت' in b['text'])
        empty = process_update(db, cb('shopcat:3:0'))[0]
        assert 'پلن‌های موجود: <b>0</b>' in empty['text']
        assert all(b.get('callback_data') != 'plan:' + plan
                   for row in empty['reply_markup']['inline_keyboard'] for b in row)
        detail = process_update(db, cb('plan:' + plan))[0]
        assert '300,000 تومان' in detail['text']
        confirm = process_update(db, cb('runtime:' + plan + ':rebecca'))[0]
        assert 'اعتبار کیف پول کافی نیست' in confirm['text']
        assert 'pay:' not in str(confirm['reply_markup'])
        # Bot shows real billing, not invented inventory or instant activation.
        assert 'تحویل آنی' in confirm['text']
        db.commit()
    credit(uid)
    with SessionLocal() as db:
        process_update(db, cb('plan:' + plan))
        confirmed = process_update(db, cb('runtime:' + plan + ':rebecca'))[0]
        actions = [b.get('callback_data', '') for row in confirmed['reply_markup']['inline_keyboard']
                   for b in row]
        assert 'pay:' + plan + ':rebecca' in actions
        assert '800,000 تومان' in confirmed['text']


def test_premium_bot_owner_reporting_and_customer_access_boundary():
    from app.telegram import process_update
    from app.config import config
    owner = config.owner_id
    assert owner > 0
    with SessionLocal() as db:
        def cb(uid, action):
            return {'callback_query': {'data': action, 'from': {
                    'id': uid, 'first_name': 'Tester'},
                    'message': {'message_id': 37,
                                'chat': {'id': uid, 'type': 'private'}}}}
        denied = process_update(db, cb(74003, 'admin:finance'))
        assert 'دسترسی مجاز نیست' in denied[0]['text']
        admin_screen = process_update(db, cb(owner, 'admin'))[0]
        assert 'گنج VPS' in admin_screen['text']
        admin_report = process_update(db, cb(owner, 'admin:finance'))[0]
        assert 'نه سود خالص' in admin_report['text']
        users = process_update(db, cb(owner, 'admin:users'))[0]
        assert 'کاربران ثبت‌شده' in users['text']


def test_premium_bot_user_display_name_escaped():
    from app.telegram import process_update
    uid = 74004
    with SessionLocal() as db:
        start = {'message': {'text': '/start', 'from': {
            'id': uid, 'first_name': '<script>alert(1)</script>'},
            'chat': {'id': uid, 'type': 'private'}}}
        process_update(db, start)
        out = process_update(db, {'callback_query': {'data': 'account',
                      'from': {'id': uid}, 'message': {'message_id': 19,
                      'chat': {'id': uid, 'type': 'private'}}}})[0]
        assert '<script>' not in out['text']
        assert '&lt;script&gt;' in out['text']


def test_shop_inventory_category_counts_unique_slots_across_price_plans():
    from app.telegram import process_update
    _, pid = setup_host(capacity=2)
    another = client.post('/api/v1/admin/plans',
                          json={'name': 'DE Second Price', 'region': 'DE',
                                'capacity': 2, 'price_toman': 250000, 'term_days': 30},
                          headers=admin)
    assert another.status_code == 200
    uid = 74301
    with SessionLocal() as db:
        update = {'callback_query': {'data': 'shop', 'from': {'id': uid},
                  'message': {'message_id': 40,
                              'chat': {'id': uid, 'type': 'private'}}}}
        result = process_update(db, update)[0]
        rows = result['reply_markup']['inline_keyboard']
        # The same two physical slots are offered under two price plans.
        # Total must not be doubled to four.
        assert rows[0][0]['text'] == '2 عدد'
        assert rows[1][0]['text'] == '0 عدد'
        assert rows[2][0]['text'] == '2 عدد'
        assert len(rows[0]) == len(rows[1]) == len(rows[2]) == 2
        assert all(row[0]['callback_data'] == row[1]['callback_data']
                   for row in rows[:3])
        assert rows[-1][0]['style'] == 'danger'
        selected = process_update(db, {'callback_query': {
            **update['callback_query'], 'data': 'shopcat:2:0'}})[0]
        listed = [b for row in selected['reply_markup']['inline_keyboard']
                  for b in row if b.get('callback_data', '').startswith('plan:')]
        assert len(listed) == 4  # 2 buttons per price plan
        assert 'پلن‌های موجود: <b>2</b>' in selected['text']


def test_shared_requests_are_scoped_to_each_owned_service():
    from app.telegram import process_update
    from app.models import Host, Plan, Slot, Subscription
    first_host, first_plan = setup_host(capacity=2)
    second_host = client.post('/api/v1/admin/hosts', json={
        'name': 'France Test Host', 'region': 'FR',
        'ip': '198.51.100.77', 'capacity': 2, 'cpu': 3,
        'ram_mb': 4096, 'reserved_ram_mb': 256, 'monthly_cost': 250000
    }, headers=admin)
    assert second_host.status_code == 200
    second_host_id = second_host.json()['id']
    second_plan = client.post('/api/v1/admin/plans', json={
        'name': 'France Shared', 'region': 'FR', 'capacity': 2,
        'price_toman': 300000, 'term_days': 30
    }, headers=admin)
    assert second_plan.status_code == 200
    for uid in (74311, 74312, 74313):
        credit(uid, 1000000)
    buyer1, _ = buy(74311, first_plan)
    buyer2, _ = buy(74312, first_plan)
    buy(74311, second_plan.json()['id'])
    buyer3, _ = buy(74313, second_plan.json()['id'])
    op1 = buyer2.post('/api/v1/operations', json={
        'host_id': first_host, 'action': 'restart_host',
        'reason': 'Host one maintenance needed.'})
    op2 = buyer3.post('/api/v1/operations', json={
        'host_id': second_host_id, 'action': 'change_shared_ip',
        'reason': 'Host two address change.'})
    assert op1.status_code == op2.status_code == 200, (op1.text, op2.text)
    def cb(uid, data):
        return {'callback_query': {'data': data, 'from': {'id': uid},
                    'message': {'message_id': 62,
                                'chat': {'id': uid, 'type': 'private'}}}}
    with SessionLocal() as db:
        services = db.scalars(select(Subscription).where(
            Subscription.user_id == 74311)).all()
        host_to_sub = {db.get(Slot, s.slot_id).host_id: s for s in services}
        first = host_to_sub[first_host]
        second = host_to_sub[second_host_id]
        assert 'votebox' not in str(process_update(db, cb(74311, 'home'))[0]['reply_markup'])
        subpage = process_update(db, cb(74311, 'sub:' + first.id))[0]
        assert any(b.get('callback_data') == 'shared:' + first.id
                   for row in subpage['reply_markup']['inline_keyboard'] for b in row)
        scope_a = process_update(db, cb(74311, 'shared:' + first.id))[0]
        assert op1.json()['id'][:6] in str(scope_a['reply_markup'])
        assert op2.json()['id'][:6] not in str(scope_a['reply_markup'])
        scope_b = process_update(db, cb(74311, 'shared:' + second.id))[0]
        assert op2.json()['id'][:6] in str(scope_b['reply_markup'])
        assert op1.json()['id'][:6] not in str(scope_b['reply_markup'])
        denied = process_update(db, cb(74312, 'shared:' + second.id))[0]
        assert 'در دسترس نیست' in denied['text']
        assert 'shared:' + second.id not in str(denied['reply_markup'])


def test_telegram_button_color_for_all_return_paths():
    from app.telegram import kb, navigation, home_keyboard
    assert kb([[('انصراف', 'home')]])['inline_keyboard'][0][0]['style'] == 'danger'
    assert kb([[('بازگشت', 'shop')]])['inline_keyboard'][0][0]['style'] == 'danger'
    assert kb(navigation('shop'))['inline_keyboard'][0][0]['style'] == 'danger'
    menu = [b for row in home_keyboard(74321)['inline_keyboard'] for b in row]
    assert next(b for b in menu if b.get('callback_data') == 'shop')['style'] == 'success'
    assert next(b for b in menu if b.get('callback_data') == 'wallet')['style'] == 'primary'
    assert next(b for b in menu if b.get('callback_data') == 'mine')['style'] == 'primary'


def test_category_rtl_visual_order_contract():
    from app.telegram import catalog_view
    with SessionLocal() as db:
        text, keyboard = catalog_view(db)
        rows = keyboard['inline_keyboard']
        assert len(rows) >= 3
        # On Telegram clients, first button currently renders to the left
        # and second to the right. User-verified RTL contract: count LEFT, title RIGHT.
        for row, category in zip(rows[:3], ('2','3','all')):
            assert len(row) == 2
            assert row[0]['text'].endswith(' عدد')
            assert row[1]['callback_data'] == 'shopcat:' + category + ':0'
            assert row[0]['callback_data'] == row[1]['callback_data']
        assert 'دو نفره' in rows[0][1]['text']
        assert 'سه نفره' in rows[1][1]['text']
        assert 'همه نودها' in rows[2][1]['text']

def test_admin_provisioning_queue_is_readonly_and_restricted():
    _, plan = setup_host(capacity=2)
    credit(76001)
    client_user, order = buy(76001, plan)
    denied = client_user.get('/api/v1/admin/provisioning/jobs')
    assert denied.status_code == 403
    r = client.get('/api/v1/admin/provisioning/jobs', headers=admin)
    assert r.status_code == 200
    payload = r.json()
    assert payload['execution_enabled'] is False
    assert payload['runtimes']['pasarguard']['status'] == 'trial_needed'
    assert payload['runtimes']['rebecca']['status'] == 'poc_needed'
    assert payload['runtimes']['marzban']['status'] == 'poc_needed'
    assert len(payload['jobs']) == 1
    assert payload['jobs'][0]['order_id'] == order['id']
    assert client_user.get('/api/v1/admin/provisioning/orders/' + order['id'] +
                           '/preflight').status_code == 403


def test_pasarguard_preflight_fails_closed_without_trial_agent():
    _, plan = setup_host(capacity=2)
    credit(76002)
    _, order = buy(76002, plan)
    with SessionLocal() as db:
        from app.models import PortLease, ProvisionJob
        from app.provisioning import preflight_order
        job = db.scalar(select(ProvisionJob).where(ProvisionJob.order_id == order['id']))
        before = db.query(PortLease).count()
        result = preflight_order(db, order['id'])
        assert result.runtime == 'pasarguard'
        assert result.allowed_to_execute is False
        assert result.candidate_ports == (30000, 30001)
        assert result.memory_mb == 1920
        assert 'host_not_enrolled_as_trial' in result.blocked_by
        assert 'authenticated_trial_agent_missing' in result.blocked_by
        assert 'pinned_installer_and_agent_executor_not_integrated' in result.blocked_by
        assert 'production_safety_interlock_active' in result.blocked_by
        assert db.query(PortLease).count() == before
        assert db.get(ProvisionJob, job.id).state == 'awaiting_connector'
        assert result.admin_view()['allowed_to_execute'] is False
        assert 'private_ip' not in result.admin_view()
    resp = client.get('/api/v1/admin/provisioning/orders/' + order['id'] +
                      '/preflight', headers=admin)
    assert resp.status_code == 200
    assert resp.json()['proposed_service_ports'] == [30000, 30001]
    assert 'no node has been installed' in resp.json()['note'].lower()


def test_provisioning_candidate_ports_skip_db_lease_and_live_bound_ports():
    from app.models import PortLease, Host, Slot
    from app.provisioning import candidate_port_pair, preflight_order, Probe
    host, plan = setup_host(capacity=3)
    credit(76003)
    _, order = buy(76003, plan)
    class VerifiedFake:
        def verify(self, _):
            return Probe(reachable=True, trial_agent_verified=True,
                         os_id='ubuntu', architecture='x86_64',
                         cgroup_v2=True, docker_available=True,
                         bound_tcp_ports=frozenset({30002,30003}))
    with SessionLocal() as db:
        h = db.get(Host, host)
        h.capabilities = {'purpose': 'trial-node'}
        db.add(PortLease(host_id=host, slot_id=db.scalar(
            select(Slot.id).where(Slot.host_id == host).limit(1)),
            ip=h.ip, protocol='tcp', port=30000, purpose='service'))
        db.commit()
        assert candidate_port_pair(db, h, frozenset({30002,30003})) == (30004,30005)
        check = preflight_order(db, order['id'], VerifiedFake())
        assert check.candidate_ports == (30004,30005)
        assert 'authenticated_trial_agent_missing' not in check.blocked_by
        assert 'production_safety_interlock_active' in check.blocked_by
        assert check.allowed_to_execute is False
        # Read-only preflight cannot reserve or install any ports.
        assert db.query(PortLease).count() == 1


def test_rebecca_and_marzban_require_independent_runtime_poc():
    from app.provisioning import preflight_order
    for number, runtime in enumerate(('rebecca', 'marzban')):
        _, plan = setup_host(capacity=2)
        buyer = 76010 + number
        credit(buyer)
        session = login(buyer)
        result = session.post('/api/v1/orders', json={
            'plan_id': plan, 'runtime': runtime,
            'idempotency_key': 'trial-poc-' + runtime})
        assert result.status_code == 200, result.text
        with SessionLocal() as db:
            preflight = preflight_order(db, result.json()['id'])
            assert 'runtime_coexistence_poc_not_approved' in preflight.blocked_by
            assert not preflight.allowed_to_execute


def test_bot_provisioning_owner_summary_is_informational_only():
    from app.telegram import process_update
    from app.config import config
    with SessionLocal() as db:
        def cb(uid, action):
            return {'callback_query': {'data': action, 'from': {'id': uid},
                         'message': {'message_id': 68,
                                     'chat': {'id': uid, 'type': 'private'}}}}
        denied = process_update(db, cb(77010, 'admin:provisioning'))[0]
        assert 'دسترسی مجاز نیست' in denied['text']
        owner = process_update(db, cb(config.owner_id, 'admin:provisioning'))[0]
        assert 'مرکز نصب و تحویل نودها' in owner['text']
        assert 'فرمان نصب واقعی صادر نمی‌شود' in owner['text']
        menu = process_update(db, cb(config.owner_id, 'admin'))[0]
        assert any(b.get('callback_data') == 'admin:provisioning'
                   for row in menu['reply_markup']['inline_keyboard'] for b in row)


def test_bot_scoped_staff_permissions_prevent_admin_data_leaks():
    from app.telegram import process_update
    from app.models import AdminPermission
    from app.services import user_get_or_create
    staff = 78001
    with SessionLocal() as db:
        user_get_or_create(db, staff, 'Staff')
        db.add(AdminPermission(user_id=staff, permission='tickets.read',
                               department='support'))
        db.commit()
        def cb(action):
            return {'callback_query': {'data': action, 'from': {'id': staff},
                      'message': {'message_id': 88,
                                  'chat': {'id': staff, 'type': 'private'}}}}
        home = process_update(db, cb('home'))[0]
        assert any(b.get('callback_data') == 'admin'
                   for row in home['reply_markup']['inline_keyboard'] for b in row)
        menu = process_update(db, cb('admin'))[0]
        actions = {b.get('callback_data') for row in menu['reply_markup']['inline_keyboard']
                   for b in row}
        assert 'admin:tickets' in actions
        assert 'admin:finance' not in actions
        assert 'admin:provisioning' not in actions
        assert 'admin:users' not in actions
        view = process_update(db, cb('admin:tickets'))[0]
        assert 'درخواست‌های پشتیبانی' in view['text']
        for forbidden in ('admin:finance', 'admin:users',
                          'admin:provisioning', 'admin:orders'):
            assert 'دسترسی مجاز نیست' in process_update(db, cb(forbidden))[0]['text']
        # Restricting the staff member or removing their permission takes
        # effect immediately; no cached menu authorization remains.
        row = db.get(AdminPermission, (staff, 'tickets.read'))
        db.delete(row)
        db.commit()
        assert 'دسترسی مجاز نیست' in process_update(db, cb('admin:tickets'))[0]['text']


def test_catalog_taxonomy_links_datacenter_location_real_hosts_and_skus():
    host_id, plan_id = setup_host(capacity=2)
    dc = client.post('/api/v1/admin/catalog/datacenters',
                     headers=admin, json={'name':'Hetzner', 'slug':'hetzner'})
    assert dc.status_code == 200, dc.text
    did = dc.json()['id']
    duplicate = client.post('/api/v1/admin/catalog/datacenters',
                      headers=admin, json={'name':'Other','slug':'hetzner'})
    assert duplicate.status_code == 422
    location = client.post('/api/v1/admin/catalog/locations',
                           headers=admin, json={'datacenter_id':did,
                            'country_code':'DE','country_name':'آلمان','city':'Falkenstein'})
    assert location.status_code == 200, location.text
    lid = location.json()['id']
    h = client.put('/api/v1/admin/catalog/hosts/'+host_id+'/placement',headers=admin,
                   json={'location_id':lid,'bandwidth_gb':5000,'os_family':'linux'})
    assert h.status_code == 200, h.text
    p = client.put('/api/v1/admin/catalog/plans/'+plan_id+'/placement',
                   headers=admin,json={'location_id':lid,'min_vcpu':1,
                     'min_ram_mb':1024,'min_traffic_gb':1000,'os_family':'linux'})
    assert p.status_code == 200, p.text
    plans = client.get('/api/v1/admin/catalog/plans',headers=admin).json()
    assert plans[0]['stock'] == 2
    assert plans[0]['datacenter'] == 'Hetzner'
    catalog = client.get('/api/v1/catalog').json()
    assert catalog[0]['available'] == 2
    from app.telegram import process_update
    with SessionLocal() as db:
        cb = lambda code: {'callback_query':{
            'data':code, 'from':{'id':99991},'message':{
            'message_id':1,'chat':{'id':99991,'type':'private'}}}}
        start = process_update(db,cb('xcat:home'))[0]
        assert 'دیتاسنتر' in str(start)
        choices = process_update(db,cb('xcat:dc'))[0]
        assert 'Hetzner' in str(choices)
        selected = process_update(db,cb('xcat:dcid:'+did))[0]
        assert 'DE Node' in str(selected)
        detail = process_update(db,cb('plan:'+plan_id))[0]
        assert 'Falkenstein' in detail['text']
        assert '1000 GB' in detail['text']
    credit(99991)
    buyer, order = buy(99991,plan_id)
    assert order['status']=='paid'
    assert len(client.get('/api/v1/catalog').json()) == 1
    assert client.get('/api/v1/catalog').json()[0]['available'] == 1


def test_catalog_ensures_physical_capacity_and_location_isolation():
    host1, plan = setup_host(capacity=2)
    h2 = client.post('/api/v1/admin/hosts',headers=admin,
      json={'name':'Other DE host','region':'DE','ip':'198.51.100.43','capacity':2,
            'cpu':2,'ram_mb':4096,'reserved_ram_mb':256,'monthly_cost':300000})
    assert h2.status_code == 200
    host2 = h2.json()['id']
    dc1 = client.post('/api/v1/admin/catalog/datacenters',headers=admin,
       json={'name':'Hetzner','slug':'hetzner'}).json()['id']
    dc2 = client.post('/api/v1/admin/catalog/datacenters',headers=admin,
       json={'name':'Vultr','slug':'vultr'}).json()['id']
    def loc(dc,city):
      r=client.post('/api/v1/admin/catalog/locations',headers=admin,
       json={'datacenter_id':dc,'country_code':'DE','country_name':'Germany','city':city})
      assert r.status_code == 200,r.text
      return r.json()['id']
    loc1=loc(dc1,'Frankfurt')
    loc2=loc(dc2,'Berlin')
    for host,location in ((host1,loc1),(host2,loc2)):
      assert client.put('/api/v1/admin/catalog/hosts/'+host+'/placement',
       headers=admin,json={'location_id':location,'bandwidth_gb':4000}).status_code==200
    url='/api/v1/admin/catalog/plans/'+plan+'/placement'
    assert client.put(url,headers=admin,json={'location_id':loc1,
       'min_vcpu':2,'min_ram_mb':1024}).status_code == 200
    assert client.get('/api/v1/catalog').json()[0]['available']==0  # CPU=3/2, <2 vCPU each
    assert client.put(url,headers=admin,json={'location_id':loc1,
       'min_vcpu':1,'min_ram_mb':2048}).status_code == 200
    assert client.get('/api/v1/catalog').json()[0]['available']==0  # 4096 - 256 <2*2048
    assert client.put(url,headers=admin,json={'location_id':loc1,
       'min_vcpu':1,'min_ram_mb':1024}).status_code == 200
    assert client.get('/api/v1/catalog').json()[0]['available']==2
    credit(99992,600000)
    buyer,order=buy(99992,plan)
    with SessionLocal() as db:
        from app.models import Slot
        assert db.get(Slot,db.scalar(select(Subscription).where(
               Subscription.order_id==order['id'])).slot_id).host_id==host1
    # Disabling a datacenter stops new sales from this location (old order untouched).
    stop=client.patch('/api/v1/admin/catalog/datacenters/'+dc1,headers=admin,
                      json={'enabled':False})
    assert stop.status_code==200
    assert client.get('/api/v1/catalog').json()[0]['available']==0
    assert buyer.get('/api/v1/orders/'+order['id']).status_code==200


def test_catalog_access_scope_and_country_guard():
    host,plan=setup_host()
    customer=login(99994)
    for url in ('/api/v1/admin/catalog/datacenters',
                '/api/v1/admin/catalog/hosts','/api/v1/admin/catalog/plans'):
       assert customer.get(url).status_code==403
    dc=client.post('/api/v1/admin/catalog/datacenters',headers=admin,
      json={'name':'Provider','slug':'provider'}).json()['id']
    loc=client.post('/api/v1/admin/catalog/locations',headers=admin,
      json={'datacenter_id':dc,'country_code':'US','country_name':'USA','city':'New York'}).json()['id']
    invalid=client.put('/api/v1/admin/catalog/hosts/'+host+'/placement',
       headers=admin,json={'location_id':loc})
    assert invalid.status_code==422
    invalid=client.put('/api/v1/admin/catalog/plans/'+plan+'/placement',
       headers=admin,json={'location_id':loc})
    assert invalid.status_code==422


def test_bot_admin_browses_real_datacenters_locations_and_hosts():
    from app.telegram import process_update
    from app.config import config
    host, plan = setup_host(capacity=2)
    dc = client.post('/api/v1/admin/catalog/datacenters', headers=admin,
        json={'name':'Hetzner', 'slug':'hetzner'}).json()['id']
    loc = client.post('/api/v1/admin/catalog/locations', headers=admin,
        json={'datacenter_id':dc,'country_code':'DE','country_name':'Germany',
              'city':'Falkenstein'}).json()['id']
    assert client.put('/api/v1/admin/catalog/hosts/'+host+'/placement',
        headers=admin,json={'location_id':loc,'bandwidth_gb':2500}).status_code==200
    def cb(uid,action):
      return {'callback_query':{'data':action,'from':{'id':uid},
        'message':{'message_id':3,'chat':{'id':uid,'type':'private'}}}}
    with SessionLocal() as db:
        admin_main=process_update(db,cb(config.owner_id,'admin:catalog'))[0]
        assert 'adcat:dc' in str(admin_main['reply_markup'])
        listing=process_update(db,cb(config.owner_id,'adcat:dc'))[0]
        assert 'Hetzner' in str(listing['reply_markup'])
        places=process_update(db,cb(config.owner_id,'adcat:dcid:'+dc))[0]
        assert 'Falkenstein' in str(places['reply_markup'])
        detail=process_update(db,cb(config.owner_id,'adcat:locid:'+loc))[0]
        assert 'Test Host' in detail['text']
        assert '4096 MB' in detail['text']
        denied=process_update(db,cb(88909,'adcat:dc'))[0]
        assert 'دسترسی مجاز نیست' in denied['text']
