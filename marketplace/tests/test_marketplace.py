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
