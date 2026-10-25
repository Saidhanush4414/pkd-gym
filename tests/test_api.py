import sys, os; sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import pytest
from datetime import date
from werkzeug.security import generate_password_hash
from app import create_app, db, User

H = {"X-Requested-With": "gym"}
@pytest.fixture
def client():
    app = create_app("sqlite:///:memory:")
    with app.app_context():
        db.session.add(User(username="boss", name="Boss", role="owner", pw_hash=generate_password_hash("ownerpass123")))
        db.session.add(User(username="t1", name="T1", role="trainer", pw_hash=generate_password_hash("trainerpass1"))); db.session.commit()
    return app.test_client()
def login(c, u, p): return c.post("/api/login", json={"username": u, "password": p, "role": "owner" if u == "boss" else "trainer"}, headers=H)
CUST = dict(name="Ravi", mobile="9876543210", months=3, amount=30000, method="upi", date=str(date.today()))

def test_auth_and_permissions(client):
    assert client.get("/api/me").status_code == 401
    assert login(client, "t1", "bad").status_code == 401
    login(client, "t1", "trainerpass1")
    assert client.get("/api/dashboard").status_code == 403
    assert client.get("/api/payments").status_code == 403

def test_customer_payment_flow(client):
    login(client, "t1", "trainerpass1")
    r = client.post("/api/customers", json={**CUST, "amount": 27000}, headers=H); assert r.status_code == 201
    c = r.get_json(); assert c["outstanding"] == 3000 and c["status"] == "Pending Payment" and c["monthly"] == 10000
    assert client.post("/api/customers", json=CUST, headers=H).status_code == 409
    assert client.post(f"/api/customers/{c['id']}/payments", json={**CUST, "amount": 7000}, headers=H).status_code == 400
    r = client.post(f"/api/customers/{c['id']}/payments", json={**CUST, "amount": 3000}, headers=H).get_json()
    assert r["outstanding"] == 0 and r["status"] == "Active"

def test_validation_and_dashboard(client):
    login(client, "t1", "trainerpass1")
    assert client.post("/api/customers", json={**CUST, "mobile": "123"}, headers=H).status_code == 400
    assert client.post("/api/customers", json={**CUST, "amount": -5}, headers=H).status_code == 400
    client.post("/api/customers", json=CUST, headers=H); client.post("/api/logout", headers=H)
    login(client, "boss", "ownerpass123")
    d = client.get("/api/dashboard?range=month").get_json()
    assert d["n"] == 1 and d["revenue"] == 30000 and d["pct"]["active"] == 100

def test_trainer_payroll_and_admin_gate(client):
    login(client, "t1", "trainerpass1")
    client.post("/api/customers", json=CUST, headers=H); client.post("/api/logout", headers=H)
    login(client, "boss", "ownerpass123")
    assert client.get("/api/settings").status_code == 403
    assert client.post("/api/admin/verify", json={"username": "boss", "password": "x"}, headers=H).status_code == 401
    assert client.post("/api/admin/verify", json={"username": "boss", "password": "ownerpass123"}, headers=H).status_code == 200
    assert client.get("/api/settings").status_code == 200
    t = client.get("/api/payments").get_json()["trainers"][0]
    assert t["collected"] == 30000 and t["pct"] == 30 and t["payout"] == 1000 + 9000

def test_signup_closed_when_owner_exists(client):
    r = client.post("/api/signup", json={"name": "X", "username": "xyz", "password": "longpassword1"}, headers=H)
    assert r.status_code == 403

def test_reset_with_mobile_otp(client):
    from datetime import datetime, timedelta
    from app import Otp, otp_hash
    with client.application.app_context():
        db.session.get(User, 1).mobile = "9876543210"
        db.session.add(Otp(purpose="reset", mobile="9876543210", code_hash=otp_hash("reset", "9876543210", "123456"), expires_at=datetime.utcnow() + timedelta(minutes=5))); db.session.commit()
    body = {"mobile": "9876543210", "username": "boss2", "password": "newpassword12"}
    assert client.post("/api/reset", json={**body, "otp": "000000"}, headers=H).status_code == 400
    assert client.post("/api/reset", json={**body, "otp": "123456"}, headers=H).status_code == 200
    assert client.post("/api/login", json={"username": "boss2", "password": "newpassword12", "role": "owner"}, headers=H).status_code == 200
    assert client.post("/api/reset", json={**body, "otp": "123456"}, headers=H).status_code == 400  # OTP is single-use
