import os, re, csv, io, time, json
from datetime import date, datetime, timedelta
from functools import wraps
from dateutil.relativedelta import relativedelta
from flask import Flask, request, jsonify, session, send_from_directory, Response, redirect, current_app
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, inspect
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()
FRONT = os.path.join(os.path.dirname(__file__), "..", "frontend")

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(60), unique=True, nullable=False)
    name = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # owner | trainer
    pw_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, default=True)
    mobile = db.Column(db.String(10))  # recovery number for OTP reset

class Customer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    mobile = db.Column(db.String(10), nullable=False, index=True)
    months = db.Column(db.Integer, nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False, index=True)
    total_price = db.Column(db.Numeric(12, 2), nullable=False)
    monthly_fee = db.Column(db.Numeric(12, 2))
    closed = db.Column(db.String(12))  # Completed | Withdrawn | None
    renewals = db.Column(db.Integer, default=0)
    notes = db.Column(db.Text)
    trainer_id = db.Column(db.Integer, db.ForeignKey("user.id"), index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    payments = db.relationship("Payment", backref="customer", order_by="Payment.pay_date")

class Payment(db.Model):  # append-only ledger; refunds are negative rows
    id = db.Column(db.Integer, primary_key=True)
    customer_id = db.Column(db.Integer, db.ForeignKey("customer.id"), nullable=False, index=True)
    amount = db.Column(db.Numeric(12, 2), nullable=False)
    pay_date = db.Column(db.Date, nullable=False, index=True)
    method = db.Column(db.String(20), nullable=False)
    kind = db.Column(db.String(10), default="payment")  # payment | refund | renewal
    idem_key = db.Column(db.String(64), unique=True)
    trainer_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    action = db.Column(db.String(60))
    detail = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Otp(db.Model):  # one-time passwords are stored hashed, expire in 5 minutes, allow 5 tries
    id = db.Column(db.Integer, primary_key=True)
    purpose = db.Column(db.String(10), index=True)
    mobile = db.Column(db.String(10), index=True)
    code_hash = db.Column(db.String(64))
    attempts = db.Column(db.Integer, default=0)
    used = db.Column(db.Boolean, default=False)
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Setting(db.Model):
    key = db.Column(db.String(40), primary_key=True)
    value = db.Column(db.Text)

METHODS = {"cash", "upi", "card", "bank_transfer", "other"}
f = float

def today_ist():  # gym runs on India time even if the server clock is UTC
    return (datetime.utcnow() + timedelta(hours=5, minutes=30)).date()
DEFAULTS = dict(monthly_fee=10000, min_months=3, base_pay=1000, rate=30, bonus_rate=35, bonus_target=100000)

def cfg():
    out = dict(DEFAULTS)
    for x in Setting.query.all(): out[x.key] = json.loads(x.value)
    return out

def audit(action, detail):
    db.session.add(AuditLog(user_id=session.get("uid"), action=action, detail=detail))

def paid(c): return sum(f(p.amount) for p in c.payments)

def status(c, today=None):
    today = today or today_ist()
    if c.closed: return c.closed
    if f(c.total_price) - paid(c) > 0.005: return "Pending Payment"
    if c.end_date < today: return "Expired"
    if (c.end_date - today).days <= 7: return "Expiring Soon"
    return "Active"

def cust_json(c):
    p = paid(c); last = c.payments[-1].pay_date if c.payments else None
    tr = db.session.get(User, c.trainer_id) if c.trainer_id else None
    return dict(id=c.id, name=c.name, mobile=c.mobile, start=str(c.start_date), end=str(c.end_date),
        months=c.months, total=f(c.total_price), paid=p, outstanding=max(f(c.total_price) - p, 0),
        monthly=round(f(c.total_price) / c.months, 2), last_payment=str(last) if last else None,
        status=status(c), closed=c.closed or "", days_left=(c.end_date - today_ist()).days, renewals=c.renewals or 0,
        trainer=tr.name if tr else "", created=c.created_at.date().isoformat(), notes=c.notes,
        payments=[dict(id=x.id, amount=f(x.amount), date=str(x.pay_date), method=x.method, kind=x.kind) for x in c.payments])

def login_required(role=None):
    def deco(fn):
        @wraps(fn)
        def w(*a, **k):
            u = db.session.get(User, session.get("uid")) if session.get("uid") else None
            if not u or not u.active: return jsonify(error="Login required"), 401
            if role and u.role != role: return jsonify(error="Forbidden"), 403
            return fn(*a, **k)
        return w
    return deco

def admin_required(fn):  # owner must re-enter username + password to open Admin (valid 15 min)
    def chk(*a, **k):
        if session.get("admin_until", 0) < time.time():
            return jsonify(error="Enter your owner password to open Admin", locked=True), 403
        return fn(*a, **k)
    chk.__name__ = fn.__name__
    return login_required("owner")(chk)

def parse_date(s):
    try: return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception: return None

def validate_payment(d):
    try: amt = round(float(d.get("amount")), 2)
    except Exception: return None, "Amount must be a number"
    if amt <= 0: return None, "Amount must be positive"
    if d.get("method") not in METHODS: return None, "Invalid payment method"
    pd = parse_date(d.get("date", ""))
    if not pd: return None, "Invalid payment date"
    return (amt, pd), None

import hashlib, hmac, secrets

def otp_hash(purpose, mobile, code):
    return hmac.new(current_app.config["SECRET_KEY"].encode(), f"{purpose}:{mobile}:{code}".encode(), hashlib.sha256).hexdigest()

def send_sms(mobile, text):
    prov = os.environ.get("SMS_PROVIDER", "").lower()
    if prov == "twilio":  # add other providers (MSG91, Fast2SMS...) here
        import base64, urllib.parse, urllib.request
        sid, tok, frm = os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"], os.environ["TWILIO_FROM"]
        req = urllib.request.Request(f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                                     data=urllib.parse.urlencode({"To": "+91" + mobile, "From": frm, "Body": text}).encode())
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{sid}:{tok}".encode()).decode())
        urllib.request.urlopen(req, timeout=10); return "sent"
    if os.environ.get("FLASK_ENV") != "production":
        print(f"\n[DEV ONLY - no SMS provider set] {text}  (for {mobile})\n", flush=True); return "console"
    raise RuntimeError("SMS provider is not configured on this server")

def check_otp(purpose, mobile, code):
    row = Otp.query.filter_by(purpose=purpose, mobile=mobile, used=False).order_by(Otp.id.desc()).first()
    if not row or row.expires_at < datetime.utcnow(): return None, "OTP expired or not found. Please request a new one."
    if row.attempts >= 5: return None, "Too many wrong attempts. Please request a new OTP."
    if not hmac.compare_digest(row.code_hash, otp_hash(purpose, mobile, str(code).strip())):
        row.attempts += 1; db.session.commit(); return None, f"Wrong OTP. {5 - row.attempts} attempts left."
    row.used = True; return row, None

_attempts = {}  # per-process; use Redis-backed Flask-Limiter if you scale to many workers

def create_app(db_url=None):
    if os.environ.get("FLASK_ENV") == "production" and not os.environ.get("SECRET_KEY"): raise RuntimeError("Set SECRET_KEY")
    app = Flask(__name__, static_folder=None)
    app.config.update(SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-key"),
        SQLALCHEMY_DATABASE_URI=db_url or os.environ.get("DATABASE_URL", "sqlite:///dev.db").replace("postgres://", "postgresql://"),
        PERMANENT_SESSION_LIFETIME=timedelta(hours=12), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True})
    if os.environ.get("FLASK_ENV") == "production":
        from werkzeug.middleware.proxy_fix import ProxyFix
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # real client IP behind the host proxy
    db.init_app(app)
    with app.app_context():
        db.create_all()
        cols = [c["name"] for c in inspect(db.engine).get_columns("customer")]
        for col, typ in (("monthly_fee", "NUMERIC(12,2)"), ("closed", "VARCHAR(12)")):
            if col not in cols: db.session.execute(db.text(f"ALTER TABLE customer ADD COLUMN {col} {typ}")); db.session.commit()
        if "mobile" not in [c["name"] for c in inspect(db.engine).get_columns("user")]:
            db.session.execute(db.text('ALTER TABLE "user" ADD COLUMN mobile VARCHAR(10)')); db.session.commit()
        for c in Customer.query.filter(Customer.monthly_fee.is_(None)).all(): c.monthly_fee = f(c.total_price) / c.months
        db.session.commit()

    @app.before_request
    def csrf():  # custom header blocks cross-site form posts
        if request.method in ("POST", "PATCH", "DELETE") and request.headers.get("X-Requested-With") != "gym":
            return jsonify(error="Bad request"), 400

    @app.cli.command("create-admin")
    def create_admin():
        import getpass
        u = input("Owner username: "); pw = getpass.getpass("Password (min 10 chars): ")
        assert len(pw) >= 10
        m = re.sub(r"\D", "", input("Recovery mobile (10 digits, optional): "))[-10:]
        db.session.add(User(username=u, name=u, role="owner", mobile=m or None, pw_hash=generate_password_hash(pw))); db.session.commit()
        print("Owner created.")

    @app.post("/api/login")
    def login():
        d = request.get_json(silent=True) or {}; ip = request.remote_addr
        tries = [t for t in _attempts.get(ip, []) if time.time() - t < 300]
        if len(tries) >= 8: return jsonify(error="Too many attempts. Try again in 5 minutes."), 429
        u = User.query.filter_by(username=str(d.get("username", "")).strip()).first()
        if not u or not u.active or not check_password_hash(u.pw_hash, str(d.get("password", ""))):
            _attempts[ip] = tries + [time.time()]; return jsonify(error="Wrong username or password"), 401
        if d.get("role") != u.role:
            return jsonify(error=f"This is a {u.role} account. Choose {u.role.title()} to sign in."), 403
        session.clear(); session["uid"] = u.id; session.permanent = True
        return jsonify(id=u.id, name=u.name, role=u.role)

    @app.get("/api/signup-info")
    def signup_info(): return jsonify(open=User.query.filter_by(role="owner").first() is None)

    def mob(d): return re.sub(r"\D", "", str(d.get("mobile", "")))[-10:]

    @app.post("/api/otp/send")
    def otp_send():
        d = request.get_json(silent=True) or {}; purpose = d.get("purpose"); mobile = mob(d)
        if purpose not in ("signup", "reset", "mobile"): return jsonify(error="Bad request"), 400
        if not re.fullmatch(r"[6-9]\d{9}", mobile): return jsonify(error="Enter a valid 10-digit mobile number"), 400
        if purpose == "mobile":
            me_ = db.session.get(User, session["uid"]) if session.get("uid") else None
            if not me_ or me_.role != "owner": return jsonify(error="Login required"), 401
            if User.query.filter(User.mobile == mobile, User.id != me_.id).first(): return jsonify(error="This number is used by another account"), 409
        elif purpose == "signup":  # one-time: only while no owner exists
            if User.query.filter_by(role="owner").first(): return jsonify(error="An owner account already exists. Use Forgot username or password."), 403
            allowed = os.environ.get("OWNER_MOBILE", "").strip()[-10:]
            if allowed and mobile != allowed: return jsonify(error="This number is not allowed to create the owner account"), 403
            if not str(d.get("name", "")).strip(): return jsonify(error="Enter your name"), 400
        ipk = "otp" + str(request.remote_addr); tries = [t for t in _attempts.get(ipk, []) if time.time() - t < 900]
        if len(tries) >= 8 or Otp.query.filter(Otp.mobile == mobile, Otp.created_at > datetime.utcnow() - timedelta(minutes=15)).count() >= 3:
            return jsonify(error="Too many OTP requests. Try again in 15 minutes."), 429
        _attempts[ipk] = tries + [time.time()]
        if purpose == "reset" and not User.query.filter_by(role="owner", mobile=mobile).first():
            return jsonify(ok=True, ttl=300)  # same reply either way, so numbers cannot be guessed
        code = f"{secrets.randbelow(1000000):06d}"
        db.session.add(Otp(purpose=purpose, mobile=mobile, code_hash=otp_hash(purpose, mobile, code), expires_at=datetime.utcnow() + timedelta(minutes=5))); db.session.commit()
        try: how = send_sms(mobile, f"PKD GYM OTP: {code}. Valid for 5 minutes. Do not share it with anyone.")
        except Exception as e:
            app.logger.error("SMS failed: %s", e); return jsonify(error="Could not send the SMS. Check the SMS settings on the server."), 502
        return jsonify(ok=True, ttl=300, dev=(how == "console"))

    @app.post("/api/signup")  # one-time owner creation, verified by mobile OTP
    def signup():
        d = request.get_json(silent=True) or {}; mobile = mob(d); name, uname, pw = str(d.get("name", "")).strip(), str(d.get("username", "")).strip(), str(d.get("password", ""))
        if User.query.filter_by(role="owner").first(): return jsonify(error="An owner account already exists."), 403
        allowed = os.environ.get("OWNER_MOBILE", "").strip()[-10:]
        if allowed and mobile != allowed: return jsonify(error="This number is not allowed to create the owner account"), 403
        if not name or len(uname) < 3 or len(pw) < 10: return jsonify(error="Enter your name, a username (3+ characters) and a password (10+ characters)"), 400
        if User.query.filter_by(username=uname).first(): return jsonify(error="Username taken"), 409
        row, err = check_otp("signup", mobile, d.get("otp", ""))
        if err: return jsonify(error=err), 400
        u = User(username=uname, name=name, role="owner", mobile=mobile, pw_hash=generate_password_hash(pw)); db.session.add(u)
        db.session.add(AuditLog(action="account.signup", detail="Owner account created by mobile OTP")); db.session.commit()
        session.clear(); session["uid"] = u.id; session.permanent = True
        return jsonify(id=u.id, name=u.name, role=u.role), 201

    @app.post("/api/reset")  # forgot username/password: new ones set after mobile OTP
    def reset():
        d = request.get_json(silent=True) or {}; mobile = mob(d); uname, pw = str(d.get("username", "")).strip(), str(d.get("password", ""))
        if len(uname) < 3 or len(pw) < 10: return jsonify(error="Username must be 3+ characters and password 10+ characters"), 400
        target = User.query.filter_by(role="owner", mobile=mobile).first()
        row, err = check_otp("reset", mobile, d.get("otp", ""))
        if err or not target: return jsonify(error=err or "Wrong OTP."), 400
        if User.query.filter(User.username == uname, User.id != target.id).first(): db.session.rollback(); return jsonify(error="Username taken"), 409
        target.username = uname; target.pw_hash = generate_password_hash(pw)
        db.session.add(AuditLog(user_id=target.id, action="account.reset", detail="Owner username and password reset by mobile OTP")); db.session.commit()
        return jsonify(ok=True)

    @app.get("/api/account")
    @login_required("owner")
    def account():
        u = db.session.get(User, session["uid"]); return jsonify(username=u.username, mobile=("xxxxxx" + u.mobile[-4:]) if u.mobile else "")

    @app.post("/api/account/mobile")
    @login_required("owner")
    def account_mobile():
        d = request.get_json(silent=True) or {}; mobile = mob(d); u = db.session.get(User, session["uid"])
        if User.query.filter(User.mobile == mobile, User.id != u.id).first(): return jsonify(error="This number is used by another account"), 409
        row, err = check_otp("mobile", mobile, d.get("otp", ""))
        if err: return jsonify(error=err), 400
        u.mobile = mobile; audit("account.mobile", "Recovery mobile changed|Owner recovery mobile number was updated"); db.session.commit()
        return jsonify(ok=True)

    @app.post("/api/logout")
    def logout(): session.clear(); return jsonify(ok=True)

    @app.get("/api/me")
    @login_required()
    def me():
        u = db.session.get(User, session["uid"]); return jsonify(id=u.id, name=u.name, role=u.role)

    @app.get("/api/customers")
    @login_required()
    def customers():
        q = (request.args.get("q") or "").strip().lower()
        rows = [cust_json(c) for c in Customer.query.order_by(Customer.id.desc()).all()]
        if q: rows = [r for r in rows if q in r["name"].lower() or q in r["mobile"]]
        return jsonify(rows)

    @app.get("/api/customers/<int:cid>")
    @login_required()
    def customer(cid): return jsonify(cust_json(db.get_or_404(Customer, cid)))

    @app.get("/api/config")
    @login_required()
    def config():
        c = cfg(); return jsonify(monthly_fee=c["monthly_fee"], min_months=c["min_months"])

    @app.post("/api/admin/verify")
    @login_required("owner")
    def admin_verify():
        d = request.get_json(silent=True) or {}; u = db.session.get(User, session["uid"]); k = "adm" + str(request.remote_addr)
        tries = [t for t in _attempts.get(k, []) if time.time() - t < 300]
        if len(tries) >= 5: return jsonify(error="Too many attempts. Try again in 5 minutes."), 429
        if str(d.get("username", "")).strip() != u.username or not check_password_hash(u.pw_hash, str(d.get("password", ""))):
            _attempts[k] = tries + [time.time()]; return jsonify(error="Wrong owner username or password"), 401
        session["admin_until"] = time.time() + 900; return jsonify(ok=True)

    @app.route("/api/settings", methods=["GET", "POST"])
    @admin_required
    def settings():
        if request.method == "POST":
            d = request.get_json(silent=True) or {}
            try:
                new = dict(monthly_fee=float(d["monthly_fee"]), min_months=int(d["min_months"]), base_pay=float(d["base_pay"]),
                           rate=float(d["rate"]), bonus_rate=float(d["bonus_rate"]), bonus_target=float(d["bonus_target"]))
            except Exception: return jsonify(error="Check the values you entered"), 400
            if (new["monthly_fee"] <= 0 or not 1 <= new["min_months"] <= 60 or new["base_pay"] < 0 or new["bonus_target"] <= 0
                    or not 0 <= new["rate"] <= 100 or not 0 <= new["bonus_rate"] <= 100):
                return jsonify(error="Fee and target must be above 0, months 1-60, rates 0-100%"), 400
            for k, v in new.items():
                x = db.session.get(Setting, k) or Setting(key=k); x.value = json.dumps(v); db.session.add(x)
            audit("settings.update", json.dumps(new)); db.session.commit()
        return jsonify(cfg())

    @app.get("/api/updates")
    @login_required("owner")
    def updates():
        names = {u.id: u.name for u in User.query.all()}
        rows = AuditLog.query.order_by(AuditLog.id.desc()).limit(200).all()
        return jsonify([dict(id=r.id, who=names.get(r.user_id, "System"), action=r.action, detail=r.detail, at=r.created_at.isoformat() + "Z") for r in rows])

    @app.get("/api/overview")
    @login_required()
    def overview():
        me = db.session.get(User, session["uid"]); mine = me.role == "trainer"  # trainers see only their own customers' numbers
        today = today_ist(); year = request.args.get("year", type=int) or today.year
        custs = [c for c in Customer.query.all() if not mine or c.trainer_id == me.id]
        pays = [p for p in Payment.query.all() if not mine or p.trainer_id == me.id]
        live = [c for c in custs if not c.closed]
        rev = lambda y, m: sum(f(p.amount) for p in pays if p.pay_date.year == y and p.pay_date.month == m)
        def due_at(cs, d=None):
            t = 0
            for c in cs:
                if d and c.start_date > d: continue
                t += max(f(c.total_price) - sum(f(p.amount) for p in c.payments if not d or p.pay_date <= d), 0)
            return t
        chg = lambda a, b: None if not b else round((a - b) / b * 100)
        lm = today.replace(day=1) - timedelta(1); exp_now = sum(1 for c in live if c.end_date < today)
        last = today.month if year == today.year else (12 if year < today.year else 0); rows = []
        for m in range(last, 0, -1):
            j = [c for c in custs if c.start_date.year == year and c.start_date.month == m]; jl = [c for c in j if not c.closed]
            rows.append(dict(month=date(year, m, 1).strftime("%b %Y"), joined=len(j), revenue=rev(year, m), due=due_at(jl), expired=sum(1 for c in jl if c.end_date < today)))
        q = AuditLog.query.filter(AuditLog.action.in_(["customer.create", "payment.edit", "membership.renew", "payment.refund", "customer.status"]))
        if mine: q = q.filter(AuditLog.user_id == me.id)
        act = [dict(kind=a.action, text=a.detail, at=a.created_at.isoformat() + "Z") for a in q.order_by(AuditLog.id.desc()).limit(15)]
        act += [dict(kind="expired", text=f"Membership expired|{c.name}'s membership expired", at=str(c.end_date)) for c in live if today - timedelta(14) <= c.end_date < today]
        years = sorted({c.start_date.year for c in custs} | {p.pay_date.year for p in pays} | {today.year}, reverse=True)
        return jsonify(years=years, year=year, total=len(custs), revenue_month=rev(today.year, today.month), month_label=today.strftime("%b %Y"),
            due=due_at(live), expired=exp_now, rows=rows, activity=sorted(act, key=lambda x: x["at"], reverse=True)[:15], scoped=mine,
            delta=dict(customers=chg(len(custs), sum(1 for c in custs if c.start_date <= lm)), revenue=chg(rev(today.year, today.month), rev(lm.year, lm.month)),
                       due=chg(due_at(live), due_at(live, lm)), expired=chg(exp_now, sum(1 for c in live if c.end_date < lm))))

    @app.post("/api/customers")
    @login_required()
    def add_customer():
        d = request.get_json(silent=True) or {}; s = cfg()
        name = str(d.get("name", "")).strip(); mobile = re.sub(r"\D", "", str(d.get("mobile", "")))[-10:]
        if not name: return jsonify(error="Name is required"), 400
        if not re.fullmatch(r"[6-9]\d{9}", mobile): return jsonify(error="Enter a valid 10-digit mobile number"), 400
        try: months = int(d.get("months"))
        except Exception: months = 0
        if not s["min_months"] <= months <= 60: return jsonify(error=f"Minimum {s['min_months']} months required"), 400
        try: amt = round(float(d.get("amount")), 2)
        except Exception: amt = 0
        if amt <= 0: return jsonify(error="Amount must be above 0"), 400
        fee = s["monthly_fee"]; total = round(fee * months, 2)
        if amt > total: return jsonify(error=f"Amount is more than the price for {months} months ({total:,.0f})"), 400
        if not d.get("confirm_duplicate") and Customer.query.filter_by(mobile=mobile).first():
            return jsonify(error="A customer with this mobile already exists", duplicate=True), 409
        key = d.get("idem_key")
        if key and Payment.query.filter_by(idem_key=key).first(): return jsonify(error="Already submitted"), 409
        today = today_ist()
        c = Customer(name=name, mobile=mobile, months=months, start_date=today, end_date=today + relativedelta(months=months),
                     total_price=total, monthly_fee=fee, trainer_id=session["uid"])
        db.session.add(c); db.session.flush()
        db.session.add(Payment(customer_id=c.id, amount=amt, pay_date=today, method="cash", idem_key=key, trainer_id=session["uid"]))
        audit("customer.create", f"New member registered|{name} joined the gym"); db.session.commit()
        return jsonify(cust_json(c)), 201

    @app.post("/api/customers/<int:cid>/close")
    @login_required("owner")
    def close_customer(cid):
        c = db.get_or_404(Customer, cid); v = (request.get_json(silent=True) or {}).get("status", "")
        if v not in ("", "Completed", "Withdrawn"): return jsonify(error="Invalid status"), 400
        c.closed = v or None; audit("customer.status", f"{'Marked ' + v if v else 'Reopened'}|{c.name}"); db.session.commit()
        return jsonify(cust_json(c))

    @app.post("/api/customers/<int:cid>/payments")
    @login_required()
    def add_payment(cid):
        c = db.get_or_404(Customer, cid); d = request.get_json(silent=True) or {}
        pay, err = validate_payment(d)
        if err: return jsonify(error=err), 400
        amt, pd = pay
        if amt > f(c.total_price) - paid(c) + 0.005: return jsonify(error="Payment exceeds outstanding balance"), 400
        key = d.get("idem_key")
        if key and Payment.query.filter_by(idem_key=key).first(): return jsonify(error="Already submitted"), 409
        db.session.add(Payment(customer_id=c.id, amount=amt, pay_date=pd, method=d["method"], idem_key=key, trainer_id=session["uid"]))
        audit("payment.add", f"customer={c.id} amount={amt}"); db.session.commit()
        db.session.refresh(c); return jsonify(cust_json(c)), 201

    @app.post("/api/customers/<int:cid>/refund")
    @login_required("owner")
    def refund(cid):
        c = db.get_or_404(Customer, cid); d = request.get_json(silent=True) or {}
        pay, err = validate_payment(d)
        if err: return jsonify(error=err), 400
        if pay[0] > paid(c): return jsonify(error="Refund exceeds amount paid"), 400
        db.session.add(Payment(customer_id=c.id, amount=-pay[0], pay_date=pay[1], method=d["method"], kind="refund", trainer_id=session["uid"]))
        audit("payment.refund", f"customer={c.id} amount={pay[0]}"); db.session.commit()
        db.session.refresh(c); return jsonify(cust_json(c))

    @app.post("/api/customers/<int:cid>/renew")
    @login_required()
    def renew(cid):
        c = db.get_or_404(Customer, cid); d = request.get_json(silent=True) or {}
        pay, err = validate_payment(d)
        if err: return jsonify(error=err), 400
        try: months = int(d.get("months"))
        except Exception: months = 0
        if not 1 <= months <= 60: return jsonify(error="Duration must be 1-60 months"), 400
        c.end_date = max(c.end_date, today_ist()) + relativedelta(months=months)
        c.months += months; c.renewals = (c.renewals or 0) + 1
        c.total_price = f(c.total_price) + round(float(d.get("total_price") or pay[0]), 2)
        db.session.add(Payment(customer_id=c.id, amount=pay[0], pay_date=pay[1], method=d["method"], kind="renewal", trainer_id=session["uid"]))
        audit("membership.renew", f"customer={c.id} months={months}"); db.session.commit()
        db.session.refresh(c); return jsonify(cust_json(c))

    @app.patch("/api/customers/<int:cid>")
    @login_required("owner")
    def edit_customer(cid):
        c = db.get_or_404(Customer, cid); d = request.get_json(silent=True) or {}; s = cfg()
        def bad(m): db.session.rollback(); return jsonify(error=m), 400
        cur_paid = paid(c)
        if "name" in d:
            n = str(d["name"]).strip()
            if not n: return bad("Name is required")
            audit("customer.edit", f"id={cid} name: {c.name!r} -> {n!r}"); c.name = n
        if "mobile" in d:
            m = re.sub(r"\D", "", str(d["mobile"]))[-10:]
            if not re.fullmatch(r"[6-9]\d{9}", m): return bad("Enter a valid 10-digit mobile number")
            audit("customer.edit", f"id={cid} mobile: {c.mobile} -> {m}"); c.mobile = m
        if "months" in d:
            try: m = int(d["months"])
            except Exception: m = 0
            if not s["min_months"] <= m <= 60: return bad(f"Minimum {s['min_months']} months required")
            rate = f(c.monthly_fee or s["monthly_fee"])
            audit("customer.edit", f"id={cid} months: {c.months} -> {m}")
            c.months = m; c.end_date = c.start_date + relativedelta(months=m); c.total_price = round(rate * m, 2)
        if "closed" in d:
            v = str(d["closed"] or "")
            if v not in ("", "Completed", "Withdrawn"): return bad("Invalid status")
            if v != (c.closed or ""): audit("customer.status", f"{'Marked ' + v if v else 'Reopened'}|{c.name}"); c.closed = v or None
        new_paid = cur_paid
        if "paid" in d:
            try: new_paid = round(float(d["paid"]), 2)
            except Exception: return bad("Paid must be a number")
            if new_paid < 0: return bad("Paid cannot be negative")
        if new_paid > f(c.total_price) + 0.005: return bad(f"Paid is more than the price ({f(c.total_price):,.0f})")
        diff = round(new_paid - cur_paid, 2)
        if diff:
            db.session.add(Payment(customer_id=c.id, amount=diff, pay_date=today_ist(), method="cash",
                                   kind="payment" if diff > 0 else "correction", trainer_id=session["uid"]))
            audit("payment.edit", f"{'Payment received' if diff > 0 else 'Payment corrected'}|₹{abs(diff):,.0f} {'from' if diff > 0 else 'for'} {c.name}")
        db.session.commit(); db.session.refresh(c); return jsonify(cust_json(c))

    @app.get("/api/payments")
    @login_required("owner")
    def payments():
        s = cfg(); rows = db.session.query(Payment, Customer).join(Customer).order_by(Payment.pay_date.desc(), Payment.id.desc()).all()
        cur = today_ist().strftime("%Y-%m")
        avail = sorted({p.pay_date.strftime("%Y-%m") for p, _ in rows} | {cur}, reverse=True)
        m = request.args.get("month") or cur
        sel = [(p, c) for p, c in rows if p.pay_date.strftime("%Y-%m") == m]
        tx = [dict(id=p.id, customer=c.name, amount=f(p.amount), date=str(p.pay_date), method=p.method, kind=p.kind) for p, c in sel]
        out = []
        for u in User.query.filter_by(role="trainer"):
            col = sum(f(p.amount) for p, _ in sel if p.trainer_id == u.id)
            joined = sum(1 for c in Customer.query.filter_by(trainer_id=u.id) if c.start_date.strftime("%Y-%m") == m)
            if not u.active: continue  # removed trainers are hidden from payroll
            pct = s["bonus_rate"] if col >= s["bonus_target"] else s["rate"]
            comm = round(max(col, 0) * pct / 100, 2)
            out.append(dict(id=u.id, name=u.name, joined=joined, collected=col, pct=pct, commission=comm, base=s["base_pay"], payout=round(s["base_pay"] + comm, 2)))
        return jsonify(month=m, months=avail, total=sum(t["amount"] for t in tx), tx=tx, trainers=out, rate=s["rate"], bonus_rate=s["bonus_rate"], bonus_target=s["bonus_target"])

    @app.get("/api/dashboard")
    @login_required("owner")
    def dashboard():
        today = today_ist(); r = request.args.get("range", "month"); first = today.replace(day=1)
        spans = {"today": (today, today), "7d": (today - timedelta(6), today), "30d": (today - timedelta(29), today),
                 "month": (first, today), "prev": (first - relativedelta(months=1), first - timedelta(1)),
                 "year": (today.replace(month=1, day=1), today)}
        a, b = spans.get(r) or (parse_date(request.args.get("from", "")) or first, parse_date(request.args.get("to", "")) or today)
        span = (b - a).days + 1; pa, pb = a - timedelta(span), a - timedelta(1)
        trainer, method = request.args.get("trainer", type=int), request.args.get("method")
        def pq(x, y):
            q = db.session.query(func.coalesce(func.sum(Payment.amount), 0)).filter(Payment.pay_date.between(x, y))
            if trainer: q = q.filter(Payment.trainer_id == trainer)
            if method: q = q.filter(Payment.method == method)
            return f(q.scalar())
        cq = Customer.query
        if trainer: cq = cq.filter_by(trainer_id=trainer)
        custs = cq.all(); n = len(custs); sts = [status(c) for c in custs]
        cnt = {s: sts.count(s) for s in ("Active", "Expiring Soon", "Expired", "Pending Payment")}
        billed = sum(f(c.total_price) for c in custs); got = sum(paid(c) for c in custs)
        new = sum(1 for c in custs if a <= c.created_at.date() <= b); pnew = sum(1 for c in custs if pa <= c.created_at.date() <= pb)
        rev, prev = pq(a, b), pq(pa, pb)
        eligible = [c for c in custs if c.end_date <= today or c.renewals]; renewed = sum(1 for c in eligible if c.renewals)
        def pct(x, y): return round(100 * x / y, 1) if y else 0
        months = []
        for i in range(11, -1, -1):
            m0 = first - relativedelta(months=i); m1 = m0 + relativedelta(months=1) - timedelta(1)
            months.append(dict(label=m0.strftime("%b %Y"), revenue=pq(m0, m1), customers=sum(1 for c in custs if m0 <= c.created_at.date() <= m1)))
        dist = [dict(label=l, count=sum(1 for c in custs if lo <= (c.end_date - today).days <= hi))
                for l, lo, hi in (("Expired", -99999, -1), ("0-3d", 0, 3), ("4-7d", 4, 7), ("8-30d", 8, 30), ("30d+", 31, 99999))]
        return jsonify(range=[str(a), str(b)], n=n, counts=cnt, new=new, prev_new=pnew, revenue=rev, prev_revenue=prev,
            total_revenue=got, billed=billed, outstanding=max(billed - got, 0), avg_rev=round(got / n, 2) if n else 0,
            renewed=renewed, eligible=len(eligible),
            pct=dict(active=pct(cnt["Active"], n), expired=pct(cnt["Expired"], n), new=pct(new, n),
                     renewal=pct(renewed, len(eligible)), collection=pct(got, billed), outstanding=pct(max(billed - got, 0), billed),
                     growth=pct(rev - prev, prev)), months=months, dist=dist)

    @app.get("/api/notifications")
    @login_required()
    def notifications():
        out = []
        for c in Customer.query.all():
            dl = (c.end_date - today_ist()).days
            if dl <= 7 and not c.closed:
                out.append(dict(customer_id=c.id, name=c.name, mobile=c.mobile, days_left=dl,
                    text="Expired" if dl < 0 else "Expires today" if dl == 0 else f"Expires in {dl} day(s)"))
        return jsonify(sorted(out, key=lambda x: x["days_left"]))

    @app.route("/api/trainers", methods=["GET", "POST"])
    @admin_required
    def trainers():
        if request.method == "POST":
            d = request.get_json(silent=True) or {}
            if len(str(d.get("password", ""))) < 8 or not d.get("username") or not d.get("name"):
                return jsonify(error="Name, username and password (8+ chars) required"), 400
            if User.query.filter_by(username=d["username"]).first(): return jsonify(error="Username taken"), 409
            db.session.add(User(username=d["username"].strip(), name=d["name"].strip(), role="trainer", pw_hash=generate_password_hash(d["password"])))
            audit("trainer.create", d["username"]); db.session.commit()
        return jsonify([dict(id=u.id, name=u.name, username=u.username, active=u.active) for u in User.query.filter_by(role="trainer")])

    @app.post("/api/trainers/<int:uid>/toggle")
    @admin_required
    def toggle(uid):
        u = db.get_or_404(User, uid); u.active = not u.active; audit("trainer.toggle", f"{uid}={u.active}"); db.session.commit()
        return jsonify(ok=True)

    @app.get("/api/export/<kind>.csv")
    @login_required("owner")
    def export(kind):
        s = io.StringIO(); w = csv.writer(s)
        if kind == "customers":
            w.writerow(["ID", "Name", "Mobile", "Start", "End", "Months", "Total", "Paid", "Outstanding", "Status", "Trainer"])
            for c in map(cust_json, Customer.query.all()): w.writerow([c[k] for k in ("id", "name", "mobile", "start", "end", "months", "total", "paid", "outstanding", "status", "trainer")])
        else:
            w.writerow(["ID", "Customer", "Amount", "Date", "Method", "Kind"])
            for p, c in db.session.query(Payment, Customer).join(Customer): w.writerow([p.id, c.name, f(p.amount), p.pay_date, p.method, p.kind])
        return Response(s.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={kind}.csv"})

    admin_path = "/" + os.environ.get("ADMIN_PATH", "admin").strip("/")  # set ADMIN_PATH to hide the owner link

    def page(portal):
        html = open(os.path.join(FRONT, "index.html"), encoding="utf-8").read().replace("<!--PORTAL-->", f'<script>window.PORTAL="{portal}"</script>')
        return Response(html, mimetype="text/html", headers={"Cache-Control": "no-store"})
    app.add_url_rule(admin_path, "admin_page", lambda: page("owner"))
    app.add_url_rule("/trainer", "trainer_page", lambda: page("trainer"))

    @app.get("/")
    def root(): return redirect("/trainer")

    @app.get("/manifest.json")
    def manifest():
        return jsonify(name="PKD GYM", short_name="PKD GYM", start_url=admin_path if request.args.get("p") == "owner" else "/trainer", scope="/",
                       display="standalone", background_color="#070912", theme_color="#070912",
                       icons=[dict(src="/icon-192.png", sizes="192x192", type="image/png", purpose="any"), dict(src="/icon-512.png", sizes="512x512", type="image/png", purpose="any"), dict(src="/icon.svg", sizes="any", type="image/svg+xml")])

    @app.get("/<path:p>")
    def static_files(p): return send_from_directory(FRONT, p)
    return app


if __name__ == "__main__":
    create_app().run(debug=True)
