# PKD GYM — Gym Management (Flask + PostgreSQL + installable PWA)

Flask serves both the REST API (`/api/*`) and the PWA frontend (`frontend/`), so one deployment gives web + Android install.

## Run locally
    cd backend && python -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
    cp ../.env.example ../.env   # set SECRET_KEY; omit DATABASE_URL to use local SQLite (dev only)
    export FLASK_APP=app:create_app && flask create-admin    # creates the owner (prompts; nothing hardcoded)
    flask run          # http://localhost:5000
    cd .. && pytest tests

## Deploy (free tiers; check current limits)
1. Push to GitHub: `git init && git add . && git commit -m "init" && git remote add origin <url> && git push -u origin main`
2. Create a managed PostgreSQL (Neon, Supabase or Render Postgres). Copy its connection string.
3. Create a web service (e.g. Render) from the repo: root `backend`, build `pip install -r requirements.txt`, start `gunicorn wsgi:app`.
   Env vars: `SECRET_KEY`, `DATABASE_URL`, `FLASK_ENV=production`.
4. Open the service shell and run `FLASK_APP=app:create_app flask create-admin`.
5. Visit the HTTPS URL; on Android Chrome use "Install app". Free web tiers usually sleep when idle (slow first load); free databases have storage caps and some expire — check your provider.

## Backups
`pg_dump "$DATABASE_URL" > backup.sql` ; restore: `psql "$DATABASE_URL" < backup.sql`. Prefer provider-managed backups.

## Known limitations
- Tables are created with `create_all`; add Alembic/Flask-Migrate before schema changes in production.
- Login rate-limit is per-process memory; use Redis-backed Flask-Limiter for multiple workers.
- Dashboard "refreshes" on filter change/tab open (no websockets). No offline entry queue (offline shows an error; nothing is faked as saved).
- Retention = renewed customers / customers whose term ended or who renewed. Notifications are in-app only.
- Edit is limited to name/notes with audit log; price/discount corrections are not yet implemented. Trainer-owned views are not restricted per trainer.
- 3D look is CSS tilt + glass panels, not WebGL.

## GitHub + Supabase (PostgreSQL) + Render
1. Push: `git init && git add . && git commit -m "ironledger" && git branch -M main && git remote add origin https://github.com/YOU/REPO.git && git push -u origin main`
2. Supabase: create a project, open *Connect*, copy the **Session pooler** URI (works on IPv4 hosts like Render's free tier). Replace `[YOUR-PASSWORD]`; if it starts with `postgres://` that is fine.
3. Render: New > Blueprint > pick the repo (uses `render.yaml`). Set `DATABASE_URL` (Supabase URI) `OWNER_MOBILE` (your 10-digit number; only it can create the owner) and the SMS settings below. `SECRET_KEY` is generated.
4. Open `https://YOUR-SITE/admin`, click *Create owner account*, enter your mobile, then the OTP. Tables are created automatically on first start.
5. On Android Chrome: menu > Install app.
Free tiers sleep when idle and have storage limits: check Render and Supabase for current limits.

## Separate links
- Trainers: `https://YOUR-SITE/trainer` (the site root opens it too). Admin/Owner: `https://YOUR-SITE/admin` (set `ADMIN_PATH` to change it). Each page accepts only its own role.

## Mobile OTP (owner sign-up and recovery)
- Owner account is created **once** with an OTP texted to the owner's mobile. After that, sign-up disappears. If the owner forgets the username or password: Admin page > *Forgot username or password?* > mobile OTP > set a new username and password. Trainers are managed by the owner in Admin.
- SMS needs a provider. Set `SMS_PROVIDER=twilio`, `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM` (add others in `send_sms`). Check your provider's rules for sending to Indian numbers (sender registration may be required). Without a provider, online (production) OTP is refused; locally the OTP is printed in the terminal for testing.
- Owners created before this version have no recovery number: sign in > Admin > **Account** > add your mobile (OTP-verified).
