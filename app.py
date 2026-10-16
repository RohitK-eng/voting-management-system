import os, re, sqlite3
from contextlib import closing
from functools import wraps
from flask import Flask, request, redirect, session, flash, abort, render_template
from jinja2 import DictLoader
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "voting-demo-key")
DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "voting.db")
CORE = ("voters", "candidates", "votes")
CORE_DDL = [
    """CREATE TABLE IF NOT EXISTS voters(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL,
       age INTEGER NOT NULL CHECK(age>=18), city TEXT)""",
    """CREATE TABLE IF NOT EXISTS candidates(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, party TEXT)""",
    """CREATE TABLE IF NOT EXISTS votes(id INTEGER PRIMARY KEY AUTOINCREMENT,
       voter_id INTEGER NOT NULL UNIQUE REFERENCES voters(id) ON DELETE CASCADE,
       candidate_id INTEGER NOT NULL REFERENCES candidates(id) ON DELETE CASCADE)"""]
SAMPLE = ["INSERT INTO voters(name,age,city) VALUES ('Asha Kumar',25,'Vellore'),('Ravi Shankar',31,'Chennai'),"
          "('Meena Iyer',45,'Madurai'),('John Paul',19,'Coimbatore')",
          "INSERT INTO candidates(name,party) VALUES ('A. Selvam','Progress Party'),('B. Devi','Unity Front'),('C. Rao','Independent')"]

# ---------------- database helpers ----------------
def run(sql, p=()):
    """Run ONE statement, commit, always close the connection."""
    with closing(sqlite3.connect(DB)) as c:
        c.execute("PRAGMA foreign_keys=ON")
        with c:
            cur = c.execute(sql, p)
            cols = [d[0] for d in cur.description] if cur.description else []
            return cols, ([list(r) for r in cur.fetchall()] if cols else []), cur.rowcount

def statements(text):
    out, buf = [], ""
    for ch in text:
        buf += ch
        if ch == ";" and sqlite3.complete_statement(buf): out.append(buf.strip()); buf = ""
    if buf.strip(): out.append(buf.strip())
    return out

def run_many(stmts, dry=False):
    """Run several statements as ONE transaction (all succeed or all roll back)."""
    with closing(sqlite3.connect(DB)) as c:
        c.execute("PRAGMA foreign_keys=ON"); c.execute("BEGIN")
        cols, rows, n = [], [], 0
        try:
            for s in stmts:
                kw = s.rstrip(";").strip().upper()
                if kw in ("BEGIN", "BEGIN TRANSACTION", "COMMIT", "END"): continue
                if kw in ("ROLLBACK", "ROLLBACK TRANSACTION"): dry = True; continue
                cur = c.execute(s)
                if cur.description: cols, rows = [d[0] for d in cur.description], [list(r) for r in cur.fetchall()]
                elif cur.rowcount > 0: n += cur.rowcount
            c.rollback() if dry else c.commit()
        except sqlite3.Error:
            c.rollback(); raise
        return cols, rows, n, dry

def tables():
    return [r[0] for r in run("SELECT name FROM sqlite_master WHERE type='table' "
                              "AND name NOT LIKE 'sqlite_%' AND name<>'users' ORDER BY 1")[1]]

def init():
    run("CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY, password TEXT NOT NULL)")
    if "role" not in [r[1] for r in run("PRAGMA table_info(users)")[1]]:      # upgrade older databases
        run("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'staff'")
    if not run("SELECT 1 FROM users WHERE username='admin'")[1]:
        run("INSERT INTO users(username,password,role) VALUES('admin',?,'admin')", (generate_password_hash("admin123"),))
    else:
        run("UPDATE users SET role='admin' WHERE username='admin'")

def q(name): return '"%s"' % name
def ok(m): flash(m, "ok")
def err(m): flash(m, "err")

def friendly(e):
    m = str(e)
    if "UNIQUE constraint failed: votes.voter_id" in m: return "This voter has already voted."
    if m.startswith("UNIQUE"): return "Duplicate value not allowed (" + m.split(": ", 1)[-1] + ")."
    if m.startswith("NOT NULL"): return m.split(": ", 1)[-1].split(".")[-1] + " is required."
    if m.startswith("CHECK"): return "Value rejected by a rule (" + m.split(": ", 1)[-1] + "). Voters must be 18 or older."
    if m.startswith("FOREIGN KEY"): return "That record points to something that does not exist, or is still in use."
    return m

def meta(t):
    if t not in tables(): abort(404)
    cols = [dict(name=r[1], type=(r[2] or "TEXT").upper(), req=bool(r[3]), pk=bool(r[5]))
            for r in run(f"PRAGMA table_info({q(t)})")[1]]
    fks = {r[3]: r[2] for r in run(f"PRAGMA foreign_key_list({q(t)})")[1]}
    return cols, fks

def fk_options(fks):
    out, ts = {}, tables()
    for col, ref in fks.items():
        if ref in ts:
            rc = [r[1] for r in run(f"PRAGMA table_info({q(ref)})")[1]]
            lab = rc[1] if len(rc) > 1 else rc[0]
            out[col] = {r[0]: f"{r[1]} (#{r[0]})" for r in run(f"SELECT rowid,{q(lab)} FROM {q(ref)} ORDER BY 2")[1]}
    return out

# ---------------- auth ----------------
def login_required(f):
    @wraps(f)
    def w(*a, **k): return f(*a, **k) if "user" in session else redirect("/login")
    return w

def admin_required(f):
    @wraps(f)
    @login_required
    def w(*a, **k):
        if session.get("role") != "admin": abort(403)
        return f(*a, **k)
    return w

@app.context_processor
def inject():
    return {"extra": [t for t in tables() if t not in CORE]} if "user" in session else {}

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session: return redirect("/")
    if request.method == "POST":
        r = run("SELECT password,role FROM users WHERE username=?", (request.form["username"].strip(),))[1]
        if r and check_password_hash(r[0][0], request.form["password"]):
            session.update(user=request.form["username"].strip(), role=r[0][1]); return redirect("/")
        err("Invalid username or password.")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u, p = request.form["username"].strip(), request.form["password"]
        if not re.fullmatch(r"\w{3,30}", u): err("Username: 3-30 letters, digits or underscore.")
        elif len(p) < 4: err("Password must be at least 4 characters.")
        else:
            try:
                run("INSERT INTO users(username,password,role) VALUES(?,?, 'staff')", (u, generate_password_hash(p)))
                ok("Account created. Please sign in."); return redirect("/login")
            except sqlite3.IntegrityError: err("That username is already taken.")
    return render_template("register.html")

@app.route("/logout")
def logout(): session.clear(); return redirect("/login")

# ---------------- dashboard ----------------
@app.route("/")
@login_required
def home():
    ts = tables(); ready = all(t in ts for t in CORE)
    counts = {t: run(f"SELECT COUNT(*) FROM {t}")[1][0][0] if t in ts else 0 for t in CORE}
    top = run("""SELECT c.name,c.party,COUNT(v.id) FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id
                 GROUP BY c.id ORDER BY 3 DESC, c.name LIMIT 5""")[1] if ready else []
    turnout = round(100 * counts["votes"] / counts["voters"]) if counts["voters"] else 0
    return render_template("home.html", ready=ready, counts=counts, top=top, turnout=turnout, ntables=len(ts))

# ---------------- DDL (admin) ----------------
@app.route("/ddl", methods=["GET", "POST"])
@admin_required
def ddl():
    if request.method == "POST":
        f, a = request.form, request.form.get("action", "")
        def tname():
            n = f.get("name", "")
            if n not in tables(): abort(400)
            return n
        def ident(key):
            v = f.get(key, "").strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", v): raise sqlite3.Error(f"'{v}' is not a valid name (letters, digits, underscore).")
            return v
        try:
            if a == "voting": run_many(CORE_DDL); ok("Voting tables are ready (voters, candidates, votes).")
            elif a == "sample":
                if all(run(f"SELECT COUNT(*) FROM {t}")[1][0][0] == 0 for t in CORE): run_many(SAMPLE); ok("Sample voters and candidates added.")
                else: err("Sample data is only added when voters, candidates and votes are all empty.")
            elif a == "create":
                n, cols = ident("name"), f.get("cols", "").strip()
                if not re.fullmatch(r"[\w\s,]+", cols): raise sqlite3.Error("Columns: use letters, digits, spaces and commas only, e.g. title TEXT, year INTEGER")
                run(f"CREATE TABLE {q(n)}(id INTEGER PRIMARY KEY AUTOINCREMENT, {cols})"); ok(f"Table '{n}' created.")
            elif a == "addcol":
                if f.get("type") not in ("TEXT", "INTEGER", "REAL"): abort(400)
                t, c = tname(), ident("col"); run(f"ALTER TABLE {q(t)} ADD COLUMN {q(c)} {f['type']}"); ok(f"Column '{c}' added to {t}.")
            elif a == "rename_table":
                t, n = tname(), ident("new"); run(f"ALTER TABLE {q(t)} RENAME TO {q(n)}"); ok(f"Table renamed to '{n}'.")
            elif a == "rename_col":
                t, c, n = tname(), ident("col"), ident("new"); run(f"ALTER TABLE {q(t)} RENAME COLUMN {q(c)} TO {q(n)}"); ok(f"Column renamed to '{n}'.")
            elif a == "drop_col":
                t, c = tname(), ident("col"); run(f"ALTER TABLE {q(t)} DROP COLUMN {q(c)}"); ok(f"Column '{c}' dropped.")
            elif a == "truncate":
                t = tname(); run_many([f"DELETE FROM {q(t)}", f"DELETE FROM sqlite_sequence WHERE name='{t}'"]); ok(f"All rows removed from {t}.")
            elif a == "drop": t = tname(); run(f"DROP TABLE {q(t)}"); ok(f"Table '{t}' dropped.")
            else: abort(400)
        except sqlite3.Error as e: err(friendly(e))
        return redirect("/ddl")
    ts = tables()
    info = [(t, run(f"SELECT COUNT(*) FROM {q(t)}")[1][0][0], [r[1] for r in run(f"PRAGMA table_info({q(t)})")[1]]) for t in ts]
    return render_template("ddl.html", ts=ts, info=info, ver=sqlite3.sqlite_version)

# ---------------- DML + DQL on any table ----------------
@app.route("/table/<t>")
@login_required
def tbl(t):
    if t not in tables():
        if t in CORE: return render_template("setup.html", t=t)
        abort(404)
    cols, fks = meta(t)
    names = [c["name"] for c in cols]
    s = request.args.get("q", "").strip()
    mode = "data" if request.args.get("mode") == "data" else "column"   # default: search column names
    order = request.args.get("order", "")
    if order not in names: order = ""
    desc = request.args.get("dir") == "desc"

    shown, where, p, nomatch = cols, "", [], False
    if s and mode == "column":
        # "name, city" -> show every column whose name contains "name" or "city"
        terms = [x.strip().lower() for x in s.split(",") if x.strip()]
        shown = [c for c in cols if any(x in c["name"].lower() for x in terms)]
        nomatch = not shown
    elif s:
        where = " WHERE " + " OR ".join(f"CAST({q(n)} AS TEXT) LIKE ?" for n in names)
        p = [f"%{s}%"] * len(names)

    sel = "".join("," + q(c["name"]) for c in shown)          # rowid first, then the visible columns
    query = f"SELECT rowid{sel} FROM {q(t)}{where}"
    if order: query += f" ORDER BY {q(order)} {'DESC' if desc else 'ASC'}"
    rows = [] if nomatch else run(query, p)[1]
    return render_template("table.html", t=t, cols=cols, shown=shown, rows=rows, q=s, mode=mode,
                           order=order, d="DESC" if desc else "ASC", nomatch=nomatch, fkopt=fk_options(fks))

@app.route("/table/<t>/add", methods=["POST"])
@login_required
def add(t):
    cols, _ = meta(t); ed = [c["name"] for c in cols if not c["pk"]]
    try:
        if ed: run(f"INSERT INTO {q(t)}({','.join(q(n) for n in ed)}) VALUES({','.join('?' * len(ed))})", [request.form.get(n, "").strip() or None for n in ed])
        else: run(f"INSERT INTO {q(t)} DEFAULT VALUES")
        ok("Record inserted.")
    except sqlite3.Error as e: err(friendly(e))
    return redirect(f"/table/{t}")

@app.route("/table/<t>/edit/<int:i>", methods=["GET", "POST"])
@login_required
def edit(t, i):
    cols, fks = meta(t); ed = [c for c in cols if not c["pk"]]
    row = run(f"SELECT {','.join(q(c['name']) for c in ed)} FROM {q(t)} WHERE rowid=?", (i,))[1] if ed else [[]]
    if not row: abort(404)
    vals = dict(zip([c["name"] for c in ed], row[0]))
    if request.method == "POST":
        vals = {c["name"]: request.form.get(c["name"], "").strip() or None for c in ed}
        try:
            n = run(f"UPDATE {q(t)} SET {','.join(q(c['name']) + '=?' for c in ed)} WHERE rowid=?", list(vals.values()) + [i])[2]
            (ok("Record updated.") if n else err("Record not found."))
            return redirect(f"/table/{t}")
        except sqlite3.Error as e: err(friendly(e))
    return render_template("edit.html", t=t, i=i, ed=ed, vals=vals, fkopt=fk_options(fks))

@app.route("/table/<t>/delete/<int:i>", methods=["POST"])
@login_required
def delete(t, i):
    meta(t)
    try: (ok("Record deleted.") if run(f"DELETE FROM {q(t)} WHERE rowid=?", (i,))[2] else err("Record not found."))
    except sqlite3.Error as e: err(friendly(e))
    return redirect(f"/table/{t}")

# ---------------- voting + results ----------------
def ready_or_setup():
    return None if all(t in tables() for t in CORE) else render_template("setup.html", t="voting")

@app.route("/vote", methods=["GET", "POST"])
@login_required
def vote():
    if (r := ready_or_setup()): return r
    if request.method == "POST":
        v, c = request.form.get("voter", ""), request.form.get("cand", "")
        if not (v.isdigit() and c.isdigit()): err("Choose a voter and a candidate.")
        elif run("SELECT 1 FROM votes WHERE voter_id=?", (v,))[1]: err("This voter has already voted.")
        else:
            try: run("INSERT INTO votes(voter_id,candidate_id) VALUES(?,?)", (v, c)); ok("Vote recorded.")
            except sqlite3.Error as e: err(friendly(e))
        return redirect("/vote")
    voters = run("SELECT id,name,city,EXISTS(SELECT 1 FROM votes WHERE voter_id=voters.id) FROM voters ORDER BY name")[1]
    cands = run("SELECT id,name,party FROM candidates ORDER BY name")[1]
    recent = run("""SELECT v.id,vo.name,c.name,c.party FROM votes v JOIN voters vo ON vo.id=v.voter_id
                    JOIN candidates c ON c.id=v.candidate_id ORDER BY v.id DESC LIMIT 10""")[1]
    return render_template("vote.html", voters=voters, cands=cands, recent=recent)

@app.route("/results")
@login_required
def results():
    if (r := ready_or_setup()): return r
    rows = run("""SELECT c.name,c.party,COUNT(v.id) FROM candidates c LEFT JOIN votes v ON v.candidate_id=c.id
                  GROUP BY c.id ORDER BY 3 DESC, c.name""")[1]
    total = sum(r[2] for r in rows); top = rows[0][2] if rows else 0
    winners = [r[0] for r in rows if top and r[2] == top]
    nvoters = run("SELECT COUNT(*) FROM voters")[1][0][0]
    return render_template("results.html", rows=rows, total=total, top=top, winners=winners, nvoters=nvoters)

# ---------------- SQL console (admin) ----------------
@app.route("/sql", methods=["GET", "POST"])
@admin_required
def sql():
    s, cols, rows = request.form.get("sql", ""), [], []
    if s.strip():
        try:
            cols, rows, n, dry = run_many(statements(s), dry=bool(request.form.get("dry")))
            msg = f"{len(rows)} row(s) returned." if cols else f"Executed. {n} row(s) changed."
            ok(msg + (" Rolled back - nothing was saved." if dry else " Committed."))
        except sqlite3.Error as e: err("SQL error: " + str(e))
    return render_template("sql.html", s=s, cols=cols, rows=rows, tabs=tables())

# ---------------- error pages ----------------
MSG = {400: "That request was not valid.", 403: "Only the admin account can open this page.",
       404: "That page or table does not exist.", 405: "That action is not allowed here."}
for _c in MSG:
    app.register_error_handler(_c, lambda e: (render_template("error.html", code=e.code, msg=MSG[e.code]), e.code))

# ---------------- templates ----------------
TEMPLATES = {
"macros.html": """{% macro field(c, val, fk) %}{% if c.name in fk %}<select name="{{c.name}}" {{'required' if c.req}}><option value="">- select -</option>
{% for k,l in fk[c.name].items() %}<option value="{{k}}" {{'selected' if val is not none and val|string==k|string}}>{{l}}</option>{% endfor %}</select>
{% else %}<input name="{{c.name}}" value="{{val if val is not none else ''}}" type="{{'number' if c.type in ('INTEGER','REAL') else 'text'}}"
{{'step=any' if c.type=='REAL'}} {{'required' if c.req}} placeholder="{{c.name}}">{% endif %}{% endmacro %}""",

"base.html": """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>BallotDesk | Voting Management</title><style>{% raw %}
@import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--ink:#17253d;--muted:#718096;--line:#e5eaf2;--paper:#f4f7fb;--white:#fff;--navy:#101c32;--navy2:#1a2e4b;--teal:#22c7b4;--teal-dark:#087f78;--red:#d94b64;--green:#16866b;--amber:#b7791f;--shadow:0 12px 35px rgba(21,39,67,.07);--radius:18px}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;background:var(--paper);color:var(--ink);font:14px/1.6 'DM Sans',Inter,'Segoe UI',Arial,sans-serif}a{color:var(--teal-dark);text-decoration:none;transition:color .18s}a:hover{color:#075b56;text-decoration:none}
.app-shell{min-height:100vh}.sidebar{position:fixed;inset:0 auto 0 0;width:258px;background:linear-gradient(160deg,#101b30 0%,#172a45 58%,#173c4c 100%);color:#c4d0df;padding:27px 17px 20px;display:flex;flex-direction:column;z-index:10;box-shadow:8px 0 32px rgba(15,31,53,.08)}
.brand{display:flex;align-items:center;gap:12px;padding:0 10px 30px;color:#fff;font:800 19px 'Manrope','Segoe UI',Arial,sans-serif;letter-spacing:-.6px}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border-radius:14px;background:linear-gradient(135deg,#39e0ca,#19a997);color:#0a2a3b;font-weight:900;font-size:20px;box-shadow:0 8px 18px rgba(34,199,180,.22)}.brand small{display:block;color:#8fa2b9;font:600 9px 'DM Sans','Segoe UI',Arial,sans-serif;letter-spacing:1.8px;text-transform:uppercase;margin-top:2px}
.nav-label{padding:14px 12px 9px;color:#8193ab;font-size:10px;font-weight:800;letter-spacing:1.6px;text-transform:uppercase}.sidebar nav{display:grid;gap:5px}.sidebar nav a{display:flex;align-items:center;gap:12px;padding:11px 13px;border:1px solid transparent;border-radius:12px;color:#bdc9d9;font-weight:600;transition:background .2s,border-color .2s,color .2s,transform .2s}.sidebar nav a:hover,.sidebar nav a.active{background:linear-gradient(100deg,rgba(34,199,180,.18),rgba(34,199,180,.07));border-color:rgba(78,223,204,.13);color:#76eddd;transform:translateX(2px)}.nav-icon{width:21px;text-align:center;font-size:17px}.sidebar-foot{margin-top:auto;border-top:1px solid rgba(220,235,250,.13);padding:18px 10px 0;color:#9aabc0;font-size:11px;line-height:1.9}.online-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:#43dfaa;margin-right:7px;box-shadow:0 0 0 4px rgba(67,223,170,.12)}
.main{margin-left:258px;min-height:100vh}.topbar{height:82px;background:rgba(255,255,255,.92);backdrop-filter:blur(12px);border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 42px;position:sticky;top:0;z-index:5}.eyebrow{color:#8190a5;font-size:10px;font-weight:800;letter-spacing:1.65px;text-transform:uppercase}.top-title{font:800 19px 'Manrope','Segoe UI',Arial,sans-serif;margin-top:2px;letter-spacing:-.4px}.user-pill{display:flex;align-items:center;gap:10px;color:#46556a;font-weight:700;font-size:12px}.avatar{width:38px;height:38px;border-radius:13px;background:linear-gradient(135deg,#dcfbf6,#b5f1e7);color:#087f76;display:grid;place-items:center;font-weight:900;font-size:14px;border:1px solid #bcece4}.user-pill>a{margin-left:9px;padding:8px 11px;border-radius:9px;background:#f3f6fa;color:#5c6b7e}.user-pill>a:hover{background:#e6edf4;color:#17253d}
.content{max-width:1580px;margin:0 auto;padding:34px 42px 55px}.page-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:27px}.page-heading h1{font:800 29px/1.25 'Manrope','Segoe UI',Arial,sans-serif;letter-spacing:-1px;margin:0 0 8px}.page-heading p{margin:0;color:var(--muted);font-size:13px}.section-title{font:800 17px 'Manrope','Segoe UI',Arial,sans-serif;margin:0 0 16px}
.box{max-width:none;margin:0;padding:0;background:transparent;border-radius:0}.panel,.stat-card,.welcome{background:#fff;border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.panel{padding:25px;margin-bottom:22px;transition:box-shadow .2s,border-color .2s}.panel:hover{border-color:#d7e2ed;box-shadow:0 15px 38px rgba(21,39,67,.085)}.welcome{padding:32px 34px;margin-bottom:24px;background:radial-gradient(circle at 88% 0%,rgba(61,221,199,.25),transparent 29%),linear-gradient(115deg,#13243d,#1a3d57 68%,#17645f);color:#fff;position:relative;overflow:hidden;border:0;box-shadow:0 18px 42px rgba(21,53,78,.16)}.welcome:after{content:'✓';position:absolute;right:54px;top:-48px;font:800 220px 'Manrope','Segoe UI',Arial,sans-serif;color:rgba(255,255,255,.045);pointer-events:none}.welcome .eyebrow{color:#7de6d8}.welcome h1{font:800 30px 'Manrope','Segoe UI',Arial,sans-serif;margin:10px 0;letter-spacing:-.8px}.welcome p{color:#d0dce8;max-width:660px;margin:0}.stats-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:17px;margin-bottom:25px}.stat-card{padding:22px;position:relative;overflow:hidden;transition:transform .2s,box-shadow .2s}.stat-card:hover{transform:translateY(-4px);box-shadow:0 17px 34px rgba(21,39,67,.11)}.stat-top{display:flex;justify-content:space-between;align-items:center;color:var(--muted);font-weight:700;font-size:12px}.stat-icon{width:41px;height:41px;border-radius:14px;display:grid;place-items:center;background:#e3faf6;color:#078577;font-size:18px}.stat-number{font:800 31px 'Manrope','Segoe UI',Arial,sans-serif;margin-top:13px;letter-spacing:-1px}.stat-note{color:var(--muted);font-size:11px;margin-top:3px}.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(280px,1fr);gap:21px}.quick-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.quick-link{display:flex;gap:13px;align-items:center;border:1px solid var(--line);padding:16px;border-radius:14px;color:var(--ink);transition:.2s;background:linear-gradient(135deg,#fff,#fbfdff)}.quick-link:hover{border-color:#9dded6;background:#f2fffc;text-decoration:none;transform:translateY(-3px);box-shadow:0 9px 20px rgba(8,127,120,.08)}.quick-link strong{display:block;font-size:13px}.quick-link small{color:var(--muted);font-size:11px}.quick-icon{display:grid;place-items:center;width:42px;height:42px;flex:0 0 42px;background:#edf4fa;border-radius:13px;font-size:18px}
.table-wrap{width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:13px;margin-top:16px}table{border-collapse:collapse;width:100%;margin:0;background:#fff;font-size:13px}td,th{border:0;border-bottom:1px solid #edf0f5;padding:14px 16px;text-align:left;white-space:nowrap}th{background:#f7f9fc;color:#74839a;font-size:10px;letter-spacing:1.1px;text-transform:uppercase;font-weight:800}tr:last-child td{border-bottom:0}tbody tr{transition:background .15s}tbody tr:hover{background:#f4fbfa}
form{margin:0}input,select,textarea{font:inherit;color:var(--ink);background:#fff;border:1px solid #d8e1ec;border-radius:10px;padding:11px 13px;margin:4px 3px 4px 0;outline:none;max-width:100%;transition:border-color .18s,box-shadow .18s,background .18s}input:focus,select:focus,textarea:focus{border-color:var(--teal);box-shadow:0 0 0 4px rgba(34,199,180,.13);background:#fcfffe}input::placeholder,textarea::placeholder{color:#a0aaba}textarea{width:min(100%,900px);font-family:ui-monospace,SFMono-Regular,Consolas,monospace;line-height:1.7}
button,.btn{border:1px solid transparent;border-radius:10px;background:linear-gradient(135deg,#0a9185,#08756e);color:#fff;padding:11px 16px;font:800 12px 'DM Sans','Segoe UI',Arial,sans-serif;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;gap:7px;transition:transform .18s,box-shadow .18s,filter .18s;text-decoration:none;box-shadow:0 4px 10px rgba(8,127,120,.12)}button:hover,.btn:hover{filter:brightness(1.07);text-decoration:none;transform:translateY(-2px);box-shadow:0 8px 17px rgba(8,127,120,.2);color:#fff}button:active,.btn:active{transform:translateY(0);box-shadow:none}button:focus-visible,.btn:focus-visible,a:focus-visible{outline:3px solid rgba(34,199,180,.5);outline-offset:3px}form.i{display:inline}form.i button{padding:7px 10px;background:#fff0f1;color:#b8324b;border:1px solid #ffd6dc;box-shadow:none}form.i button:hover{background:#ffe2e7;transform:translateY(-1px);box-shadow:none}.btn.secondary,button.secondary{background:#eef2f7;color:#33445a;border-color:#e0e6ee;box-shadow:none}.btn.secondary:hover,button.secondary:hover{background:#e2eaf2;color:#17253d}.btn.danger,button.danger{background:linear-gradient(135deg,#d84d67,#b82e4a);color:#fff}.btn.danger:hover,button.danger:hover{filter:brightness(1.05)}
hr{border:0;border-top:1px solid var(--line);margin:25px 0}h2{font:800 24px 'Manrope','Segoe UI',Arial,sans-serif;letter-spacing:-.6px;margin:0 0 8px}h3{font:800 17px 'Manrope','Segoe UI',Arial,sans-serif;margin:24px 0 13px;letter-spacing:-.25px}p{color:#5f6f82}.msg{padding:13px 16px;margin:0 0 17px;border-radius:12px;font-weight:700;border:1px solid;box-shadow:0 4px 12px rgba(20,40,60,.025)}.msg.ok{background:#e8faf5;border-color:#bceee2;color:#087f68}.msg.ok:before{content:'✓  ';font-weight:900}.msg.err{background:#fff0f2;border-color:#f6c3cb;color:#b4233f}.msg.err:before{content:'!  ';font-weight:900}
label{display:inline-block;color:#59697c;font-size:12px;font-weight:800;min-width:100px}.muted{color:var(--muted)}.pill{display:inline-block;padding:5px 10px;border-radius:999px;background:#e5f8f3;color:#087f68;font-size:10px;font-weight:900;letter-spacing:.5px}.empty{padding:28px;text-align:center;color:var(--muted)}.toolbar{display:flex;flex-wrap:wrap;gap:9px;align-items:center}.grid-form{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:13px;align-items:end}.grid-form label{display:block;min-width:0}.grid-form input,.grid-form select{width:100%;margin:4px 0 0}.ddl-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px}.panel h3:first-child{margin-top:0}.bar{height:9px;background:#e8eef3;border-radius:8px;overflow:hidden;min-width:120px;display:inline-block;vertical-align:middle}.bar i{display:block;height:100%;background:linear-gradient(90deg,#21b9a8,#59dfc9);border-radius:8px}tr.win td{background:#effcf8}.chips{display:flex;flex-wrap:wrap;gap:7px;margin-bottom:12px}.chips button{background:#edf2f8;color:#33445a;font-weight:800;padding:8px 11px;box-shadow:none}.chips button:hover{background:#dce8f2;box-shadow:none}.sidebar nav a.sub{padding:8px 13px 8px 18px;font-size:13px}.err-code{font:800 64px 'Manrope',Arial,sans-serif;color:var(--teal-dark);margin:0}
/* Authentication pages */
body:has(.auth-layout){background:#101b30}.auth-wrap{max-width:unset;margin:0;padding:0;background:transparent;border:0;border-radius:0;box-shadow:none;min-height:100vh;display:flex;align-items:stretch}.auth-layout{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(420px,.95fr);width:100%;min-height:100vh;background:#f5f7fb}.auth-visual{padding:54px clamp(30px,6vw,90px);background:radial-gradient(circle at 85% 18%,rgba(61,221,199,.23),transparent 25%),radial-gradient(circle at 8% 90%,rgba(75,115,201,.22),transparent 28%),linear-gradient(145deg,#101b30,#17334e 60%,#12665f);color:#fff;display:flex;flex-direction:column;justify-content:space-between;position:relative;overflow:hidden}.auth-visual:after{content:'✓';position:absolute;right:3%;bottom:4%;font:800 clamp(200px,28vw,430px)/1 'Manrope',sans-serif;color:rgba(255,255,255,.035);pointer-events:none}.auth-brand{display:flex;align-items:center;gap:13px;font:800 20px 'Manrope',sans-serif;letter-spacing:-.5px;position:relative;z-index:1}.auth-brand .brand-mark{width:47px;height:47px}.auth-brand small{display:block;color:#9fb2c8;font:600 10px 'DM Sans',sans-serif;letter-spacing:1.8px;text-transform:uppercase}.auth-copy{max-width:590px;position:relative;z-index:1;padding:60px 0}.auth-kicker{display:inline-flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid rgba(126,230,216,.25);border-radius:999px;background:rgba(33,201,180,.09);color:#8ce8dc;font-size:10px;font-weight:900;letter-spacing:1.4px;text-transform:uppercase}.auth-copy h1{font:800 clamp(34px,4vw,57px)/1.12 'Manrope',sans-serif;letter-spacing:-2px;margin:23px 0 17px;max-width:560px}.auth-copy p{color:#c5d3e1;font-size:15px;max-width:480px;line-height:1.85}.auth-features{display:grid;gap:13px;margin-top:30px}.auth-feature{display:flex;align-items:center;gap:12px;color:#e2edf5;font-size:13px;font-weight:600}.auth-feature span{display:grid;place-items:center;width:29px;height:29px;border:1px solid rgba(112,231,213,.22);border-radius:9px;background:rgba(34,199,180,.1);color:#7de6d8}.auth-foot{position:relative;z-index:1;color:#91a7bd;font-size:11px;letter-spacing:.3px}.auth-form-side{display:flex;align-items:center;justify-content:center;padding:45px clamp(24px,5vw,75px);background:linear-gradient(145deg,#f8fafc,#edf3f8)}.auth-card{width:100%;max-width:430px;background:#fff;border:1px solid #e7edf4;border-radius:24px;padding:clamp(26px,3vw,42px);box-shadow:0 24px 70px rgba(23,42,68,.1)}.auth-card .auth-mobile-brand{display:none}.auth-card .form-kicker{color:#0b9286;font-size:10px;font-weight:900;letter-spacing:1.8px;text-transform:uppercase}.auth-card h2{font-size:30px;letter-spacing:-1px;margin:10px 0 8px}.auth-card .auth-intro{font-size:13px;line-height:1.7;color:#7b899b;margin:0 0 25px}.auth-card label{display:block;min-width:0;margin:0 0 7px;color:#394a60;font-size:12px}.auth-card input{width:100%;margin:0 0 17px;padding:13px 14px;border-radius:11px;background:#fbfcfe}.auth-card button{width:100%;padding:14px;margin-top:5px;font-size:13px}.auth-card .auth-switch{text-align:center;margin:21px 0 0;font-size:12px;color:#7b899b}.auth-card .auth-switch a{font-weight:800}.auth-card .demo-credentials{margin-top:22px;padding:13px 14px;background:#f2faf9;border:1px solid #d9f1ed;border-radius:12px;font-size:11px;color:#53736f;line-height:1.7}.auth-card .demo-credentials strong{color:#176b65;display:block;margin-bottom:2px}.auth-card .demo-credentials code{font-family:ui-monospace,Consolas,monospace;color:#1b4e4b;font-weight:800}.auth-card .security-note{display:flex;align-items:center;gap:8px;color:#8997a8;font-size:10px;margin-top:20px}.auth-card .security-note span{color:#0d9c8d}

/* Minimal centered login page; other authentication and application pages stay unchanged. */
body:has(.login-layout){background:#f3f6fa}
.auth-wrap:has(.login-layout){width:100%;min-height:100vh;align-items:center;justify-content:center;padding:36px 18px;background:radial-gradient(ellipse at 50% 0%,#e0f7f3 0%,#f3f6fa 52%,#eef2f7 100%)}
.login-layout{width:100%;min-height:auto;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:20px;background:transparent}
.login-card{max-width:430px;padding:34px 36px 30px;border-radius:20px;box-shadow:0 18px 55px rgba(23,42,68,.09);border-color:#e4eaf1}
.login-brand{display:flex;align-items:center;justify-content:center;gap:12px;margin:0 0 23px}
.login-brand .brand-mark{width:45px;height:45px;border-radius:13px;font-size:21px}
.login-brand strong{display:block;font:800 20px 'Manrope',sans-serif;letter-spacing:-.5px;color:#17253d}
.login-brand small{display:block;margin-top:2px;font:700 9px 'DM Sans',sans-serif;letter-spacing:1.25px;color:#8190a5}
.login-divider{height:1px;background:#edf0f5;margin:0 0 25px}
.login-card .form-kicker{font-size:10px;letter-spacing:1.7px}
.login-card h2{font-size:28px;margin:7px 0 6px}
.login-card .auth-intro{margin-bottom:22px}
.login-card .demo-credentials{margin-top:20px}
.login-footer{font-size:10px;font-weight:800;letter-spacing:1.5px;color:#94a0b1;text-align:center}
.login-footer span{color:#20a99b;padding:0 5px}
@media(max-width:760px){.auth-wrap:has(.login-layout){padding:20px 14px}.login-card{padding:29px 23px;border-radius:18px}.login-brand{margin-bottom:20px}.login-divider{margin-bottom:22px}}
@media(max-width:1050px){.sidebar{width:220px}.main{margin-left:220px}.topbar{padding:0 25px}.content{padding:27px 25px}.stats-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.auth-layout{grid-template-columns:minmax(0,.9fr) minmax(390px,1.1fr)}.auth-visual{padding:40px}}
@media(max-width:760px){.sidebar{position:static;width:auto;padding:12px;display:block}.brand{padding:4px 8px 12px}.sidebar .nav-label,.sidebar-foot{display:none}.sidebar nav{display:flex;overflow-x:auto}.sidebar nav a{white-space:nowrap;padding:9px 11px;font-size:12px}.main{margin-left:0}.topbar{height:65px;padding:0 16px}.content{padding:20px 14px}.page-heading h1{font-size:23px}.stats-grid{gap:10px}.stat-card{padding:15px}.stat-number{font-size:24px}.dashboard-grid{grid-template-columns:1fr}.quick-grid{grid-template-columns:1fr 1fr}.welcome{padding:23px}.panel{padding:16px}.auth-wrap{min-height:100vh}.auth-layout{grid-template-columns:1fr}.auth-visual{display:none}.auth-form-side{min-height:100vh;padding:22px 15px;background:radial-gradient(circle at top right,#d7f8f1,transparent 35%),#f3f6fa}.auth-card{padding:27px 23px;border-radius:20px}.auth-card .auth-mobile-brand{display:flex;align-items:center;gap:10px;margin-bottom:27px;color:#17253d;font:800 16px 'Manrope',sans-serif}.auth-mobile-brand small{display:block;font:600 9px 'DM Sans',sans-serif;color:#8391a3;letter-spacing:1.2px;text-transform:uppercase}.ddl-grid{grid-template-columns:1fr}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{scroll-behavior:auto!important;transition:none!important}}
{% endraw %}</style></head><body>
{% if session.user %}{% set nav=[('/','▦','Overview'),('/table/voters','♙','Voters'),('/table/candidates','◉','Candidates'),('/table/votes','✓','Vote records'),('/vote','▤','Cast a vote'),('/results','▥','Results')] %}
<div class="app-shell"><aside class="sidebar"><div class="brand"><span class="brand-mark">B</span><span>BallotDesk<small>Election workspace</small></span></div>
<div class="nav-label">Workspace</div><nav>{% for p,i,l in nav %}<a href="{{p}}" class="{{'active' if request.path==p}}"><span class="nav-icon">{{i}}</span> {{l}}</a>{% endfor %}
{% if extra %}<div class="nav-label">Other tables</div>{% for t in extra %}<a class="sub {{'active' if request.path=='/table/'+t}}" href="/table/{{t}}"><span class="nav-icon">▫</span> {{t}}</a>{% endfor %}{% endif %}
{% if session.role=='admin' %}<div class="nav-label">Database tools</div><a href="/ddl" class="{{'active' if request.path=='/ddl'}}"><span class="nav-icon">⌘</span> DDL operations</a>
<a href="/sql" class="{{'active' if request.path=='/sql'}}"><span class="nav-icon">⌁</span> SQL console</a>{% endif %}</nav>
<div class="sidebar-foot"><span class="online-dot"></span>Local workspace active<br><span style="padding-left:14px">SQLite database</span></div></aside>
<div class="main"><header class="topbar"><div><div class="eyebrow">Election administration</div><div class="top-title">{% block title %}{% endblock %}</div></div>
<div class="user-pill"><div class="avatar">{{session.user[:1]|upper}}</div><span>{{session.user}} · {{session.role}}</span><a href="/logout">Sign out ↗</a></div></header><main class="content">
{% else %}<main class="auth-wrap">{% endif %}
{% for cat,m in get_flashed_messages(with_categories=true) %}<div class="msg {{cat}}">{{m}}</div>{% endfor %}
{% block body %}{% endblock %}</main>{% if session.user %}</div></div>{% endif %}</body></html>""",

"login.html": """{% extends "base.html" %}{% block title %}Sign in | BallotDesk{% endblock %}{% block body %}
<div class="auth-layout login-layout"><div class="auth-card login-card"><div class="login-brand"><span class="brand-mark">B</span><div><strong>BallotDesk</strong><small>VOTING MANAGEMENT SYSTEM</small></div></div><div class="login-divider"></div><div class="form-kicker">WELCOME BACK</div><h2>Sign in</h2><p class="auth-intro">Sign in to manage voter records, candidates and election results.</p><form method="post"><label for="username">Username</label><input id="username" name="username" placeholder="Enter your username" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" type="password" name="password" placeholder="Enter your password" autocomplete="current-password" required><button type="submit">Sign in <span aria-hidden="true">→</span></button></form><p class="auth-switch">New to BallotDesk? <a href="/register">Create a staff account</a></p><div class="demo-credentials"><strong>Demo administrator credentials</strong><span>Username: <code>admin</code> &nbsp;·&nbsp; Password: <code>admin123</code></span></div><div class="security-note"><span>●</span> Local demo environment · SQLite database</div></div><div class="login-footer">BALLOTDESK <span>•</span> ELECTION ADMINISTRATION</div></div>{% endblock %}""",

"register.html": """{% extends "base.html" %}{% block title %}Create account | BallotDesk{% endblock %}{% block body %}
<div class="auth-layout"><section class="auth-visual"><div class="auth-brand"><span class="brand-mark">B</span><span>BallotDesk<small>Voting management system</small></span></div><div class="auth-copy"><span class="auth-kicker">STAFF ACCESS</span><h1>A clearer way to manage elections.</h1><p>Create a staff account to work with voter records, candidate details and ballots in a single organised workspace.</p><div class="auth-features"><div class="auth-feature"><span>✓</span> Organised election records</div><div class="auth-feature"><span>✓</span> Guided database workspace</div><div class="auth-feature"><span>✓</span> Responsive, secure-by-default sign-in flow</div></div></div><div class="auth-foot">BALLOTDESK · LOCAL ELECTION WORKSPACE</div></section><section class="auth-form-side"><div class="auth-card"><div class="auth-mobile-brand"><span class="brand-mark">B</span><span>BallotDesk<small>Voting management system</small></span></div><div class="form-kicker">GET STARTED</div><h2>Create your account</h2><p class="auth-intro">Set up staff access for the voting management workspace.</p><form method="post"><label for="username">Username</label><input id="username" name="username" placeholder="3–30 letters, digits or underscore" autocomplete="username" required autofocus><label for="password">Password</label><input id="password" type="password" name="password" placeholder="At least 4 characters" autocomplete="new-password" required><button type="submit">Create staff account <span aria-hidden="true">→</span></button></form><p class="auth-switch">Already have an account? <a href="/login">Return to sign in</a></p><div class="security-note"><span>●</span> Staff accounts have standard workspace access</div></div></section></div>{% endblock %}""",

"error.html": """{% extends "base.html" %}{% block title %}Error{% endblock %}{% block body %}<section class="panel"><p class="err-code">{{code}}</p><h2>{{msg}}</h2>
<p><a class="btn" href="/">Back to overview</a></p></section>{% endblock %}""",

"setup.html": """{% extends "base.html" %}{% block title %}Setup required{% endblock %}{% block body %}<section class="panel"><span class="pill">SETUP REQUIRED</span>
<h2>The voting tables have not been created yet</h2><p>Create the voters, candidates and votes tables first, then come back here.</p>
{% if session.role=='admin' %}<a class="btn" href="/ddl">Open DDL operations →</a>{% else %}<p>Ask the admin to create the tables.</p>{% endif %}</section>{% endblock %}""",

"home.html": """{% extends "base.html" %}{% block title %}Overview{% endblock %}{% block body %}
<section class="welcome"><div class="eyebrow">CONTROL CENTRE · LIVE OVERVIEW</div><h1>Good to see you, {{session.user}}.</h1>
<p>Manage voter records, maintain candidates, record ballots and monitor results from one place.</p></section>
{% if not ready %}<section class="panel"><span class="pill">SETUP REQUIRED</span><h3>Start by creating your election tables</h3>
{% if session.role=='admin' %}<a class="btn" href="/ddl">Open database setup →</a>{% else %}<p>Ask the admin to create the tables.</p>{% endif %}</section>{% endif %}
<div class="stats-grid">
<article class="stat-card"><div class="stat-top">Registered voters <span class="stat-icon">♙</span></div><div class="stat-number">{{counts.voters}}</div><div class="stat-note">Voter records</div></article>
<article class="stat-card"><div class="stat-top">Candidates <span class="stat-icon">◉</span></div><div class="stat-number">{{counts.candidates}}</div><div class="stat-note">People contesting</div></article>
<article class="stat-card"><div class="stat-top">Votes recorded <span class="stat-icon">✓</span></div><div class="stat-number">{{counts.votes}}</div><div class="stat-note">Turnout {{turnout}}%</div></article>
<article class="stat-card"><div class="stat-top">Database tables <span class="stat-icon">▤</span></div><div class="stat-number">{{ntables}}</div><div class="stat-note">Application tables</div></article></div>
<div class="dashboard-grid"><section class="panel"><h3 class="section-title">Quick actions</h3><div class="quick-grid">
<a class="quick-link" href="/table/voters"><span class="quick-icon">♙</span><span><strong>Manage voters</strong><small>Add, search, edit, delete</small></span></a>
<a class="quick-link" href="/table/candidates"><span class="quick-icon">◉</span><span><strong>Manage candidates</strong><small>Maintain profiles</small></span></a>
<a class="quick-link" href="/vote"><span class="quick-icon">✓</span><span><strong>Cast a vote</strong><small>Record a ballot</small></span></a>
<a class="quick-link" href="/results"><span class="quick-icon">▥</span><span><strong>View results</strong><small>Counts by candidate</small></span></a>
{% if session.role=='admin' %}<a class="quick-link" href="/ddl"><span class="quick-icon">⌘</span><span><strong>Database structure</strong><small>CREATE, ALTER, DROP</small></span></a>
<a class="quick-link" href="/sql"><span class="quick-icon">⌁</span><span><strong>SQL console</strong><small>Run any SQL</small></span></a>{% endif %}</div></section>
<section class="panel"><h3 class="section-title">Candidate standings</h3>{% if top %}<div class="table-wrap"><table><thead><tr><th>Candidate</th><th>Party</th><th>Votes</th></tr></thead><tbody>
{% for r in top %}<tr><td>{{r[0]}}</td><td>{{r[1] or '—'}}</td><td><span class="pill">{{r[2]}}</span></td></tr>{% endfor %}</tbody></table></div>
{% else %}<div class="empty">No standings yet.<br>Add candidates and record votes.</div>{% endif %}<p style="margin-top:16px"><a href="/results">Open full results →</a></p></section></div>{% endblock %}""",

"ddl.html": """{% extends "base.html" %}{% block title %}Database structure{% endblock %}{% block body %}
<div class="page-heading"><div><h1>DDL operations</h1><p>CREATE, ALTER, RENAME, TRUNCATE and DROP. SQLite {{ver}}.</p></div></div>
<section class="panel"><h3>Quick setup</h3><div class="toolbar"><form method="post"><input type="hidden" name="action" value="voting"><button>Create voting tables (voters, candidates, votes)</button></form>
<form method="post"><input type="hidden" name="action" value="sample"><button class="secondary">Load sample data</button></form></div></section>
<div class="ddl-grid">
<section class="panel"><h3>CREATE TABLE</h3><form method="post"><input type="hidden" name="action" value="create"><input name="name" placeholder="table name" required>
<input name="cols" placeholder="e.g. title TEXT, year INTEGER" size="28" required><button>Create</button></form><p class="muted">An auto-numbered <b>id</b> column is added for you.</p></section>
<section class="panel"><h3>ALTER TABLE · add column</h3><form method="post"><input type="hidden" name="action" value="addcol"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select>
<input name="col" placeholder="column name" required><select name="type"><option>TEXT</option><option>INTEGER</option><option>REAL</option></select><button>Add column</button></form></section>
<section class="panel"><h3>ALTER TABLE · rename column</h3><form method="post"><input type="hidden" name="action" value="rename_col"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select>
<input name="col" placeholder="old column" required><input name="new" placeholder="new column" required><button>Rename</button></form></section>
<section class="panel"><h3>ALTER TABLE · drop column</h3><form method="post" onsubmit="return confirm('Drop this column?')"><input type="hidden" name="action" value="drop_col"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select>
<input name="col" placeholder="column name" required><button class="danger">Drop column</button></form></section>
<section class="panel"><h3>ALTER TABLE · rename table</h3><form method="post"><input type="hidden" name="action" value="rename_table"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select>
<input name="new" placeholder="new table name" required><button>Rename</button></form></section>
<section class="panel"><h3>TRUNCATE / DROP</h3><form method="post" onsubmit="return confirm('Delete ALL rows?')" class="toolbar"><input type="hidden" name="action" value="truncate"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select><button class="danger">Truncate</button></form>
<form method="post" onsubmit="return confirm('DROP this table permanently?')" class="toolbar"><input type="hidden" name="action" value="drop"><select name="name">{% for t in ts %}<option>{{t}}</option>{% endfor %}</select><button class="danger">Drop table</button></form></section></div>
<section class="panel"><h3>Existing tables</h3>{% if info %}<div class="table-wrap"><table><thead><tr><th>Table</th><th>Rows</th><th>Columns</th><th></th></tr></thead><tbody>
{% for t,n,c in info %}<tr><td><b>{{t}}</b></td><td>{{n}}</td><td>{{c|join(', ')}}</td><td><a href="/table/{{t}}">Open →</a></td></tr>{% endfor %}</tbody></table></div>
{% else %}<div class="empty">No tables yet.</div>{% endif %}</section>{% endblock %}""",

"table.html": """{% extends "base.html" %}{% from "macros.html" import field %}{% block title %}{{t|capitalize}}{% endblock %}{% block body %}
<style>th a.sortlink{color:inherit;display:inline-flex;gap:6px;align-items:center}th a.sortlink:hover{color:var(--teal-dark)}.colchips a{display:inline-block;margin:0 6px 6px 0;padding:6px 11px;border-radius:999px;background:#edf2f8;color:#33445a;font-weight:700;font-size:12px}.colchips a:hover{background:#dce8f2}</style>
<div class="page-heading"><div><h1>{{t|capitalize}}</h1><p>{{rows|length}} record(s){% if q %} · {% if mode=='column' %}{{shown|length}} of {{cols|length}} column(s) matching “{{q}}”{% else %}matching “{{q}}” in record contents{% endif %}{% endif %}</p></div></div>
<section class="panel"><form class="toolbar"><input name="q" value="{{q}}" placeholder="{{'Type a column name, e.g. name, city' if mode=='column' else 'Search record contents'}}" size="30">
<select name="mode"><option value="column" {{'selected' if mode=='column'}}>Search column names</option><option value="data" {{'selected' if mode=='data'}}>Search record contents</option></select>
<select name="order"><option value="">Order by…</option>{% for c in cols %}<option {{'selected' if c.name==order}}>{{c.name}}</option>{% endfor %}</select>
<select name="dir"><option value="asc">Ascending</option><option value="desc" {{'selected' if d=='DESC'}}>Descending</option></select>
<button>Search / Sort</button><a class="btn secondary" href="/table/{{t}}">Reset</a></form>
{% if nomatch %}<div class="empty">No column name contains “{{q}}”.<br>Columns in this table:</div><div class="colchips" style="text-align:center">{% for c in cols %}<a href="?q={{c.name|urlencode}}&mode=column">{{c.name}}</a>{% endfor %}</div>
{% else %}<div class="table-wrap"><table><thead><tr>{% for c in shown %}{% set nxt = 'desc' if (order==c.name and d=='ASC') else 'asc' %}<th><a class="sortlink" href="?q={{q|urlencode}}&mode={{mode}}&order={{c.name|urlencode}}&dir={{nxt}}" title="Sort by {{c.name}}">{{c.name}}{% if order==c.name %}<span>{{'▲' if d=='ASC' else '▼'}}</span>{% endif %}</a></th>{% endfor %}<th>Actions</th></tr></thead><tbody>
{% for r in rows %}<tr>{% for c in shown %}{% set x=r[loop.index] %}<td>{% if c.name in fkopt and x in fkopt[c.name] %}{{fkopt[c.name][x]}}{% elif x is none %}—{% else %}{{x}}{% endif %}</td>{% endfor %}
<td><a href="/table/{{t}}/edit/{{r[0]}}">Edit</a> &nbsp;<form class="i" method="post" action="/table/{{t}}/delete/{{r[0]}}" onsubmit="return confirm('Delete this record? Related records may be removed too.')"><button>Delete</button></form></td></tr>
{% else %}<tr><td colspan="{{shown|length+1}}" class="empty">No records found.</td></tr>{% endfor %}</tbody></table></div>{% endif %}</section>
<section class="panel"><h3>Insert new record</h3><form method="post" action="/table/{{t}}/add"><div class="grid-form">
{% for c in cols if not c.pk %}<label>{{c.name}}{{field(c, none, fkopt)}}</label>{% endfor %}<button>Insert</button></div></form></section>{% endblock %}""",

"edit.html": """{% extends "base.html" %}{% from "macros.html" import field %}{% block title %}Edit record{% endblock %}{% block body %}
<div class="page-heading"><div><h1>Edit {{t}} #{{i}}</h1></div></div><section class="panel"><form method="post"><div class="grid-form">
{% for c in ed %}<label>{{c.name}}{{field(c, vals[c.name], fkopt)}}</label>{% endfor %}</div><p><button>Update</button> <a class="btn secondary" href="/table/{{t}}">Cancel</a></p></form></section>{% endblock %}""",

"vote.html": """{% extends "base.html" %}{% block title %}Ballot station{% endblock %}{% block body %}
<div class="page-heading"><div><h1>Cast a vote</h1><p>Each voter can vote once.</p></div></div><section class="panel">
{% if not voters or not cands %}<div class="empty">Add at least one voter and one candidate first.<br><a href="/table/voters">Voters</a> · <a href="/table/candidates">Candidates</a></div>
{% else %}<form method="post" class="toolbar"><select name="voter" required><option value="">Select voter…</option>{% for v in voters %}<option value="{{v[0]}}" {{'disabled' if v[3]}}>{{v[1]}}{{' — '+v[2] if v[2]}}{{' (already voted)' if v[3]}}</option>{% endfor %}</select>
<select name="cand" required><option value="">Select candidate…</option>{% for c in cands %}<option value="{{c[0]}}">{{c[1]}}{{' ('+c[2]+')' if c[2]}}</option>{% endfor %}</select>
<button onclick="return confirm('Submit this vote? It cannot be changed here.')">Vote</button></form>{% endif %}</section>
<section class="panel"><h3>Recent ballots</h3>{% if recent %}<div class="table-wrap"><table><thead><tr><th>#</th><th>Voter</th><th>Candidate</th><th>Party</th></tr></thead><tbody>
{% for r in recent %}<tr><td>{{r[0]}}</td><td>{{r[1]}}</td><td>{{r[2]}}</td><td>{{r[3] or '—'}}</td></tr>{% endfor %}</tbody></table></div>{% else %}<div class="empty">No votes yet.</div>{% endif %}</section>{% endblock %}""",

"results.html": """{% extends "base.html" %}{% block title %}Election results{% endblock %}{% block body %}
<div class="page-heading"><div><h1>Results</h1><p>{{total}} vote(s) from {{nvoters}} registered voter(s){% if nvoters %} · turnout {{(100*total/nvoters)|round|int}}%{% endif %}</p></div></div>
{% if winners %}<div class="msg ok">{{'Leading: ' if winners|length==1 else 'Tied for the lead: '}}{{winners|join(', ')}} ({{top}} vote{{'s' if top!=1}})</div>{% endif %}
<section class="panel"><div class="table-wrap"><table><thead><tr><th>Rank</th><th>Candidate</th><th>Party</th><th>Votes</th><th>Share</th></tr></thead><tbody>
{% for r in rows %}<tr class="{{'win' if top and r[2]==top}}"><td>{{loop.index}}</td><td>{{r[0]}}</td><td>{{r[1] or '—'}}</td><td><span class="pill">{{r[2]}}</span></td>
<td><div class="bar"><i style="width:{{(100*r[2]/total)|round|int if total else 0}}%"></i></div> {{(100*r[2]/total)|round|int if total else 0}}%</td></tr>
{% else %}<tr><td colspan="5" class="empty">No candidates yet.</td></tr>{% endfor %}</tbody></table></div></section>{% endblock %}""",

"sql.html": """{% extends "base.html" %}{% block title %}Query workspace{% endblock %}{% block body %}
<div class="page-heading"><div><h1>SQL console</h1><p>SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, DROP… Several statements run as one transaction.</p></div></div>
<section class="panel"><div class="chips">{% for lbl,code in [('SELECT','SELECT * FROM voters;'),('JOIN','SELECT vo.name, c.name AS candidate FROM votes v JOIN voters vo ON vo.id=v.voter_id JOIN candidates c ON c.id=v.candidate_id;'),
('GROUP BY','SELECT party, COUNT(*) AS n FROM candidates GROUP BY party HAVING n>=1;'),('Subquery','SELECT name FROM voters WHERE id NOT IN (SELECT voter_id FROM votes);'),
('UPDATE',\"UPDATE voters SET city='Vellore' WHERE id=1;\"),('DELETE','DELETE FROM votes WHERE id=1;')] %}<button type="button" onclick='document.getElementById("sqlbox").value={{code|tojson}}'>{{lbl}}</button>{% endfor %}</div>
<form method="post"><textarea id="sqlbox" name="sql" rows="6" placeholder="SELECT * FROM voters;">{{s}}</textarea><br>
<label style="min-width:0"><input type="checkbox" name="dry" {{'checked' if request.form.get('dry')}}> Test only (ROLLBACK at the end)</label><br><button>Run</button></form>
<p class="muted">Tables: {{tabs|join(', ') or 'none yet'}}</p>
{% if cols %}<div class="table-wrap"><table><thead><tr>{% for c in cols %}<th>{{c}}</th>{% endfor %}</tr></thead><tbody>{% for r in rows %}<tr>{% for x in r %}<td>{{x if x is not none else '—'}}</td>{% endfor %}</tr>{% endfor %}</tbody></table></div>{% endif %}</section>{% endblock %}""",
}
TEMPLATES["base.html"] = TEMPLATES["base.html"]
app.jinja_loader = DictLoader(TEMPLATES)

init()
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
