"""
MOU Portal — a small, self-contained Flask app that lets each region's
representative register, log in, download the MOU form, fill in the on-screen
details, upload the signed hardcopy (PDF) plus any supporting documents, and
submit. An admin (the boss) logs in to see which regions have submitted and to
download every form and attachment.

Deliberately dependency-light (Flask only) and backed by SQLite so it can be
dropped onto the existing cPanel account with no database to provision. Deploys
the same Passenger way as the UCP app, mounted at hrdnexus.org/mou.

CLI:
    python app.py init-db
    python app.py create-admin boss@example.com "S3cret!" "Director, HRD"
    python app.py list-users
"""

import os
import sqlite3
import secrets
import zipfile
import io
import sys
from datetime import datetime, date
from functools import wraps

from flask import (
    Flask, g, session, request, redirect, url_for, render_template,
    flash, send_file, abort, Response,
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from fpdf import FPDF
from fpdf.enums import XPos, YPos

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
DB_PATH = os.path.join(INSTANCE_DIR, "mou.db")

# Ghana's 16 regions — the submitting units.
REGIONS = [
    "Ahafo", "Ashanti", "Bono", "Bono East", "Central", "Eastern",
    "Greater Accra", "North East", "Northern", "Oti", "Savannah",
    "Upper East", "Upper West", "Volta", "Western", "Western North",
]

# What the signed MOU may be uploaded as (PDF only — it is a signed letter).
SIGNED_MOU_EXTS = {"pdf"}
# Supporting documents may be a PDF or a scan/photo.
SUPPORTING_EXTS = {"pdf", "jpg", "jpeg", "png"}
MAX_UPLOAD_MB = 15


# --------------------------------------------------------------------------- #
# Database                                                                     #
# --------------------------------------------------------------------------- #

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    region        TEXT,
    full_name     TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    phone         TEXT,
    position      TEXT,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'rep',   -- 'rep' | 'admin'
    created_at    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS submissions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER NOT NULL,
    region             TEXT NOT NULL,
    purpose            TEXT,
    commencement_date  TEXT,
    expiry_date        TEXT,
    signatory_name     TEXT,
    signatory_position TEXT,
    date_signed        TEXT,
    agreed             INTEGER NOT NULL DEFAULT 0,
    remarks            TEXT,
    status             TEXT NOT NULL DEFAULT 'draft',   -- 'draft' | 'submitted'
    created_at         TEXT NOT NULL,
    submitted_at       TEXT,
    updated_at         TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS documents (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    submission_id INTEGER NOT NULL,
    kind          TEXT NOT NULL,            -- 'signed_mou' | 'supporting'
    original_name TEXT NOT NULL,
    stored_name   TEXT NOT NULL,
    size_bytes    INTEGER,
    uploaded_at   TEXT NOT NULL,
    FOREIGN KEY (submission_id) REFERENCES submissions (id)
);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    os.makedirs(INSTANCE_DIR, exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.executescript(SCHEMA)
    _migrate(con)
    con.commit()
    con.close()


def _migrate(con):
    """Add any columns introduced after a database was first created."""
    have = {r[1] for r in con.execute("PRAGMA table_info(submissions)").fetchall()}
    for name, ddl in (("purpose", "TEXT"), ("commencement_date", "TEXT"),
                      ("expiry_date", "TEXT")):
        if name not in have:
            con.execute(f"ALTER TABLE submissions ADD COLUMN {name} {ddl}")


# --------------------------------------------------------------------------- #
# App factory                                                                  #
# --------------------------------------------------------------------------- #

def create_app():
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("MOU_SECRET_KEY", "dev-only-change-me-on-server"),
        MAX_CONTENT_LENGTH=MAX_UPLOAD_MB * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    init_db()
    app.teardown_appcontext(close_db)

    # ----- helpers -------------------------------------------------------- #

    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    @app.context_processor
    def inject_globals():
        return {"current_user": current_user(), "current_year": date.today().year}

    def login_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            if not current_user():
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return wrapped

    def admin_required(view):
        @wraps(view)
        def wrapped(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("login", next=request.path))
            if u["role"] != "admin":
                abort(403)
            return view(*a, **kw)
        return wrapped

    # Lightweight CSRF: a per-session token echoed in every state-changing form.
    def csrf_token():
        tok = session.get("_csrf")
        if not tok:
            tok = secrets.token_urlsafe(32)
            session["_csrf"] = tok
        return tok

    app.jinja_env.globals["csrf_token"] = csrf_token

    def check_csrf():
        if request.form.get("_csrf", "") != session.get("_csrf", ""):
            abort(400, "Invalid or missing form token. Please reload and try again.")

    def my_submission(user_id, create=False):
        db = get_db()
        row = db.execute(
            "SELECT * FROM submissions WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user_id,),
        ).fetchone()
        if row is None and create:
            u = db.execute("SELECT region FROM users WHERE id = ?", (user_id,)).fetchone()
            now = datetime.utcnow().isoformat(timespec="seconds")
            cur = db.execute(
                "INSERT INTO submissions (user_id, region, status, created_at) VALUES (?,?, 'draft', ?)",
                (user_id, u["region"] or "", now),
            )
            db.commit()
            row = db.execute("SELECT * FROM submissions WHERE id = ?", (cur.lastrowid,)).fetchone()
        return row

    def docs_for(submission_id):
        return get_db().execute(
            "SELECT * FROM documents WHERE submission_id = ? ORDER BY kind, id",
            (submission_id,),
        ).fetchall()

    # ----- public / auth -------------------------------------------------- #

    @app.route("/")
    def index():
        u = current_user()
        if u:
            return redirect(url_for("admin" if u["role"] == "admin" else "dashboard"))
        return render_template("index.html")

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if current_user():
            return redirect(url_for("index"))
        if request.method == "POST":
            check_csrf()
            f = {k: request.form.get(k, "").strip() for k in
                 ("full_name", "email", "phone", "position", "region", "password", "confirm")}
            errors = []
            if not f["full_name"]:
                errors.append("Your full name is required.")
            if not f["email"] or "@" not in f["email"]:
                errors.append("A valid email address is required.")
            if f["region"] not in REGIONS:
                errors.append("Please choose your region.")
            if len(f["password"]) < 8:
                errors.append("Password must be at least 8 characters.")
            if f["password"] != f["confirm"]:
                errors.append("The two passwords do not match.")
            db = get_db()
            if f["email"] and db.execute("SELECT 1 FROM users WHERE email = ?",
                                         (f["email"].lower(),)).fetchone():
                errors.append("An account with that email already exists — please log in instead.")
            if errors:
                for e in errors:
                    flash(e, "error")
                return render_template("register.html", regions=REGIONS, form=f)
            db.execute(
                """INSERT INTO users (region, full_name, email, phone, position,
                                      password_hash, role, created_at)
                   VALUES (?,?,?,?,?,?, 'rep', ?)""",
                (f["region"], f["full_name"], f["email"].lower(), f["phone"], f["position"],
                 generate_password_hash(f["password"], method="pbkdf2:sha256"),
                 datetime.utcnow().isoformat(timespec="seconds")),
            )
            db.commit()
            flash("Account created — please log in.", "success")
            return redirect(url_for("login"))
        return render_template("register.html", regions=REGIONS, form={})

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if current_user():
            return redirect(url_for("index"))
        if request.method == "POST":
            check_csrf()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            row = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row and check_password_hash(row["password_hash"], password):
                session.clear()
                session["user_id"] = row["id"]
                csrf_token()
                nxt = request.args.get("next") or url_for("index")
                return redirect(nxt)
            flash("Invalid email or password.", "error")
            return render_template("login.html", email=email)
        return render_template("login.html", email="")

    @app.route("/logout", methods=["POST"])
    def logout():
        check_csrf()
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    # ----- representative dashboard -------------------------------------- #

    @app.route("/dashboard")
    @login_required
    def dashboard():
        u = current_user()
        if u["role"] == "admin":
            return redirect(url_for("admin"))
        sub = my_submission(u["id"])
        docs = docs_for(sub["id"]) if sub else []
        has_signed = any(d["kind"] == "signed_mou" for d in docs)
        details_ready = bool(sub and sub["purpose"] and sub["signatory_name"]
                             and sub["signatory_position"])
        return render_template(
            "dashboard.html", sub=sub, docs=docs, has_signed=has_signed,
            details_ready=details_ready,
        )

    @app.route("/submission/save", methods=["POST"])
    @login_required
    def submission_save():
        check_csrf()
        u = current_user()
        if u["role"] == "admin":
            abort(403)
        sub = my_submission(u["id"], create=True)
        if sub["status"] == "submitted":
            flash("Your MOU has already been submitted and is locked.", "error")
            return redirect(url_for("dashboard"))
        db = get_db()
        db.execute(
            """UPDATE submissions
               SET purpose = ?, commencement_date = ?, expiry_date = ?,
                   signatory_name = ?, signatory_position = ?,
                   agreed = ?, remarks = ?, updated_at = ?
               WHERE id = ?""",
            (request.form.get("purpose", "").strip(),
             request.form.get("commencement_date", "").strip(),
             request.form.get("expiry_date", "").strip(),
             request.form.get("signatory_name", "").strip(),
             request.form.get("signatory_position", "").strip(),
             1 if request.form.get("agreed") else 0,
             request.form.get("remarks", "").strip(),
             datetime.utcnow().isoformat(timespec="seconds"),
             sub["id"]),
        )
        db.commit()
        flash("Your details were saved.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/submission/upload", methods=["POST"])
    @login_required
    def submission_upload():
        check_csrf()
        u = current_user()
        if u["role"] == "admin":
            abort(403)
        sub = my_submission(u["id"], create=True)
        if sub["status"] == "submitted":
            flash("Your MOU has already been submitted and is locked.", "error")
            return redirect(url_for("dashboard"))

        kind = request.form.get("kind")
        if kind not in ("signed_mou", "supporting"):
            abort(400)
        file = request.files.get("file")
        if not file or not file.filename:
            flash("Please choose a file to upload.", "error")
            return redirect(url_for("dashboard"))

        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        allowed = SIGNED_MOU_EXTS if kind == "signed_mou" else SUPPORTING_EXTS
        if ext not in allowed:
            flash(
                ("The signed MOU must be a PDF." if kind == "signed_mou"
                 else "Supporting files must be a PDF or image (jpg/png)."),
                "error",
            )
            return redirect(url_for("dashboard"))

        db = get_db()
        # Only one signed MOU — replace any existing one.
        if kind == "signed_mou":
            for old in db.execute(
                "SELECT * FROM documents WHERE submission_id = ? AND kind = 'signed_mou'",
                (sub["id"],),
            ).fetchall():
                _remove_file(old["stored_name"])
                db.execute("DELETE FROM documents WHERE id = ?", (old["id"],))

        stored = f"{sub['id']}_{kind}_{secrets.token_hex(6)}_{secure_filename(file.filename)}"
        path = os.path.join(UPLOAD_DIR, stored)
        file.save(path)
        db.execute(
            """INSERT INTO documents (submission_id, kind, original_name, stored_name,
                                      size_bytes, uploaded_at)
               VALUES (?,?,?,?,?,?)""",
            (sub["id"], kind, file.filename, stored, os.path.getsize(path),
             datetime.utcnow().isoformat(timespec="seconds")),
        )
        db.commit()
        flash("File uploaded.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/submission/document/<int:doc_id>/delete", methods=["POST"])
    @login_required
    def submission_doc_delete(doc_id):
        check_csrf()
        u = current_user()
        db = get_db()
        doc = db.execute(
            """SELECT d.* FROM documents d
               JOIN submissions s ON s.id = d.submission_id
               WHERE d.id = ? AND s.user_id = ?""",
            (doc_id, u["id"]),
        ).fetchone()
        if not doc:
            abort(404)
        sub = db.execute("SELECT * FROM submissions WHERE id = ?", (doc["submission_id"],)).fetchone()
        if sub["status"] == "submitted":
            flash("Your MOU has already been submitted and is locked.", "error")
            return redirect(url_for("dashboard"))
        _remove_file(doc["stored_name"])
        db.execute("DELETE FROM documents WHERE id = ?", (doc_id,))
        db.commit()
        flash("File removed.", "success")
        return redirect(url_for("dashboard"))

    @app.route("/submission/submit", methods=["POST"])
    @login_required
    def submission_submit():
        check_csrf()
        u = current_user()
        if u["role"] == "admin":
            abort(403)
        sub = my_submission(u["id"], create=True)
        if sub["status"] == "submitted":
            return redirect(url_for("dashboard"))
        if not (sub["purpose"] and sub["signatory_name"] and sub["signatory_position"]):
            flash("Please complete and save the MOU details before submitting.", "error")
            return redirect(url_for("dashboard"))
        docs = docs_for(sub["id"])
        if not any(d["kind"] == "signed_mou" for d in docs):
            flash("Please upload the signed MOU (PDF) before submitting.", "error")
            return redirect(url_for("dashboard"))
        if not sub["agreed"]:
            flash("Please tick the confirmation box, then submit.", "error")
            return redirect(url_for("dashboard"))
        db = get_db()
        now = datetime.utcnow().isoformat(timespec="seconds")
        db.execute(
            "UPDATE submissions SET status = 'submitted', submitted_at = ?, updated_at = ? WHERE id = ?",
            (now, now, sub["id"]),
        )
        db.commit()
        flash("Your MOU has been submitted. Thank you.", "success")
        return redirect(url_for("dashboard"))

    # ----- admin (boss) --------------------------------------------------- #

    @app.route("/admin")
    @admin_required
    def admin():
        db = get_db()
        rows = db.execute(
            """SELECT s.*, u.full_name, u.email, u.phone, u.position,
                      (SELECT COUNT(*) FROM documents d WHERE d.submission_id = s.id) AS doc_count
               FROM submissions s JOIN users u ON u.id = s.user_id
               ORDER BY s.status DESC, s.region"""
        ).fetchall()
        # Coverage across the 16 regions.
        submitted_regions = {r["region"] for r in rows if r["status"] == "submitted"}
        reps = db.execute(
            "SELECT region, full_name, email, phone FROM users WHERE role = 'rep' ORDER BY region"
        ).fetchall()
        return render_template(
            "admin.html", rows=rows, reps=reps, regions=REGIONS,
            submitted_regions=submitted_regions,
        )

    @app.route("/admin/submission/<int:sub_id>")
    @admin_required
    def admin_submission(sub_id):
        db = get_db()
        sub = db.execute(
            """SELECT s.*, u.full_name, u.email, u.phone, u.position
               FROM submissions s JOIN users u ON u.id = s.user_id WHERE s.id = ?""",
            (sub_id,),
        ).fetchone()
        if not sub:
            abort(404)
        return render_template("admin_detail.html", sub=sub, docs=docs_for(sub_id))

    @app.route("/admin/export.csv")
    @admin_required
    def admin_export_csv():
        import csv
        rows = get_db().execute(
            """SELECT u.region, u.full_name, u.email, u.phone, u.position,
                      s.signatory_name, s.signatory_position, s.date_signed,
                      s.status, s.submitted_at, s.remarks,
                      (SELECT COUNT(*) FROM documents d WHERE d.submission_id = s.id) AS docs
               FROM submissions s JOIN users u ON u.id = s.user_id
               ORDER BY s.region"""
        ).fetchall()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Region", "Representative", "Email", "Phone", "Position",
                    "Signatory", "Signatory position", "Date signed",
                    "Status", "Submitted at", "Remarks", "Documents"])
        for r in rows:
            w.writerow([r[k] for k in r.keys()])
        return Response(
            buf.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=mou_submissions.csv"},
        )

    @app.route("/admin/download-all.zip")
    @admin_required
    def admin_download_all():
        db = get_db()
        docs = db.execute(
            """SELECT d.*, u.region FROM documents d
               JOIN submissions s ON s.id = d.submission_id
               JOIN users u ON u.id = s.user_id
               ORDER BY u.region"""
        ).fetchall()
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, "w", zipfile.ZIP_DEFLATED) as zf:
            for d in docs:
                path = os.path.join(UPLOAD_DIR, d["stored_name"])
                if os.path.exists(path):
                    safe_region = secure_filename(d["region"] or "Unknown")
                    arc = f"{safe_region}/{d['kind']}_{d['original_name']}"
                    zf.write(path, arc)
        mem.seek(0)
        return send_file(mem, mimetype="application/zip", as_attachment=True,
                         download_name="mou_documents.zip")

    # ----- downloads ------------------------------------------------------ #

    @app.route("/submission/mou.pdf")
    @login_required
    def submission_generate():
        """Generate the rep's completed MOU as a PDF — all fields filled from the
        site, with only the signature/date lines left blank to sign by hand."""
        u = current_user()
        if u["role"] == "admin":
            abort(403)
        sub = my_submission(u["id"])
        if not sub or not (sub["purpose"] and sub["signatory_name"] and sub["signatory_position"]):
            flash("Please complete and save the MOU details first.", "error")
            return redirect(url_for("dashboard"))
        pdf = build_mou_pdf(sub, u["region"])
        return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                         download_name=f"MOU_{secure_filename(u['region'] or 'region')}.pdf")

    @app.route("/admin/submission/<int:sub_id>/mou.pdf")
    @admin_required
    def admin_submission_pdf(sub_id):
        """Let the admin download the completed (unsigned) MOU for any region."""
        sub = get_db().execute("SELECT * FROM submissions WHERE id = ?", (sub_id,)).fetchone()
        if not sub:
            abort(404)
        pdf = build_mou_pdf(sub, sub["region"])
        return send_file(io.BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                         download_name=f"MOU_{secure_filename(sub['region'] or 'region')}.pdf")

    @app.route("/download/document/<int:doc_id>")
    @login_required
    def download_document(doc_id):
        u = current_user()
        db = get_db()
        doc = db.execute(
            """SELECT d.*, s.user_id FROM documents d
               JOIN submissions s ON s.id = d.submission_id WHERE d.id = ?""",
            (doc_id,),
        ).fetchone()
        if not doc:
            abort(404)
        # Admins may download anyone's; a rep only their own.
        if u["role"] != "admin" and doc["user_id"] != u["id"]:
            abort(403)
        path = os.path.join(UPLOAD_DIR, doc["stored_name"])
        if not os.path.exists(path):
            abort(404)
        return send_file(path, as_attachment=True, download_name=doc["original_name"])

    @app.errorhandler(413)
    def too_large(_e):
        flash(f"That file is too large (max {MAX_UPLOAD_MB} MB).", "error")
        return redirect(url_for("dashboard"))

    return app


def _remove_file(stored_name):
    try:
        os.remove(os.path.join(UPLOAD_DIR, stored_name))
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# MOU document generation                                                      #
# --------------------------------------------------------------------------- #

NAVY_RGB = (15, 42, 74)
BLANK = "____________________"


def _fmt_date(s):
    if not s:
        return None
    try:
        return datetime.strptime(str(s)[:10], "%Y-%m-%d").strftime("%d %B %Y")
    except ValueError:
        return str(s)


def _ascii(s):
    """fpdf core fonts are latin-1 only — normalise the few smart characters."""
    return (str(s or "")
            .replace("’", "'").replace("‘", "'")
            .replace("“", '"').replace("”", '"')
            .replace("–", "-").replace("—", "-")
            .encode("latin-1", "replace").decode("latin-1"))


def build_mou_pdf(sub, region):
    """Render a completed MOU (all fields filled from the site) as PDF bytes,
    leaving only the signature and date lines blank for hand-signing. This is a
    generic placeholder MOU — the official wording can be substituted later."""
    region = region or sub["region"] or BLANK
    pdf = FPDF(format="A4")
    pdf.set_auto_page_break(True, margin=18)
    pdf.set_margins(22, 20, 22)
    pdf.add_page()

    def _cell(text, h=6, align="L"):
        # Return the cursor to the left margin on a new line after each block,
        # otherwise fpdf2 leaves x at the right edge and the next cell has no room.
        pdf.multi_cell(0, h, _ascii(text), align=align,
                       new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def centered(text, size, bold=False, navy=False, gap=1):
        pdf.set_font("Times", "B" if bold else "", size)
        pdf.set_text_color(*(NAVY_RGB if navy else (0, 0, 0)))
        _cell(text, h=7, align="C")
        pdf.ln(gap)

    def heading(text):
        pdf.ln(2)
        pdf.set_font("Times", "B", 12)
        pdf.set_text_color(*NAVY_RGB)
        _cell(text)
        pdf.set_text_color(0, 0, 0)

    def para(text, gap=2):
        pdf.set_font("Times", "", 11)
        pdf.set_text_color(0, 0, 0)
        _cell(text)
        pdf.ln(gap)

    def bullet(text):
        pdf.set_font("Times", "", 11)
        _cell("   -   " + text)

    def label_line(text, bold=False):
        pdf.set_font("Times", "B" if bold else "", 11)
        _cell(text)

    centered("GHANA HEALTH SERVICE", 14, bold=True, navy=True, gap=0)
    centered("Legal Unit", 11, gap=2)
    centered("MEMORANDUM OF UNDERSTANDING", 13, bold=True, navy=True, gap=3)

    para('This Memorandum of Understanding ("MOU") is made on this ______ day of '
         '____________________, 20______, BETWEEN the Ghana Health Service, acting '
         'through its Legal Unit ("the Legal Unit"), of the first part; AND the '
         f'{region} Regional Health Directorate ("the Region"), of the other part.')

    heading("1.  Purpose")
    para(sub["purpose"] or BLANK)

    heading("2.  Scope")
    para("This MOU covers the activities, standards and commitments agreed between the "
         "parties in furtherance of the purpose stated above.")

    heading("3.  Responsibilities of the Region")
    bullet("To comply with the policies, guidelines and directives of the Ghana Health Service.")
    bullet("To provide accurate and timely information to the Legal Unit as required.")
    bullet("To designate a focal person responsible for this MOU.")

    heading("4.  Responsibilities of the Legal Unit")
    bullet("To provide guidance, oversight and support to the Region.")
    bullet("To communicate relevant policies and decisions in a timely manner.")

    heading("5.  Duration")
    comm = _fmt_date(sub["commencement_date"]) or BLANK
    exp = _fmt_date(sub["expiry_date"]) or BLANK
    para(f"This MOU shall take effect from {comm} and shall remain in force until "
         f"{exp}, unless terminated earlier by mutual agreement of the parties in writing.")

    heading("6.  Review and Amendment")
    para("This MOU may be reviewed or amended at any time by the mutual written consent "
         "of both parties.")

    heading("7.  General")
    para("Nothing in this MOU is intended to create legally binding obligations that "
         "override the statutes, regulations or standing policies of the Ghana Health "
         "Service. The parties enter into this understanding in good faith.", gap=4)

    heading("Signatories")
    label_line("Signed on behalf of the Region:", bold=True)
    label_line(f"Name:  {sub['signatory_name'] or BLANK}")
    label_line(f"Position:  {sub['signatory_position'] or BLANK}")
    label_line("Signature:  ____________________          Date:  ____________________")
    pdf.ln(5)
    label_line("Signed on behalf of the Legal Unit:", bold=True)
    label_line("Name:  ____________________")
    label_line("Position:  ____________________")
    label_line("Signature:  ____________________          Date:  ____________________")

    return bytes(pdf.output())


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _cli():
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "init-db":
        init_db()
        print(f"Database ready at {DB_PATH}")
    elif cmd == "create-admin":
        if len(sys.argv) < 5:
            print('Usage: python app.py create-admin <email> <password> "<full name>"')
            return
        email, password, name = sys.argv[2].lower(), sys.argv[3], sys.argv[4]
        init_db()
        con = sqlite3.connect(DB_PATH)
        con.row_factory = sqlite3.Row
        existing = con.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        pw = generate_password_hash(password, method="pbkdf2:sha256")
        if existing:
            con.execute("UPDATE users SET password_hash = ?, role = 'admin', full_name = ? WHERE id = ?",
                        (pw, name, existing["id"]))
            print(f"Updated existing account {email} to admin.")
        else:
            con.execute(
                """INSERT INTO users (region, full_name, email, phone, position,
                                      password_hash, role, created_at)
                   VALUES (NULL, ?, ?, NULL, 'Administrator', ?, 'admin', ?)""",
                (name, email, pw, datetime.utcnow().isoformat(timespec="seconds")),
            )
            print(f"Created admin account {email}.")
        con.commit()
        con.close()
    elif cmd == "list-users":
        init_db()
        con = sqlite3.connect(DB_PATH)
        for r in con.execute("SELECT id, role, region, full_name, email FROM users ORDER BY role, region"):
            print(r)
        con.close()
    else:
        print("Commands: init-db | create-admin <email> <pw> \"<name>\" | list-users")


app = create_app()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        _cli()
    else:
        app.run(debug=True, port=5057)
