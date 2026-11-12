
import os
import sqlite3
import secrets
import string
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_from_directory, abort
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE = os.path.abspath(os.path.dirname(__file__))
DATA = os.environ.get("DATA_DIR", os.path.join(BASE, "storage"))
UPLOADS = os.path.join(DATA, "uploads")
DB_PATH = os.path.join(DATA, "sharebox.db")

os.makedirs(UPLOADS, exist_ok=True)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret")
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            code TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner INTEGER NOT NULL,
            filename TEXT NOT NULL,
            stored TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner INTEGER NOT NULL,
            requester INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            UNIQUE(owner, requester)
        );
        """)

init_db()

def make_code():
    chars = string.ascii_uppercase + string.digits
    return "SB-" + "".join(secrets.choice(chars) for _ in range(8))

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "uid" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

@app.route("/")
def index():
    return redirect(url_for("dashboard")) if session.get("uid") else render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if "@" not in email:
            flash("أدخل بريداً إلكترونياً صحيحاً.")
        elif len(password) < 8:
            flash("كلمة المرور يجب أن تكون 8 أحرف على الأقل.")
        elif password != confirm:
            flash("كلمتا المرور غير متطابقتين.")
        else:
            try:
                with db() as con:
                    con.execute(
                        "INSERT INTO users(email,password,code) VALUES(?,?,?)",
                        (email, generate_password_hash(password), make_code())
                    )
                flash("تم إنشاء الحساب. يمكنك تسجيل الدخول.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("هذا البريد مسجل مسبقاً.")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with db() as con:
            user = con.execute(
                "SELECT * FROM users WHERE email=?", (email,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session.clear()
            session["uid"] = user["id"]
            return redirect(url_for("dashboard"))

        flash("بيانات الدخول غير صحيحة.")

    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
@login_required
def dashboard():
    with db() as con:
        user = con.execute(
            "SELECT * FROM users WHERE id=?", (session["uid"],)
        ).fetchone()

        files = con.execute(
            "SELECT * FROM files WHERE owner=? ORDER BY id DESC",
            (session["uid"],)
        ).fetchall()

        incoming = con.execute("""
            SELECT r.*, u.email
            FROM requests r JOIN users u ON u.id=r.requester
            WHERE r.owner=? ORDER BY r.id DESC
        """, (session["uid"],)).fetchall()

        approved = con.execute("""
            SELECT r.*, u.email
            FROM requests r JOIN users u ON u.id=r.owner
            WHERE r.requester=? AND r.status='approved'
        """, (session["uid"],)).fetchall()

    return render_template(
        "dashboard.html", user=user,
        files=files, incoming=incoming, approved=approved
    )

@app.route("/upload", methods=["POST"])
@login_required
def upload():
    count = 0

    for item in request.files.getlist("files"):
        if not item or not item.filename:
            continue

        filename = secure_filename(item.filename)
        if not filename:
            continue

        stored = secrets.token_hex(16) + "_" + filename
        item.save(os.path.join(UPLOADS, stored))

        with db() as con:
            con.execute(
                "INSERT INTO files(owner,filename,stored) VALUES(?,?,?)",
                (session["uid"], filename, stored)
            )
        count += 1

    flash(f"تم رفع {count} ملف.")
    return redirect(url_for("dashboard"))

@app.route("/request-access", methods=["POST"])
@login_required
def request_access():
    code = request.form.get("code", "").strip().upper()

    with db() as con:
        owner = con.execute(
            "SELECT id FROM users WHERE code=?", (code,)
        ).fetchone()

        if not owner:
            flash("الرمز غير صحيح.")
        elif owner["id"] == session["uid"]:
            flash("لا يمكنك استخدام رمزك الخاص.")
        else:
            old = con.execute(
                "SELECT * FROM requests WHERE owner=? AND requester=?",
                (owner["id"], session["uid"])
            ).fetchone()

            if old:
                if old["status"] == "pending":
                    flash("طلبك ما زال قيد الانتظار.")
                else:
                    con.execute(
                        "UPDATE requests SET status='pending' WHERE id=?",
                        (old["id"],)
                    )
                    flash("تم إرسال طلب جديد.")
            else:
                con.execute(
                    "INSERT INTO requests(owner,requester,status) VALUES(?,?,'pending')",
                    (owner["id"], session["uid"])
                )
                flash("تم إرسال طلبك إلى صاحب الملفات.")

    return redirect(url_for("dashboard"))

@app.route("/decision/<int:rid>/<action>", methods=["POST"])
@login_required
def decision(rid, action):
    if action not in ("approve", "reject"):
        abort(404)

    status = "approved" if action == "approve" else "rejected"

    with db() as con:
        result = con.execute(
            "UPDATE requests SET status=? WHERE id=? AND owner=?",
            (status, rid, session["uid"])
        )
        if result.rowcount == 0:
            abort(404)

    flash("تم تحديث الطلب.")
    return redirect(url_for("dashboard"))

@app.route("/shared/<int:owner_id>")
@login_required
def shared(owner_id):
    with db() as con:
        allowed = con.execute(
            """SELECT id FROM requests
            WHERE owner=? AND requester=? AND status='approved'""",
            (owner_id, session["uid"])
        ).fetchone()

        if not allowed:
            abort(403)

        owner = con.execute(
            "SELECT email FROM users WHERE id=?", (owner_id,)
        ).fetchone()

        files = con.execute(
            "SELECT * FROM files WHERE owner=?", (owner_id,)
        ).fetchall()

    return render_template("shared.html", owner=owner, files=files)

@app.route("/download/<int:file_id>")
@login_required
def download(file_id):
    with db() as con:
        item = con.execute(
            "SELECT * FROM files WHERE id=?", (file_id,)
        ).fetchone()

        if not item:
            abort(404)

        allowed = item["owner"] == session["uid"]

        if not allowed:
            allowed = con.execute(
                """SELECT id FROM requests
                WHERE owner=? AND requester=? AND status='approved'""",
                (item["owner"], session["uid"])
            ).fetchone() is not None

        if not allowed:
            abort(403)

    return send_from_directory(
        UPLOADS, item["stored"],
        as_attachment=True,
        download_name=item["filename"]
    )

@app.errorhandler(413)
def too_large(error):
    return "حجم الملف أكبر من الحد المسموح (100 ميجابايت).", 413

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
