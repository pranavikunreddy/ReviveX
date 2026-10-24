
import os
import sqlite3
from functools import wraps
from flask import (
    Flask, render_template, request,
redirect, url_for, session, flash, abort
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Use an environment variable before deployment.
app.config["SECRET_KEY"] = os.environ.get(
    "REVIVEX_SECRET_KEY", "local-development-key-change-before-deployment"
)

DATABASE = os.path.join(app.root_path, "revivex.db")


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn



def init_db():
    with get_db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                description TEXT NOT NULL,
                technologies TEXT DEFAULT '',
                status TEXT NOT NULL DEFAULT 'On Hold',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)



def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped_view


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if len(username) < 3 or len(username) > 40:
            flash("Username must be 3 to 40 characters.")
            return redirect(url_for("signup"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.")
            return redirect(url_for("signup"))

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO users
                       (username, email, password_hash)
                       VALUES (?, ?, ?)""",
                    (username, email, password_hash)
                )
        except sqlite3.IntegrityError:
            flash("This email is already registered.")
            return redirect(url_for("signup"))

        flash("Account created! Please login.")
        return redirect(url_for("login"))

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE email = ?",
                (email,)
            ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))

        flash("Invalid email or password.")

    return render_template("login.html")



@app.route("/dashboard")
@login_required
def dashboard():
    with get_db() as conn:
        projects = conn.execute(
            """SELECT * FROM projects
               WHERE user_id = ?
               ORDER BY id DESC""",
            (session["user_id"],)
        ).fetchall()

    return render_template(
        "dashboard.html",
        username=session["username"],
        projects=projects
    )

    
@app.route("/projects/add", methods=["GET", "POST"])
@login_required
def add_project():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        technologies = request.form.get("technologies", "").strip()
        status = request.form.get("status", "On Hold")

        allowed_statuses = ["Abandoned", "On Hold", "In Progress"]

        if not name or not description:
            flash("Project name and description are required.")
            return redirect(url_for("add_project"))

        if status not in allowed_statuses:
            flash("Please choose a valid project status.")
            return redirect(url_for("add_project"))

        with get_db() as conn:
            conn.execute(
                """INSERT INTO projects
                   (user_id, name, description, technologies, status)
                   VALUES (?, ?, ?, ?, ?)""",
                (session["user_id"], name, description,
                 technologies, status)
            )

        flash("Project saved successfully!")
        return redirect(url_for("dashboard"))

    return render_template("add_project.html")


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    with get_db() as conn:
        project = conn.execute(
            """SELECT * FROM projects
               WHERE id = ? AND user_id = ?""",
            (project_id, session["user_id"])
        ).fetchone()

    if project is None:
        abort(404)

    return render_template(
        "project_detail.html",
        project=project
    )

@app.route("/projects/<int:project_id>/edit", methods=["GET", "POST"])
@login_required
def edit_project(project_id):
    with get_db() as conn:
        project = conn.execute(
            """SELECT * FROM projects
               WHERE id = ? AND user_id = ?""",
            (project_id, session["user_id"])
        ).fetchone()

        if project is None:
            abort(404)

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            description = request.form.get("description", "").strip()
            technologies = request.form.get("technologies", "").strip()
            status = request.form.get("status", "")

            allowed_statuses = ["Abandoned", "On Hold", "In Progress"]

            if not name or not description:
                flash("Name and description are required.")
                return redirect(
                    url_for("edit_project", project_id=project_id)
                )

            if status not in allowed_statuses:
                flash("Please choose a valid project status.")
                return redirect(
                    url_for("edit_project", project_id=project_id)
                )

            conn.execute(
                """UPDATE projects
                   SET name = ?, description = ?,
                       technologies = ?, status = ?
                   WHERE id = ? AND user_id = ?""",
                (name, description, technologies, status,
                 project_id, session["user_id"])
            )

            flash("Project updated successfully!")
            return redirect(
                url_for("project_detail", project_id=project_id)
            )

    return render_template("edit_project.html", project=project)


@app.route("/projects/<int:project_id>/delete", methods=["POST"])
@login_required
def delete_project(project_id):
    with get_db() as conn:
        project = conn.execute(
            """SELECT id FROM projects
               WHERE id = ? AND user_id = ?""",
            (project_id, session["user_id"])
        ).fetchone()

        if project is None:
            abort(404)

        conn.execute(
            """DELETE FROM projects
               WHERE id = ? AND user_id = ?""",
            (project_id, session["user_id"])
        )

    flash("Project deleted successfully!")
    return redirect(url_for("dashboard"))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have logged out.")
    return redirect(url_for("home"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
