# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os

# app and config
app = Flask(__name__)
app.secret_key = os.environ.get("EDUPATH_SECRET", "dev-secret-key-change-me")
DB_PATH = "edupath.db"

# Session config
app.permanent_session_lifetime = timedelta(hours=2)  # auto logout after 2 hrs

# Database helpers
def get_db_connection():
    """Create a new database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with required tables."""
    conn = get_db_connection()
    c = conn.cursor()

    # Users table
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Interests table
    c.execute("""
        CREATE TABLE IF NOT EXISTS interests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            interest TEXT NOT NULL,
            level TEXT,
            style TEXT,
            topic TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

# ---------------- Resource Data ----------------
RESOURCES = {
    "AI / Machine Learning": [
        {"title": "Intro to Machine Learning", "link": "https://www.coursera.org/learn/machine-learning", "type": "Course"},
        {"title": "Deep Learning Specialization", "link": "https://www.coursera.org/specializations/deep-learning", "type": "Course"},
        {"title": "Hands-On Machine Learning with Scikit-Learn & TensorFlow", "link": "https://www.oreilly.com/library/view/hands-on-machine-learning/9781491962282/", "type": "Book"},
    ],
    "Web Development": [
        {"title": "The Odin Project", "link": "https://www.theodinproject.com/", "type": "Free Curriculum"},
        {"title": "FreeCodeCamp Web Dev", "link": "https://www.freecodecamp.org/learn", "type": "Free Course"},
        {"title": "MDN Web Docs", "link": "https://developer.mozilla.org/", "type": "Documentation"},
    ],
    "Data Science": [
        {"title": "Python for Data Science", "link": "https://www.datacamp.com/tracks/data-scientist-with-python", "type": "Course"},
        {"title": "Kaggle Learn", "link": "https://www.kaggle.com/learn", "type": "Free Tutorials"},
        {"title": "Data Science Handbook", "link": "https://jakevdp.github.io/PythonDataScienceHandbook/", "type": "Book"},
    ],
    "Cybersecurity": [
        {"title": "TryHackMe", "link": "https://tryhackme.com/", "type": "Interactive Labs"},
        {"title": "Introduction to Cybersecurity - Cisco", "link": "https://www.netacad.com/courses/cybersecurity/introduction-cybersecurity", "type": "Course"},
        {"title": "OWASP Top 10", "link": "https://owasp.org/www-project-top-ten/", "type": "Guide"},
    ],
    "Math": [
        {"title": "Khan Academy Mathematics", "link": "https://www.khanacademy.org/math", "type": "Lessons"},
        {"title": "Paul’s Online Math Notes", "link": "https://tutorial.math.lamar.edu/", "type": "Notes"},
        {"title": "3Blue1Brown", "link": "https://www.3blue1brown.com/", "type": "Visual Learning"},
    ],
    "Physics": [
        {"title": "MIT OpenCourseWare Physics", "link": "https://ocw.mit.edu/courses/physics/", "type": "Course"},
        {"title": "Physics Classroom", "link": "https://www.physicsclassroom.com/", "type": "Lessons"},
        {"title": "MinutePhysics YouTube", "link": "https://www.youtube.com/user/minutephysics", "type": "Videos"},
    ],
    "Languages": [
        {"title": "Duolingo", "link": "https://www.duolingo.com/", "type": "App"},
        {"title": "BBC Languages", "link": "http://www.bbc.co.uk/languages", "type": "Guide"},
        {"title": "LingQ", "link": "https://www.lingq.com/", "type": "Platform"},
    ],
}

# ---------------- Routes ----------------
@app.route("/")
def home():
    """Landing page. Redirect logged-in users to interests."""
    if session.get("user_id"):
        return redirect(url_for("interests"))
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """User registration with validation and hashing."""
    if session.get("user_id"):
        return redirect(url_for("interests"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        password_confirm = request.form.get("password_confirm", "")

        if not username or not email or not password:
            flash("Please fill all required fields.", "danger")
            return redirect(url_for("register"))
        if password != password_confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        hashed = generate_password_hash(password, method="pbkdf2:sha256", salt_length=16)

        try:
            conn = get_db_connection()
            c = conn.cursor()
            c.execute(
                "INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                (username, email, hashed),
            )
            conn.commit()
            conn.close()
            flash("Registration successful. Please log in.", "success")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username or email already exists. Try another.", "danger")
            return redirect(url_for("register"))
        except Exception as e:
            flash(f"Registration failed: {str(e)}", "danger")
            return redirect(url_for("register"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """User login with password check."""
    if session.get("user_id"):
        return redirect(url_for("interests"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, username, password FROM users WHERE email = ?", (email,))
        row = c.fetchone()
        conn.close()

        if row and check_password_hash(row["password"], password):
            session.permanent = True
            session["user_id"] = row["id"]
            session["username"] = row["username"]
            flash("Logged in successfully.", "success")
            return redirect(url_for("interests"))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Clear session and log out user."""
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))

@app.route("/interests", methods=["GET", "POST"])
def interests():
    """Protected route: add and view user interests."""
    if not session.get("user_id"):
        flash("Please log in to access this page.", "warning")
        return redirect(url_for("login"))

    user_id = session["user_id"]

    if request.method == "POST":
        selected = request.form.getlist("interest")
        level = request.form.get("level", "").strip()
        style = request.form.get("style", "").strip()
        topic = request.form.get("topic", "").strip()

        if not selected:
            flash("Please select at least one interest.", "danger")
            return redirect(url_for("interests"))

        try:
            conn = get_db_connection()
            c = conn.cursor()
            for interest in selected:
                c.execute(
                    """
                    INSERT INTO interests 
                    (user_id, interest, level, style, topic, created_at) 
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (user_id, interest, level, style, topic, datetime.utcnow().isoformat()),
                )
            conn.commit()
            conn.close()
            flash("Your interests were saved.", "success")
        except Exception as e:
            flash(f"Error saving interests: {str(e)}", "danger")

        return redirect(url_for("interests"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        """
        SELECT interest, level, style, topic, created_at 
        FROM interests 
        WHERE user_id = ? 
        ORDER BY created_at DESC
        """,
        (user_id,),
    )
    saved = c.fetchall()
    conn.close()

    return render_template("interests.html",
                           username=session.get("username"),
                           saved_interests=saved)

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    """User dashboard: shows selected interests with resource links."""
    if "user_id" not in session:
        return redirect(url_for("login"))

    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT interest FROM interests WHERE user_id = ?", (session["user_id"],))
    user_interests = [row["interest"] for row in c.fetchall()]
    conn.close()

    selected_resources = {}
    if request.method == "POST":
        selected_interest = request.form.get("interest")
        if selected_interest in RESOURCES:
            selected_resources[selected_interest] = RESOURCES[selected_interest]

    return render_template(
        "dashboard.html",
        interests=user_interests,
        username=session["username"],
        selected_resources=selected_resources
    )



@app.route("/resources")
def resources():
    if "user_id" not in session:
        return redirect(url_for("login"))

    interest = request.args.get("interest")
    if not interest:
        flash("No interest selected.", "warning")
        return redirect(url_for("dashboard"))

    resources = RESOURCES.get(interest, [])

    return render_template(
        "resources.html",
        interest=interest,
        resources=resources,
        username=session.get("username")
    )



# ---------------- Run ----------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

