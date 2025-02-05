import os
import uuid
import psycopg2
from datetime import timedelta
import dotenv
import requests
from flask import Flask, request, redirect, render_template, g, url_for, make_response
from flask_socketio import SocketIO, emit

# Load environment variables from .env file
dotenv.load_dotenv(".env")

CLIENT_ID = os.environ.get("TIGOL_CLIENT_ID")
CLIENT_SECRET = os.environ.get("TIGOL_CLIENT_SECRET")
REDIRECT_URI = os.environ.get("TIGOL_REDIRECT_URI")
DATABASE_URL = os.getenv("DB_DSN")

API_BASE_URL = "https://api.tigol.net"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")
app.permanent_session_lifetime = timedelta(days=2)

socketio = SocketIO(app, async_mode="threading")

USER_SESSIONS = {}

def get_custom_session():
    session_id = request.cookies.get("session_id")
    if session_id is None or session_id not in USER_SESSIONS:
        session_id = str(uuid.uuid4())
        USER_SESSIONS[session_id] = {}
    return session_id, USER_SESSIONS[session_id]

def update_custom_session(session_id, data):
    USER_SESSIONS[session_id] = data

# Database helper functions
def get_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = get_db()
    with db.cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS authorized_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL
            )
            """
        )
    print("Database initialized.")

def get_user_data_with_token(token):
    user_response = requests.get(
        f"{API_BASE_URL}/auth/v1/user/me",
        headers={"Authorization": f"Bearer {token}"}
    )
    user_response.raise_for_status()
    return user_response.json()

@app.route("/")
def index():
    oauth_url = (
        f"https://www.tigol.net/oauth/authorize"
        f"?client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT_URI}"
        f"&scope=user:read"
    )
    return redirect(oauth_url)

@app.route("/authorized")
def authorized():
    code = request.args.get("code")
    if not code:
        return "Missing authorization code", 400

    session_id, custom_session = get_custom_session()
    custom_session["auth_code"] = code
    update_custom_session(session_id, custom_session)

    resp = make_response(redirect(url_for("loading")))
    resp.set_cookie("session_id", session_id)
    return resp

@app.route("/loading")
def loading():
    return render_template("loading.html")

@app.route("/display")
def display():
    session_id, custom_session = get_custom_session()
    user_data = custom_session.get("user_data")
    if not user_data:
        return render_template("error.html", error_message="Session expired. Log in again.")
    
    username = user_data.get("username")
    if username:
        db = get_db()
        try:
            with db.cursor() as cur:
                cur.execute("INSERT INTO authorized_users (username) VALUES (%s) ON CONFLICT DO NOTHING", (username,))
        except psycopg2.Error as e:
            print("Database error:", e)

    with get_db().cursor() as cur:
        cur.execute("SELECT username FROM authorized_users ORDER BY username ASC")
        users = [row[0] for row in cur.fetchall()]
    
    return render_template("authorized.html", user_data=user_data, users=users)

@socketio.on("start_auth")
def handle_start_auth():
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in USER_SESSIONS:
        emit("error", {"msg": "No valid session found."})
        return

    custom_session = USER_SESSIONS[session_id]

    if custom_session.get("token") and custom_session.get("user_data"):
        emit("progress", {"msg": "Using cached token and user data."})
        emit("done", {"redirect": url_for("display")})
        return

    code = custom_session.get("auth_code")
    if not code:
        emit("error", {"msg": "No authorization code found in session."})
        return

    try:
        emit("progress", {"msg": "Exchanging code for token..."})
        auth_data = {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET, "code": code}
        response = requests.post(f"{API_BASE_URL}/auth/oidc/token", json=auth_data)
        response.raise_for_status()

        token = response.json()["access_token"]
        emit("progress", {"msg": "Retrieving user data..."})
        user_data = get_user_data_with_token(token)

        custom_session["token"] = token
        custom_session["user_data"] = user_data
        update_custom_session(session_id, custom_session)

        emit("progress", {"msg": "Done!"})
        emit("done", {"redirect": url_for("display")})
    except Exception as e:
        emit("error", {"msg": f"Error: {str(e)}"})

def get_app() -> Flask:
    with app.app_context():
        init_db()
    return app

if __name__ == "__main__":
    with app.app_context():
        init_db()
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True)
