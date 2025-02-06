import os
import uuid
import psycopg2
from datetime import timedelta
import dotenv
from flask import Flask, request, redirect, render_template, g, url_for, make_response
from flask_socketio import SocketIO, emit
from tigol import TIgolApiClient
import hashlib

dotenv.load_dotenv(".env")

DATABASE_URL = os.environ.get("DB_DSN") or (
    f"postgresql://{os.environ.get('POSTGRES_USER', 'userlist')}:{os.environ.get('POSTGRES_PASSWORD', 'userlist')}"
    f"@{os.environ.get('POSTGRES_HOST', 'localhost')}:{os.environ.get('POSTGRES_PORT', '5434')}/"
    f"{os.environ.get('POSTGRES_DB', 'userlist')}"
)

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "super-secret-key")
app.permanent_session_lifetime = timedelta(days=2)

socketio = SocketIO(app, async_mode="threading")

client = TIgolApiClient(
    os.environ.get("TIGOL_CLIENT_ID"),
    os.environ.get("TIGOL_CLIENT_SECRET"),
)

USER_SESSIONS = {}

def retrieve_session():
    session_id = request.cookies.get("session_id") or str(uuid.uuid4())
    return session_id, USER_SESSIONS.setdefault(session_id, {})

def store_session(session_id, data):
    USER_SESSIONS[session_id] = data

def connect_db():
    if "db" not in g:
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = True
    return g.db

@app.teardown_appcontext
def disconnect_db(_):
    if db := g.pop("db", None):
        db.close()

def initialize_database():
    with connect_db().cursor() as cur:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS authorized_users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email_md5 TEXT UNIQUE NOT NULL
            )
            """
        )
    print("Database initialized.")

@app.route("/")
def index():
    if request.args.get("authorize") == "1":
        return redirect(client.get_authorization_url(redirect_uri=os.environ.get("TIGOL_REDIRECT_URI"), scopes=["user:read"]))
    return render_template("root.html")

@app.route("/authorized")
def authorized():
    if not (code := request.args.get("code")):
        return "Missing authorization code", 400

    session_id, session_data = retrieve_session()
    session_data["auth_code"] = code
    store_session(session_id, session_data)

    response = make_response(redirect(url_for("loading")))
    response.set_cookie("session_id", session_id)
    return response

@app.route("/loading")
def loading():
    return render_template("loading.html")

@app.route("/display")
def display():
    _, session_data = retrieve_session()
    if not (user_data := session_data.get("user_data")):
        return render_template("error.html", error_message="Session expired. Log in again.")

    username = user_data.get("username")
    email_md5 = hashlib.md5(user_data.get("email").encode()).hexdigest()
    if username:
        try:
            with connect_db().cursor() as cur:
                cur.execute("INSERT INTO authorized_users (username, email_md5) VALUES (%s, %s) ON CONFLICT DO NOTHING", (username, email_md5))
        except psycopg2.Error as e:
            print("Database error:", e)

    with connect_db().cursor() as cur:
        cur.execute("SELECT username, email_md5 FROM authorized_users ORDER BY username ASC")
        users = [{"username": row[0], "email_md5": row[1]} for row in cur.fetchall()]

    return render_template("authorized.html", user_data=user_data, users=users)

@socketio.on("start_auth")
def handle_start_auth():
    session_id = request.cookies.get("session_id")
    if not session_id or session_id not in USER_SESSIONS:
        return emit("error", {"msg": "No valid session found."})

    session_data = USER_SESSIONS[session_id]

    if "token" in session_data and "user_data" in session_data:
        emit("progress", {"msg": "Using cached token and user data."})
        return emit("done", {"redirect": url_for("display")})

    if not (code := session_data.get("auth_code")):
        return emit("error", {"msg": "No authorization code found in session."})

    try:
        emit("progress", {"msg": "Exchanging code for token..."})
        token_obj = client.exchange_code_for_token(code=code)

        emit("progress", {"msg": "Retrieving user data..."})
        user_obj = client.get_user(token_obj)

        session_data.update({"token": token_obj, "user_data": user_obj.__dict__})
        store_session(session_id, session_data)

        emit("progress", {"msg": "Done!"})
        emit("done", {"redirect": url_for("display")})
    except Exception as e:
        emit("error", {"msg": f"Error: {str(e)}"})

def get_app() -> Flask:
    with app.app_context():
        initialize_database()
    return app

if __name__ == "__main__":
    with app.app_context():
        initialize_database()
    print("Starting Flask-SocketIO server...")
    socketio.run(app, debug=True)
