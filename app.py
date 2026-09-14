import os
import secrets
from datetime import datetime

import psycopg
from psycopg.rows import dict_row

from flask import (
    Flask,
    request,
    jsonify,
    session,
    send_from_directory
)

from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

DATABASE_URL = os.environ.get("DATABASE_URL")


def get_db():
    if not DATABASE_URL:
        raise RuntimeError(
            "DATABASE_URL is not configured."
        )

    return psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row
    )


def init_db():

    with get_db() as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) NOT NULL,
                phone VARCHAR(30) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                contact_user_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_id, contact_user_id)
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS conversations (
                id SERIAL PRIMARY KEY,

                user_one INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                user_two INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(user_one, user_two)
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id SERIAL PRIMARY KEY,

                conversation_id INTEGER NOT NULL
                    REFERENCES conversations(id)
                    ON DELETE CASCADE,

                sender_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                message TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS waves (
                id SERIAL PRIMARY KEY,

                sender_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                receiver_id INTEGER NOT NULL
                    REFERENCES users(id)
                    ON DELETE CASCADE,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

                UNIQUE(sender_id, receiver_id)
            );
        """)

        conn.commit()


def current_user_id():

    return session.get("user_id")


@app.route("/")
def home():

    return send_from_directory(
        ".",
        "index.html"
    )


@app.route("/login.html")
def login_page():

    return send_from_directory(
        ".",
        "login.html"
    )


@app.route("/signup.html")
def signup_page():

    return send_from_directory(
        ".",
        "signup.html"
    )


# -------------------------
# SIGN UP
# -------------------------

@app.route(
    "/api/signup",
    methods=["POST"]
)
def signup():

    data = request.get_json() or {}

    username = data.get(
        "username",
        ""
    ).strip()

    phone = data.get(
        "phone",
        ""
    ).strip()

    email = data.get(
        "email",
        ""
    ).strip().lower()

    password = data.get(
        "password",
        ""
    )

    if not username or not phone or not email or not password:

        return jsonify({
            "success": False,
            "message": "Please fill in all fields."
        }), 400

    if len(password) < 6:

        return jsonify({
            "success": False,
            "message": "Password must be at least 6 characters."
        }), 400

    with get_db() as conn:

        existing = conn.execute(
            """
            SELECT id
            FROM users
            WHERE phone = %s
               OR email = %s
            """,
            (phone, email)
        ).fetchone()

        if existing:

            return jsonify({
                "success": False,
                "message": "Phone number or email is already registered."
            }), 409

        user = conn.execute(
            """
            INSERT INTO users
            (
                username,
                phone,
                email,
                password_hash
            )
            VALUES (%s, %s, %s, %s)
            RETURNING id
            """,
            (
                username,
                phone,
                email,
                generate_password_hash(password)
            )
        ).fetchone()

        conn.commit()

    return jsonify({
        "success": True,
        "message": "Account created successfully."
    })


# -------------------------
# LOGIN
# -------------------------

@app.route(
    "/api/login",
    methods=["POST"]
)
def login():

    data = request.get_json() or {}

    identifier = data.get(
        "identifier",
        ""
    ).strip()

    password = data.get(
        "password",
        ""
    )

    if not identifier or not password:

        return jsonify({
            "success": False,
            "message": "Enter your phone/email and password."
        }), 400

    with get_db() as conn:

        user = conn.execute(
            """
            SELECT *
            FROM users
            WHERE phone = %s
               OR email = %s
            LIMIT 1
            """,
            (
                identifier,
                identifier.lower()
            )
        ).fetchone()

    if not user:

        return jsonify({
            "success": False,
            "message": "Account not found."
        }), 404

    if not check_password_hash(
        user["password_hash"],
        password
    ):

        return jsonify({
            "success": False,
            "message": "Incorrect password."
        }), 401

    session["user_id"] = user["id"]

    return jsonify({
        "success": True,
        "username": user["username"],
        "phone": user["phone"],
        "email": user["email"]
    })


# -------------------------
# LOGOUT
# -------------------------

@app.route(
    "/api/logout",
    methods=["POST"]
)
def logout():

    session.clear()

    return jsonify({
        "success": True
    })


# -------------------------
# CURRENT USER
# -------------------------

@app.route("/api/me")
def me():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "logged_in": False
        })

    with get_db() as conn:

        user = conn.execute(
            """
            SELECT
                id,
                username,
                phone,
                email
            FROM users
            WHERE id = %s
            """,
            (user_id,)
        ).fetchone()

    if not user:

        session.clear()

        return jsonify({
            "logged_in": False
        })

    return jsonify({
        "logged_in": True,
        "user": user
    })


# -------------------------
# FIND USER BY PHONE
# -------------------------

@app.route(
    "/api/find-user",
    methods=["POST"]
)
def find_user():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    data = request.get_json() or {}

    phone = data.get(
        "phone",
        ""
    ).strip()

    if not phone:

        return jsonify({
            "success": False,
            "message": "Enter a phone number."
        }), 400

    with get_db() as conn:

        user = conn.execute(
            """
            SELECT
                id,
                username,
                phone
            FROM users
            WHERE phone = %s
            """,
            (phone,)
        ).fetchone()

    if not user:

        return jsonify({
            "success": False,
            "message": "That number is not registered on JAYRIX."
        }), 404

    if user["id"] == user_id:

        return jsonify({
            "success": False,
            "message": "That's your own number."
        }), 400

    return jsonify({
        "success": True,
        "user": user
    })


# -------------------------
# ADD CONTACT
# -------------------------

@app.route(
    "/api/contacts",
    methods=["POST"]
)
def add_contact():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    data = request.get_json() or {}

    contact_id = data.get("contact_id")

    with get_db() as conn:

        contact = conn.execute(
            """
            SELECT id, username, phone
            FROM users
            WHERE id = %s
            """,
            (contact_id,)
        ).fetchone()

        if not contact:

            return jsonify({
                "success": False,
                "message": "User not found."
            }), 404

        conn.execute(
            """
            INSERT INTO contacts
            (
                user_id,
                contact_user_id
            )
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                user_id,
                contact_id
            )
        )

        conn.commit()

    return jsonify({
        "success": True,
        "user": contact
    })


# -------------------------
# CONTACTS
# -------------------------

@app.route("/api/contacts")
def contacts():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    with get_db() as conn:

        rows = conn.execute(
            """
            SELECT
                u.id,
                u.username,
                u.phone
            FROM contacts c

            JOIN users u
            ON u.id = c.contact_user_id

            WHERE c.user_id = %s

            ORDER BY u.username
            """,
            (user_id,)
        ).fetchall()

    return jsonify({
        "success": True,
        "contacts": rows
    })


# -------------------------
# SEND WAVE
# -------------------------

@app.route(
    "/api/wave",
    methods=["POST"]
)
def wave():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    data = request.get_json() or {}

    receiver_id = data.get(
        "receiver_id"
    )

    if not receiver_id:

        return jsonify({
            "success": False,
            "message": "Receiver is required."
        }), 400

    with get_db() as conn:

        receiver = conn.execute(
            """
            SELECT id, username
            FROM users
            WHERE id = %s
            """,
            (receiver_id,)
        ).fetchone()

        if not receiver:

            return jsonify({
                "success": False,
                "message": "User not found."
            }), 404

        conn.execute(
            """
            INSERT INTO waves
            (
                sender_id,
                receiver_id
            )
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
            """,
            (
                user_id,
                receiver_id
            )
        )

        conn.commit()

    return jsonify({
        "success": True,
        "message": "Wave sent!"
    })


# -------------------------
# GET / CREATE CONVERSATION
# -------------------------

@app.route(
    "/api/conversation",
    methods=["POST"]
)
def conversation():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    data = request.get_json() or {}

    other_id = data.get(
        "user_id"
    )

    if not other_id:

        return jsonify({
            "success": False,
            "message": "User is required."
        }), 400

    if user_id == other_id:

        return jsonify({
            "success": False,
            "message": "You cannot chat with yourself."
        }), 400

    first = min(
        user_id,
        other_id
    )

    second = max(
        user_id,
        other_id
    )

    with get_db() as conn:

        existing = conn.execute(
            """
            SELECT id
            FROM conversations
            WHERE user_one = %s
              AND user_two = %s
            """,
            (
                first,
                second
            )
        ).fetchone()

        if existing:

            conversation_id = existing["id"]

        else:

            new_conversation = conn.execute(
                """
                INSERT INTO conversations
                (
                    user_one,
                    user_two
                )
                VALUES (%s, %s)
                RETURNING id
                """,
                (
                    first,
                    second
                )
            ).fetchone()

            conversation_id = new_conversation["id"]

        conn.commit()

    return jsonify({
        "success": True,
        "conversation_id": conversation_id
    })


# -------------------------
# SEND MESSAGE
# -------------------------

@app.route(
    "/api/messages",
    methods=["POST"]
)
def send_message():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    data = request.get_json() or {}

    conversation_id = data.get(
        "conversation_id"
    )

    message = data.get(
        "message",
        ""
    ).strip()

    if not conversation_id or not message:

        return jsonify({
            "success": False,
            "message": "Message cannot be empty."
        }), 400

    with get_db() as conn:

        conversation = conn.execute(
            """
            SELECT id
            FROM conversations
            WHERE id = %s
              AND (
                  user_one = %s
                  OR user_two = %s
              )
            """,
            (
                conversation_id,
                user_id,
                user_id
            )
        ).fetchone()

        if not conversation:

            return jsonify({
                "success": False,
                "message": "Conversation not found."
            }), 404

        new_message = conn.execute(
            """
            INSERT INTO messages
            (
                conversation_id,
                sender_id,
                message
            )
            VALUES (%s, %s, %s)
            RETURNING
                id,
                message,
                created_at
            """,
            (
                conversation_id,
                user_id,
                message
            )
        ).fetchone()

        conn.commit()

    return jsonify({
        "success": True,
        "message": new_message
    })


# -------------------------
# GET MESSAGES
# -------------------------

@app.route(
    "/api/messages/<int:conversation_id>"
)
def get_messages(conversation_id):

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    with get_db() as conn:

        conversation = conn.execute(
            """
            SELECT id
            FROM conversations
            WHERE id = %s
              AND (
                  user_one = %s
                  OR user_two = %s
              )
            """,
            (
                conversation_id,
                user_id,
                user_id
            )
        ).fetchone()

        if not conversation:

            return jsonify({
                "success": False,
                "message": "Conversation not found."
            }), 404

        messages = conn.execute(
            """
            SELECT
                m.id,
                m.sender_id,
                m.message,
                m.created_at,
                u.username
            FROM messages m

            JOIN users u
            ON u.id = m.sender_id

            WHERE m.conversation_id = %s

            ORDER BY m.created_at ASC
            """,
            (conversation_id,)
        ).fetchall()

    return jsonify({
        "success": True,
        "messages": messages
    })


# -------------------------
# CHAT LIST
# -------------------------

@app.route("/api/chats")
def chats():

    user_id = current_user_id()

    if not user_id:

        return jsonify({
            "success": False,
            "message": "Please log in first."
        }), 401

    with get_db() as conn:

        rows = conn.execute(
            """
            SELECT
                c.id AS conversation_id,

                CASE
                    WHEN c.user_one = %s
                    THEN u2.id
                    ELSE u1.id
                END AS other_id,

                CASE
                    WHEN c.user_one = %s
                    THEN u2.username
                    ELSE u1.username
                END AS username,

                CASE
                    WHEN c.user_one = %s
                    THEN u2.phone
                    ELSE u1.phone
                END AS phone

            FROM conversations c

            JOIN users u1
            ON u1.id = c.user_one

            JOIN users u2
            ON u2.id = c.user_two

            WHERE
                c.user_one = %s
                OR c.user_two = %s

            ORDER BY c.created_at DESC
            """,
            (
                user_id,
                user_id,
                user_id,
                user_id,
                user_id
            )
        ).fetchall()

    return jsonify({
        "success": True,
        "chats": rows
    })


# -------------------------
# STARTUP
# -------------------------

if __name__ == "__main__":

    init_db()

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
        )
