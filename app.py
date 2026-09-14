from flask import Flask, request, jsonify, send_from_directory
import hashlib
import os

app = Flask(__name__)

# Temporary user storage
# We'll replace this with a real database next.
users = {}


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route("/")
def home():
    return send_from_directory(".", "index.html")


@app.route("/login")
def login_page():
    return send_from_directory(".", "login.html")


@app.route("/signup")
def signup_page():
    return send_from_directory(".", "signup.html")


@app.route("/api/signup", methods=["POST"])
def signup():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No data received."
        }), 400

    username = data.get("username", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not username or not email or not password:
        return jsonify({
            "success": False,
            "message": "Please fill in all fields."
        }), 400

    if email in users:
        return jsonify({
            "success": False,
            "message": "An account with this email already exists."
        }), 409

    users[email] = {
        "username": username,
        "email": email,
        "password": hash_password(password)
    }

    return jsonify({
        "success": True,
        "message": "Account created successfully.",
        "username": username
    })


@app.route("/api/login", methods=["POST"])
def login():

    data = request.get_json()

    if not data:
        return jsonify({
            "success": False,
            "message": "No data received."
        }), 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return jsonify({
            "success": False,
            "message": "Please enter your email and password."
        }), 400

    user = users.get(email)

    if not user:
        return jsonify({
            "success": False,
            "message": "Account not found."
        }), 404

    if user["password"] != hash_password(password):
        return jsonify({
            "success": False,
            "message": "Incorrect password."
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful.",
        "username": user["username"],
        "email": user["email"]
    })


@app.route("/api/status")
def status():

    return jsonify({
        "app": "JAYRIX",
        "status": "online"
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))

    app.run(
        host="0.0.0.0",
        port=port,
        debug=True
  )
