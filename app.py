from flask_cors import CORS, cross_origin
import json
from common_functions import return_success,return_error,is_valid_email
from mysql_connector import get_db
from flask import Flask, render_template_string, request, session, redirect, url_for,send_file, Response,make_response
# from flask_session import Session
import bcrypt
import uuid
# from flask_bcrypt import Bcrypt
app = Flask(__name__)
app.secret_key = "harshit25102000"
CORS(app,supports_credentials=True)

@app.before_request
def validate_session_and_role():
    # Skip validation for public endpoints
    if request.endpoint in ['login']:
        return

    session_id = request.cookies.get("session_id")
    if not session_id:
        return return_error(error="UNAUTHORIZED", message="No session found"), 401

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # Validate session and fetch role
    cursor.execute(
        "SELECT user_id, user_role,user_email FROM sessions WHERE session_id=%s AND expires_at > NOW()",
        (session_id,)
    )
    active_session = cursor.fetchone()

    if not active_session:
        return return_error(error="SESSION_INVALID", message="Session expired or invalid"), 401

    # Attach role and user_id to Flask's session object for use in routes
    print(active_session)
    session["user_id"] = active_session["user_id"]
    session["user_role"] = active_session["user_role"]
    session["user_email"] = active_session["user_email"]


@app.route("/signup",methods=["POST"])
def signup():
    try:
        if session.get("user_role") != "Admin":
            return return_error(error="FORBIDDEN", message="Only Admins can add users"), 403
        print(request)
        data = request.get_json()
        print(data)
        first_name = data["first_name"]
        last_name = data["last_name"]
        email = data["email"]
        password = data["password1"]
        password2=data["password2"]
        role=data["role"]

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        check_user = cursor.fetchone()

        #check if this email is already registered
        if check_user is not None:

            return return_error(error="ACCOUNT_ALREADY_EXIST", message="Account with this email already exists")
        if not is_valid_email(email):

            return return_error(error="WRONG_EMAIL", message="Enter a valid Email")

        if not password==password2:

            return return_error(error="PASSWORD_DID_NOT_MATCH", message="Passwords did not match")


        bytes = password.encode('utf-8')

        # generating the salt
        salt = bcrypt.gensalt()
        hashpass=bcrypt.hashpw(bytes, salt)

        query={"first_name":first_name,"last_name":last_name, "password":hashpass,"email":email,"role":role}
        print(query)
        cursor.execute(
            "INSERT INTO users (first_name, last_name, password_hash, email, user_role) VALUES (%s, %s, %s, %s, %s)",
            (first_name, last_name, hashpass.decode('utf-8'), email, role)
        )
        conn.commit()


        return return_success({"email":email})
    except Exception as e:
         return return_error(message=str(e))



@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data["email"]
        password = data["password"]

        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user is None:
            return return_error(error="ACCOUNT_NOT_FOUND", message="No account with this email exists")

        stored_hash = user["password_hash"].encode("utf-8")
        if not bcrypt.checkpw(password.encode("utf-8"), stored_hash):
            return return_error(error="INVALID_PASSWORD", message="Incorrect password")

        #delete existing old sessions
        cursor.execute("DELETE FROM sessions WHERE user_id=%s", (user["id"],))
        conn.commit()

        #Create a new session
        session_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO sessions (session_id, user_id, user_role,user_email, expires_at) VALUES (%s, %s,%s, %s, NOW() + INTERVAL 1 HOUR)",
            (session_id, user["id"], user["user_role"],user["email"])
        )

        conn.commit()

        #Return success and set cookie
        resp = make_response(return_success({"email": email, "role": user["user_role"]}))
        resp.set_cookie("session_id", session_id, httponly=True, secure=True, samesite="Strict")

        # also store in Flask session object if needed
        session["email"] = email
        session["role"] = user["user_role"]

        return resp

    except Exception as e:
        return return_error(message=str(e))


@app.route("/me", methods=["GET"])
def me():
    try:

        user_role = session.get("user_role")
        user_id= session.get("user_id")
        user_email = session.get("email")

        return return_success({"user_role": user_role, "user_id": user_id, "user_email": user_email})

    except Exception as e:
        return return_error(message=str(e))

@app.route("/logout", methods=["POST"])
def logout():
    try:
        session_id = request.cookies.get("session_id")
        if not session_id:
            return return_error(error="NO_SESSION", message="No active session"), 401

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id=%s", (session_id,))
        conn.commit()

        resp = make_response(return_success({"message": "Logged out successfully"}))
        resp.delete_cookie("session_id")  # clear cookie on client
        return resp

    except Exception as e:
        return return_error(message=str(e))

@app.route("/delete_user", methods=["POST"])
def delete_user():
    try:
        # Ensure only Admin can delete users
        if session.get("user_role") != "Admin":
            return return_error(error="FORBIDDEN", message="Only Admins can delete users"), 403

        data = request.get_json()
        email = data.get("email")

        if not email:
            return return_error(error="MISSING_EMAIL", message="Email is required"), 400

        conn = get_db()
        cursor = conn.cursor()

        cursor.execute("DELETE FROM users WHERE email=%s", (email,))
        conn.commit()

        return return_success({"message": f"User with email {email} deleted successfully"})

    except Exception as e:
        return return_error(message=str(e))

if __name__=="__main__":

    app.config['DEBUG'] = True
    app.secret_key = "harshit25102000"
    app.config.update(SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=True)
    # app.config["SESSION_PERMANENT"] = True
    # app.config["SESSION_TYPE"] = "mongodb"
    # app.config["SESSION_MONGODB"] = client
    # app.config["SESSION_MONGODB_DB"] = 'userData'
    # app.config["SESSION_MONGODB_COLLECTION"] = 'sessions'
    # Session(app)
    app.run(debug=True)