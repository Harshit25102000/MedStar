from flask_cors import CORS, cross_origin
import json
from common_functions import return_success,return_error,is_valid_email,to_nullable
from mysql_connector import get_db
from flask import Flask, render_template_string, request, session, redirect, url_for,send_file, Response,make_response
# from flask_session import Session
import bcrypt
import uuid
import pandas as pd
from flask import request, jsonify
import os
from datetime import date
from reconcile_functions import *

ALLOWED_EXTENSIONS = {"xlsx"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

app = Flask(__name__)
app.secret_key = "harshit25102000"
CORS(app,
     resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
     supports_credentials=True)


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

    cursor.execute(
        "UPDATE sessions SET expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE) WHERE session_id=%s",
        (session_id,)
    )
    conn.commit()

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
            "INSERT INTO sessions (session_id, user_id, user_role,user_email, expires_at) VALUES (%s, %s,%s, %s, NOW() + INTERVAL 30 MINUTE)",
            (session_id, user["id"], user["user_role"],user["email"])
        )

        conn.commit()

        #Return success and set cookie
        resp = make_response(return_success({"email": email, "role": user["user_role"]}))
        resp.set_cookie("session_id", session_id, httponly=True, secure=True, samesite="None",path="/")

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
        user_email = session.get("user_email")


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


@app.route("/upload_excel", methods=["POST"])
def upload_excel_sheets():
    try:
        internal_file = request.files.get("internal")
        agency_file = request.files.get("agency")

        # If neither file is provided, return error
        if not internal_file and not agency_file:
            return jsonify({"error": "At least one file (internal or agency) is required"}), 400

        uploaded_by = session.get("user_email")
        now = date.today()

        os.makedirs("uploads", exist_ok=True)
        conn = get_db()
        cursor = conn.cursor()

        # ---------------------------
        # 📌 PROCESS INTERNAL SHEET
        # ---------------------------
        if internal_file:
            if not allowed_file(internal_file.filename):
                return jsonify({"error": "Internal sheet must be .xlsx"}), 400

            internal_path = f"uploads/internal_{internal_file.filename}"
            internal_file.save(internal_path)

            try:
                df = pd.read_excel(internal_path, header=None)
            except Exception as e:
                return jsonify({"error": f"Failed to read Internal Excel: {str(e)}"}), 400

            df = df.iloc[1:]  # remove header

            insert_query = """
                INSERT INTO internal_data (
                    assignment_id, shift_day, shift_date, shift_start_time, shift_end_time,
                    facility, state, invoice_date, invoice, role, staff_id, first_name, surname,
                    shift_time_slot, total_shift_length, total_charges, gst, total,
                    created_at, uploaded_by
                ) 
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            for _, row in df.iterrows():
                if row.isna().all():  # skip blank rows
                    continue

                cursor.execute(insert_query, (
                    to_nullable(row[0], int),
                    to_nullable(row[1], str),
                    to_nullable(row[2], str),
                    to_nullable(row[3], str),
                    to_nullable(row[4], str),
                    to_nullable(row[5], str),
                    to_nullable(row[6], str),
                    to_nullable(row[7], str),
                    to_nullable(row[8], int),
                    to_nullable(row[9], str),
                    to_nullable(row[10], str),
                    to_nullable(row[11], str),
                    to_nullable(row[12], str),
                    to_nullable(row[13], str),
                    to_nullable(row[14], float),
                    to_nullable(row[15], float),
                    to_nullable(row[16], float),
                    to_nullable(row[17], float),
                    now,
                    uploaded_by
                ))

        # ---------------------------
        # 📌 PROCESS AGENCY SHEET
        # ---------------------------
        if agency_file:
            if not allowed_file(agency_file.filename):
                return jsonify({"error": "Agency sheet must be .xlsx"}), 400

            agency_path = f"uploads/agency_{agency_file.filename}"
            agency_file.save(agency_path)

            try:
                df = pd.read_excel(agency_path, header=None)
            except Exception as e:
                return jsonify({"error": f"Failed to read Agency Excel: {str(e)}"}), 400

            df = df.iloc[1:]

            insert_agency = """
                INSERT INTO agency_data (
                    role, assignment_id, first_name, surname, start_date, end_date,
                    facility_name, shift_date, request_type, bill_rate, billing_period,
                    invoice, register_type, total, invoiced_units, shift_load_name,
                    created_at, uploaded_by
                )
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            """

            for _, row in df.iterrows():
                if row.isna().all():
                    continue

                # Extract name: "Surname, Firstname"
                full_name = to_nullable(row[2], str)
                if full_name and "," in full_name:
                    surname, first_name = [x.strip() for x in full_name.split(",", 1)]
                else:
                    surname, first_name = None, None

                cursor.execute(insert_agency, (
                    to_nullable(row[0], str),
                    to_nullable(row[1], int),
                    first_name,
                    surname,
                    to_nullable(row[3], str),
                    to_nullable(row[4], str),
                    to_nullable(row[5], str),
                    to_nullable(row[6], str),
                    to_nullable(row[7], str),
                    to_nullable(row[8], str),
                    to_nullable(row[9], str),
                    to_nullable(row[10], int),
                    to_nullable(row[11], str),
                    to_nullable(row[12], float),
                    to_nullable(row[13], float),
                    to_nullable(row[14], str),
                    now,
                    uploaded_by
                ))

        conn.commit()

        try:
            for f in os.listdir("uploads"):
                file_path = os.path.join("uploads", f)
                if os.path.isfile(file_path):
                    os.remove(file_path)
        except Exception as cleanup_err:
            print("Cleanup failed:", cleanup_err)

        return jsonify({"message": "Sheets uploaded and stored successfully"}), 200

    except Exception as e:
        return return_error(message=str(e))


@app.route("/reconcile_all", methods=["POST"])
def reconcile_all_endpoint():
    # try:
        results = reconcile_all()
        return jsonify({"message": "Reconciliation complete", "results": results}), 200
    # except Exception as e:
    #     return return_error(str(e))

@app.route("/reconcile_by_date", methods=["POST"])
def reconcile_by_dates_endpoint():
    try:
        data = request.json
        start_date = data.get("start_date")
        end_date = data.get("end_date")

        if not start_date or not end_date:
            return jsonify({"error": "start_date and end_date required"}), 400

        results = reconcile_by_date(start_date, end_date)
        return jsonify({"message": "Reconciliation complete", "results": results}), 200

    except Exception as e:
        return return_error(str(e))


@app.route("/change_password", methods=["POST"])
def change_password():
    # Ensure only Admin can delete users
    if session.get("user_role") != "Admin":
        return return_error(error="FORBIDDEN", message="Only Admins can delete users"), 403
    try:
        data = request.get_json()
        email = data.get("email")
        password1 = data.get("password1")
        password2 = data.get("password2")

        if not email or not password1 or not password2:
            return return_error(error="MISSING_FIELDS", message="Email and both passwords are required")

        # Password match check
        if password1 != password2:
            return return_error(error="PASSWORD_MISMATCH", message="Passwords do not match")

        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        if user is None:
            return return_error(error="ACCOUNT_NOT_FOUND", message="No account with this email exists")

        # Hash new password
        new_hash = bcrypt.hashpw(password1.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        # Update password hash
        cursor.execute("""
            UPDATE users 
            SET password_hash=%s 
            WHERE email=%s
        """, (new_hash, email))

        conn.commit()

        return return_success()

    except Exception as e:
        return return_error(message=str(e))


@app.route("/reconcile_by_date_and_facility", methods=["POST"])
def reconcile_by_dates_and_facility_endpoint():
    try:
        data = request.json
        start_date = data.get("start_date")
        end_date = data.get("end_date")
        facility = data.get("facility")

        if not start_date or not end_date or not facility:
            return jsonify({"error": "start_date, end_date and facility is required"}), 400

        results = reconcile_by_date_and_facility(start_date, end_date,facility)
        return jsonify({"message": "Reconciliation complete", "results": results}), 200

    except Exception as e:
        return return_error(str(e))

@app.route("/get_all_users", methods=["GET"])
def get_all_users():
    try:
        # Ensure only Admin can delete users
        if session.get("user_role") != "Admin":
            return return_error(error="FORBIDDEN", message="Only Admins can delete users"), 403

        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # Validate session and fetch role
        cursor.execute(
            "SELECT first_name,last_name,email from users;"
        )
        all_users= cursor.fetchall()

        return return_success(all_users)

    except Exception as e:
        return return_error(message=str(e))


@app.route("/stats", methods=["GET"])
def get_statistics():
    try:
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        # 1️⃣ TOTAL VALUE (sum of total column)
        cursor.execute("SELECT COALESCE(SUM(total), 0) AS total_value FROM internal_data")
        total_value = cursor.fetchone()["total_value"]

        # 2️⃣ PENDING VALUE (sum of negative outstanding values returned as positive)
        cursor.execute("""
            SELECT COALESCE(ABS(SUM(outstanding)), 0) AS pending_value
            FROM internal_data
            WHERE outstanding < 0
        """)
        pending_value = cursor.fetchone()["pending_value"]

        # 3️⃣ RECONCILED PERCENTAGE
        # Count matched rows
        cursor.execute("SELECT COUNT(*) AS matched FROM internal_data WHERE status = 'Matched'")
        matched = cursor.fetchone()["matched"]

        # Count total rows
        cursor.execute("SELECT COUNT(*) AS total FROM internal_data")
        total_rows = cursor.fetchone()["total"]

        reconciled_percentage = 0
        if total_rows > 0:
            reconciled_percentage = round((matched / total_rows) * 100, 2)

        return jsonify({
            "total_value": float(total_value),
            "pending_value": float(pending_value),
            "reconciled_percentage": reconciled_percentage
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__=="__main__":

    app.config['DEBUG'] = True
    app.secret_key = "harshit25102000"
    app.config.update(SESSION_COOKIE_SAMESITE="None", SESSION_COOKIE_SECURE=False)
    # app.config["SESSION_PERMANENT"] = True
    # app.config["SESSION_TYPE"] = "mongodb"
    # app.config["SESSION_MONGODB"] = client
    # app.config["SESSION_MONGODB_DB"] = 'userData'
    # app.config["SESSION_MONGODB_COLLECTION"] = 'sessions'
    # Session(app)
    app.run(debug=True)