
import os
import re
import secrets
import hashlib
import smtplib

from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from pathlib import Path
from email.message import EmailMessage
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash


# Load configuration from .env
BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

app = Flask(__name__)

app.secret_key = os.getenv("MEDICARE_SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("MEDICARE_SECRET_KEY is missing from .env.")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing from .env.")


INDIA_TZ = ZoneInfo("Asia/Kolkata")

DEFAULT_START_TIME = time(10, 0)
DEFAULT_END_TIME = time(18, 0)
LUNCH_START = time(13, 0)
LUNCH_END = time(14, 0)
SLOT_MINUTES = 30

RESET_TOKEN_MINUTES = 30
MAX_REVIEW_LENGTH = 1000


# PostgreSQL connection. Each request block commits on success
# and rolls back automatically if an exception occurs.
@contextmanager
def get_db():
    db = psycopg.connect(
        DATABASE_URL,
        row_factory=dict_row,
        connect_timeout=15
    )
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db():
    """Check that the migrated PostgreSQL tables are available."""
    required_tables = {
        "users",
        "patients",
        "doctors",
        "appointments",
        "doctor_date_availability",
        "doctor_slot_availability",
        "doctor_reviews",
        "password_reset_tokens",
    }

    with get_db() as db:
        rows = db.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_schema = 'public'
              AND table_type = 'BASE TABLE'
        """).fetchall()

        existing = {row["table_name"] for row in rows}
        missing = required_tables - existing

        if missing:
            raise RuntimeError(
                "Missing PostgreSQL tables: " + ", ".join(sorted(missing))
            )


def india_now():
    return datetime.now(INDIA_TZ)


def utc_now():
    return datetime.now(timezone.utc)


def verify_password(stored_password, entered_password):
    if not stored_password:
        return False

    if stored_password.startswith(("scrypt:", "pbkdf2:")):
        try:
            return check_password_hash(stored_password, entered_password)
        except (ValueError, TypeError):
            return False

    return stored_password == entered_password


def normalize_phone(value):
    if not value:
        return ""

    value = value.strip()

    if not re.fullmatch(r"\+?[\d\s().-]+", value):
        return ""

    digits = re.sub(r"\D", "", value)

    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]

    return digits if len(digits) == 10 else ""


def login_required(role=None):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please log in first.")
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                flash("You are not allowed to access that page.")
                return redirect(url_for("home"))

            return view(*args, **kwargs)
        return wrapped
    return decorator


def normalize_time(value):
    if not value:
        return ""

    value = value.strip()

    for fmt in ("%H:%M", "%I:%M %p", "%I:%M%p"):
        try:
            return datetime.strptime(value, fmt).strftime("%H:%M")
        except ValueError:
            continue

    return value


def generate_time_slots():
    slots = []
    current = datetime.combine(date.today(), DEFAULT_START_TIME)
    end = datetime.combine(date.today(), DEFAULT_END_TIME)

    while current < end:
        slot_time = current.time()

        if not (LUNCH_START <= slot_time < LUNCH_END):
            slots.append(current.strftime("%H:%M"))

        current += timedelta(minutes=SLOT_MINUTES)

    return slots


def is_past_slot(selected_date, slot_time):
    try:
        slot_date = date.fromisoformat(selected_date)
        slot_clock = datetime.strptime(slot_time, "%H:%M").time()
    except ValueError:
        return True

    current = india_now()

    if slot_date < current.date():
        return True

    if slot_date > current.date():
        return False

    slot_datetime = datetime.combine(
        slot_date, slot_clock, tzinfo=INDIA_TZ
    )
    return slot_datetime <= current


def send_password_reset_email(recipient, reset_url):
    sender = os.getenv("MEDICARE_EMAIL", "").strip()
    app_password = os.getenv(
        "MEDICARE_EMAIL_APP_PASSWORD", ""
    ).replace(" ", "").strip()

    if not sender or not app_password:
        raise RuntimeError("Email settings are missing from .env.")

    message = EmailMessage()
    message["Subject"] = "MediCare+ Password Reset"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "Hello,\n\n"
        "We received a request to reset your MediCare+ password.\n\n"
        "Use the link below to choose a new password. "
        "This link expires in 30 minutes and can only be used once.\n\n"
        f"{reset_url}\n\n"
        "If you did not request this reset, you can ignore this email.\n"
    )

    with smtplib.SMTP_SSL("smtp.gmail.com", 465, timeout=20) as smtp:
        smtp.login(sender, app_password)
        smtp.send_message(message)


def get_user_email(user_id):
    with get_db() as db:
        row = db.execute(
            "SELECT email FROM users WHERE id = %s",
            (user_id,)
        ).fetchone()
        return row["email"] if row else ""


@app.route("/")
def home():
    with get_db() as db:
        doctors = db.execute("""
            SELECT
                d.id, d.name, d.specialization, d.experience,
                d.fee, d.available_days,
                COALESCE(r.average_rating, 0) AS average_rating,
                COALESCE(r.review_count, 0) AS review_count
            FROM doctors d
            LEFT JOIN (
                SELECT doctor_id, AVG(rating) AS average_rating,
                       COUNT(*) AS review_count
                FROM doctor_reviews
                GROUP BY doctor_id
            ) r ON r.doctor_id = d.id
            ORDER BY d.name
        """).fetchall()

        reviews = db.execute("""
            SELECT dr.rating, dr.review_text, dr.created_at,
                   p.name AS patient_name, d.name AS doctor_name,
                   d.specialization
            FROM doctor_reviews dr
            JOIN patients p ON p.id = dr.patient_id
            JOIN doctors d ON d.id = dr.doctor_id
            ORDER BY dr.created_at DESC, dr.id DESC
            LIMIT 6
        """).fetchall()

    return render_template("home.html", doctors=doctors, reviews=reviews)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone_input = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        phone = normalize_phone(phone_input) if phone_input else ""

        if not name or not email or len(password) < 6:
            flash("Enter your name and email, and use a password of at least 6 characters.")
            return redirect(url_for("register"))

        if phone_input and not phone:
            flash("Enter a valid 10-digit Indian mobile number.")
            return redirect(url_for("register"))

        try:
            with get_db() as db:
                existing = db.execute("""
                    SELECT id FROM users WHERE LOWER(email) = LOWER(%s)
                """, (email,)).fetchone()

                if existing:
                    flash("An account with this email already exists. Please log in.")
                    return redirect(url_for("login"))

                if phone:
                    phone_user = db.execute("""
                        SELECT id FROM users WHERE phone = %s
                    """, (phone,)).fetchone()

                    if phone_user:
                        flash("This phone number is already registered.")
                        return redirect(url_for("register"))

                hashed_password = generate_password_hash(password)

                db.execute("""
                    INSERT INTO users (name, email, password, role, phone)
                    VALUES (%s, %s, %s, 'patient', %s)
                """, (name, email, hashed_password, phone or None))

                db.execute("""
                    INSERT INTO patients (name, email, password, phone)
                    VALUES (%s, %s, %s, %s)
                """, (name, email, hashed_password, phone or None))

            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))

        except psycopg.IntegrityError:
            app.logger.exception("Registration integrity error")
            flash("That email or phone number is already registered.")
            return redirect(url_for("register"))

        except psycopg.Error:
            app.logger.exception("Registration failed")
            flash("Registration could not be completed. Please try again.")
            return redirect(url_for("register"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get(
            "identifier", request.form.get("email", "")
        ).strip()
        password = request.form.get("password", "")

        admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
        admin_password = os.getenv("ADMIN_PASSWORD", "")

        if (
            admin_email
            and identifier.lower() == admin_email
            and admin_password
            and password == admin_password
        ):
            session.clear()
            session["user_id"] = -1
            session["name"] = "Administrator"
            session["role"] = "admin"
            return redirect(url_for("admin_dashboard"))

        phone = normalize_phone(identifier)
        is_email = "@" in identifier
        normalized_identifier = identifier.lower() if is_email else phone

        if not normalized_identifier:
            flash("Enter a valid email address or 10-digit phone number.")
            return redirect(url_for("login"))

        with get_db() as db:
            if is_email:
                user = db.execute("""
                    SELECT id, name, email, password, role, phone
                    FROM users WHERE LOWER(email) = LOWER(%s)
                """, (normalized_identifier,)).fetchone()
            else:
                user = db.execute("""
                    SELECT id, name, email, password, role, phone
                    FROM users WHERE phone = %s
                """, (normalized_identifier,)).fetchone()

            if not user or not verify_password(user["password"], password):
                flash("Invalid email/phone number or password.")
                return redirect(url_for("login"))

            if not user["password"].startswith(("scrypt:", "pbkdf2:")):
                db.execute("""
                    UPDATE users SET password = %s WHERE id = %s
                """, (generate_password_hash(password), user["id"]))

            session.clear()
            session["user_id"] = user["id"]
            session["name"] = user["name"]
            session["role"] = user["role"]

            if user["role"] == "doctor":
                doctor = db.execute("""
                    SELECT id FROM doctors WHERE user_id = %s
                """, (user["id"],)).fetchone()

                if not doctor:
                    session.clear()
                    flash("Doctor profile not found for this account.")
                    return redirect(url_for("login"))

                session["doctor_id"] = doctor["id"]
                return redirect(url_for("doctor_dashboard"))

            if user["role"] == "patient":
                return redirect(url_for("patient_dashboard"))

            if user["role"] == "admin":
                return redirect(url_for("admin_dashboard"))

            session.clear()
            flash("Unknown account role.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()

        if not email:
            flash("Enter the email address associated with your account.")
            return redirect(url_for("forgot_password"))

        generic_message = (
            "If an account exists with that email, "
            "a password-reset link will be sent."
        )

        with get_db() as db:
            user = db.execute("""
                SELECT id, email FROM users
                WHERE LOWER(email) = LOWER(%s) AND role = 'patient'
            """, (email,)).fetchone()

            if user:
                db.execute("""
                    UPDATE password_reset_tokens
                    SET used = 1 WHERE user_id = %s AND used = 0
                """, (user["id"],))

                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(
                    raw_token.encode("utf-8")
                ).hexdigest()

                created = utc_now()
                expires = created + timedelta(minutes=RESET_TOKEN_MINUTES)

                db.execute("""
                    INSERT INTO password_reset_tokens
                        (user_id, token_hash, expires_at, used, created_at)
                    VALUES (%s, %s, %s, 0, %s)
                """, (
                    user["id"], token_hash, expires.isoformat(),
                    created.isoformat()
                ))

                reset_url = url_for(
                    "reset_password", token=raw_token, _external=True
                )

                try:
                    send_password_reset_email(user["email"], reset_url)
                except Exception:
                    app.logger.exception("Password-reset email could not be sent")
                    db.execute("""
                        UPDATE password_reset_tokens SET used = 1
                        WHERE token_hash = %s
                    """, (token_hash,))

        flash(generic_message)
        return redirect(url_for("login"))

    return render_template("forgot_password.html")


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()

    with get_db() as db:
        reset_record = db.execute("""
            SELECT id, user_id, expires_at, used
            FROM password_reset_tokens WHERE token_hash = %s
        """, (token_hash,)).fetchone()

        if not reset_record or reset_record["used"]:
            flash("This reset link is invalid or has already been used.")
            return redirect(url_for("forgot_password"))

        try:
            expires_at = datetime.fromisoformat(reset_record["expires_at"])
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        except ValueError:
            flash("This reset link is invalid. Please request another.")
            return redirect(url_for("forgot_password"))

        if utc_now() >= expires_at:
            db.execute("""
                UPDATE password_reset_tokens SET used = 1 WHERE id = %s
            """, (reset_record["id"],))
            flash("This reset link has expired. Please request a new one.")
            return redirect(url_for("forgot_password"))

        if request.method == "POST":
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")

            if len(password) < 6:
                flash("Your new password must have at least 6 characters.")
                return redirect(url_for("reset_password", token=token))

            if password != confirm_password:
                flash("The passwords do not match.")
                return redirect(url_for("reset_password", token=token))

            hashed_password = generate_password_hash(password)

            db.execute("""
                UPDATE users SET password = %s WHERE id = %s
            """, (hashed_password, reset_record["user_id"]))

            user = db.execute("""
                SELECT email FROM users WHERE id = %s
            """, (reset_record["user_id"],)).fetchone()

            if user:
                db.execute("""
                    UPDATE patients SET password = %s
                    WHERE LOWER(email) = LOWER(%s)
                """, (hashed_password, user["email"]))

            db.execute("""
                UPDATE password_reset_tokens SET used = 1
                WHERE user_id = %s
            """, (reset_record["user_id"],))

            flash("Password changed successfully. Please log in.")
            return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("home"))


@app.route("/patient", methods=["GET", "POST"])
@login_required("patient")
def patient_dashboard():
    with get_db() as db:
        patient = db.execute("""
            SELECT id FROM patients WHERE LOWER(email) = LOWER(%s)
        """, (get_user_email(session["user_id"]),)).fetchone()

        if not patient:
            flash("Patient profile not found.")
            return redirect(url_for("logout"))

        patient_id = patient["id"]

        doctors = db.execute("""
            SELECT d.id, d.name, d.specialization, d.experience,
                   d.fee, d.available_days,
                   COALESCE(r.average_rating, 0) AS average_rating,
                   COALESCE(r.review_count, 0) AS review_count
            FROM doctors d
            LEFT JOIN (
                SELECT doctor_id, AVG(rating) AS average_rating,
                       COUNT(*) AS review_count
                FROM doctor_reviews GROUP BY doctor_id
            ) r ON r.doctor_id = d.id
            ORDER BY d.name
        """).fetchall()

        if request.method == "POST":
            doctor_id = request.form.get("doctor_id", type=int)
            appointment_date = request.form.get(
                "appointment_date", ""
            ).strip()
            appointment_time = normalize_time(
                request.form.get("appointment_time", "").strip()
            )

            if not doctor_id or not appointment_date or not appointment_time:
                flash("Please select a doctor, date, and time.")
                return redirect(url_for("patient_dashboard"))

            try:
                selected_date = date.fromisoformat(appointment_date)
                selected_time = datetime.strptime(
                    appointment_time, "%H:%M"
                ).time()
            except ValueError:
                flash("Please select a valid appointment date and time.")
                return redirect(url_for("patient_dashboard"))

            if selected_date < india_now().date():
                flash("Appointment date cannot be in the past.")
                return redirect(url_for("patient_dashboard"))

            if (
                selected_time < DEFAULT_START_TIME
                or selected_time >= DEFAULT_END_TIME
                or LUNCH_START <= selected_time < LUNCH_END
                or appointment_time not in generate_time_slots()
            ):
                flash("Please select a valid clinic time slot.")
                return redirect(url_for("patient_dashboard"))

            if is_past_slot(appointment_date, appointment_time):
                flash("This time slot has already passed.")
                return redirect(url_for("patient_dashboard"))

            doctor = db.execute("""
                SELECT id FROM doctors WHERE id = %s
            """, (doctor_id,)).fetchone()

            if not doctor:
                flash("Selected doctor was not found.")
                return redirect(url_for("patient_dashboard"))

            day_availability = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = %s AND availability_date = %s
            """, (doctor_id, appointment_date)).fetchone()

            if not day_availability or day_availability["status"] != "Available":
                flash("This doctor is not available on the selected date.")
                return redirect(url_for("patient_dashboard"))

            slot_availability = db.execute("""
                SELECT status FROM doctor_slot_availability
                WHERE doctor_id = %s AND availability_date = %s
                  AND slot_time = %s
            """, (doctor_id, appointment_date, appointment_time)).fetchone()

            if not slot_availability or slot_availability["status"] != "Available":
                flash("This time slot is not available. Please choose another.")
                return redirect(url_for("patient_dashboard"))

            conflict = db.execute("""
                SELECT id FROM appointments
                WHERE doctor_id = %s AND appointment_date = %s
                  AND appointment_time = %s
                  AND status NOT IN ('Cancelled', 'Rejected')
            """, (doctor_id, appointment_date, appointment_time)).fetchone()

            if conflict:
                flash("That appointment slot is already booked.")
                return redirect(url_for("patient_dashboard"))

            db.execute("""
                INSERT INTO appointments
                    (patient_id, doctor_id, appointment_date,
                     appointment_time, status)
                VALUES (%s, %s, %s, %s, 'Booked')
            """, (patient_id, doctor_id, appointment_date, appointment_time))

            flash("Appointment booked successfully.")
            return redirect(url_for("patient_dashboard"))

        appointments = db.execute("""
            SELECT a.id, a.appointment_date, a.appointment_time, a.status,
                   d.name AS doctor_name, d.specialization, d.fee,
                   dr.id AS review_id, dr.rating AS review_rating,
                   dr.review_text AS review_text,
                   dr.created_at AS review_created_at
            FROM appointments a
            JOIN doctors d ON d.id = a.doctor_id
            LEFT JOIN doctor_reviews dr ON dr.appointment_id = a.id
            WHERE a.patient_id = %s
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (patient_id,)).fetchall()

    return render_template(
        "patient.html", doctors=doctors, appointments=appointments,
        today=india_now().date().isoformat()
    )


@app.route("/patient/review/<int:appointment_id>", methods=["POST"])
@login_required("patient")
def submit_patient_review(appointment_id):
    rating_input = request.form.get("rating", "").strip()
    review_text = request.form.get("review_text", "").strip()

    try:
        rating = int(rating_input)
    except (TypeError, ValueError):
        flash("Please select a rating from 1 to 5 stars.")
        return redirect(url_for("patient_dashboard"))

    if rating < 1 or rating > 5:
        flash("Please select a rating from 1 to 5 stars.")
        return redirect(url_for("patient_dashboard"))

    if not review_text:
        flash("Please write a short review before submitting.")
        return redirect(url_for("patient_dashboard"))

    if len(review_text) > MAX_REVIEW_LENGTH:
        flash("Your review must be 1000 characters or fewer.")
        return redirect(url_for("patient_dashboard"))

    with get_db() as db:
        patient = db.execute("""
            SELECT id FROM patients WHERE LOWER(email) = LOWER(%s)
        """, (get_user_email(session["user_id"]),)).fetchone()

        if not patient:
            flash("Patient profile not found.")
            return redirect(url_for("logout"))

        appointment = db.execute("""
            SELECT id, patient_id, doctor_id, status FROM appointments
            WHERE id = %s AND patient_id = %s
        """, (appointment_id, patient["id"])).fetchone()

        if not appointment:
            flash("That appointment was not found in your history.")
            return redirect(url_for("patient_dashboard"))

        if appointment["status"] != "Completed":
            flash("You can review an appointment after it is marked Completed.")
            return redirect(url_for("patient_dashboard"))

        existing_review = db.execute("""
            SELECT id FROM doctor_reviews WHERE appointment_id = %s
        """, (appointment_id,)).fetchone()

        if existing_review:
            flash("You have already reviewed this appointment.")
            return redirect(url_for("patient_dashboard"))

        try:
            db.execute("""
                INSERT INTO doctor_reviews
                    (appointment_id, patient_id, doctor_id,
                     rating, review_text, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                appointment["id"], patient["id"], appointment["doctor_id"],
                rating, review_text, india_now().isoformat()
            ))
        except psycopg.IntegrityError:
            flash("This appointment has already been reviewed.")
            return redirect(url_for("patient_dashboard"))

    flash("Thank you! Your review has been submitted.")
    return redirect(url_for("patient_dashboard"))


@app.route("/patient/slot-availability")
@login_required("patient")
def patient_slot_availability():
    doctor_id = request.args.get("doctor_id", type=int)
    selected_date = request.args.get("appointment_date", "").strip()

    if not doctor_id:
        return jsonify({"error": "Please select a doctor."}), 400

    try:
        parsed_date = date.fromisoformat(selected_date)
    except ValueError:
        return jsonify({"error": "Please select a valid date."}), 400

    if parsed_date < india_now().date():
        return jsonify({"slots": [], "message": "Past dates cannot be booked."})

    with get_db() as db:
        doctor = db.execute("""
            SELECT id FROM doctors WHERE id = %s
        """, (doctor_id,)).fetchone()

        if not doctor:
            return jsonify({"error": "Doctor not found."}), 404

        day_availability = db.execute("""
            SELECT status FROM doctor_date_availability
            WHERE doctor_id = %s AND availability_date = %s
        """, (doctor_id, selected_date)).fetchone()

        if not day_availability or day_availability["status"] != "Available":
            return jsonify({
                "slots": [],
                "message": "This doctor has not marked this date Available yet."
            })

        saved_rows = db.execute("""
            SELECT slot_time, status FROM doctor_slot_availability
            WHERE doctor_id = %s AND availability_date = %s
        """, (doctor_id, selected_date)).fetchall()

        saved_statuses = {
            normalize_time(row["slot_time"]): row["status"]
            for row in saved_rows
        }

        appointment_rows = db.execute("""
            SELECT appointment_time FROM appointments
            WHERE doctor_id = %s AND appointment_date = %s
              AND status NOT IN ('Cancelled', 'Rejected')
        """, (doctor_id, selected_date)).fetchall()

        booked_times = {
            normalize_time(row["appointment_time"])
            for row in appointment_rows
        }

    slots = []
    for slot in generate_time_slots():
        label = datetime.strptime(slot, "%H:%M").strftime("%I:%M %p")

        if slot in booked_times:
            status = "Booked"
        elif is_past_slot(selected_date, slot):
            status = "Not Available"
        else:
            status = saved_statuses.get(slot, "Available")

        slots.append({"time": slot, "label": label, "status": status})

    return jsonify({"slots": slots, "message": "Select a slot marked Available."})


@app.route("/cancel_appointment/<int:appointment_id>", methods=["POST"])
@login_required("patient")
def cancel_appointment(appointment_id):
    with get_db() as db:
        patient = db.execute("""
            SELECT id FROM patients WHERE LOWER(email) = LOWER(%s)
        """, (get_user_email(session["user_id"]),)).fetchone()

        if not patient:
            flash("Patient profile not found.")
            return redirect(url_for("patient_dashboard"))

        result = db.execute("""
            UPDATE appointments SET status = 'Cancelled'
            WHERE id = %s AND patient_id = %s
              AND status NOT IN ('Cancelled', 'Rejected', 'Completed')
        """, (appointment_id, patient["id"]))

        flash(
            "Appointment cancelled."
            if result.rowcount else "Appointment could not be cancelled."
        )

    return redirect(url_for("patient_dashboard"))


@app.route("/doctor", methods=["GET", "POST"])
@login_required("doctor")
def doctor_dashboard():
    doctor_id = session.get("doctor_id")

    if request.method == "POST":
        appointment_id = request.form.get("appointment_id", type=int)
        status = request.form.get("status", "").strip()

        if status not in ("Booked", "Approved", "Rejected", "Completed"):
            flash("Invalid appointment status.")
            return redirect(url_for("doctor_dashboard"))

        with get_db() as db:
            result = db.execute("""
                UPDATE appointments SET status = %s
                WHERE id = %s AND doctor_id = %s
            """, (status, appointment_id, doctor_id))

        flash(
            "Appointment status updated."
            if result.rowcount else "Appointment not found."
        )
        return redirect(url_for("doctor_dashboard"))

    selected_date = request.args.get("date", india_now().date().isoformat())

    try:
        selected_date = date.fromisoformat(selected_date).isoformat()
    except ValueError:
        selected_date = india_now().date().isoformat()

    now = india_now()
    today = now.date().isoformat()

    with get_db() as db:
        doctor = db.execute("""
            SELECT id, name, specialization, available_days
            FROM doctors WHERE id = %s
        """, (doctor_id,)).fetchone()

        if not doctor:
            flash("Doctor profile not found.")
            return redirect(url_for("logout"))

        if selected_date > today:
            db.execute("""
                INSERT INTO doctor_date_availability
                    (doctor_id, availability_date, status)
                VALUES (%s, %s, 'Available')
                ON CONFLICT (doctor_id, availability_date) DO NOTHING
            """, (doctor_id, selected_date))

            current_date_status = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = %s AND availability_date = %s
            """, (doctor_id, selected_date)).fetchone()

            if current_date_status and current_date_status["status"] == "Available":
                for slot in generate_time_slots():
                    db.execute("""
                        INSERT INTO doctor_slot_availability
                            (doctor_id, availability_date, slot_time, status)
                        VALUES (%s, %s, %s, 'Available')
                        ON CONFLICT (doctor_id, availability_date, slot_time)
                        DO NOTHING
                    """, (doctor_id, selected_date, slot))

        availability = db.execute("""
            SELECT status FROM doctor_date_availability
            WHERE doctor_id = %s AND availability_date = %s
        """, (doctor_id, selected_date)).fetchone()

        availability_status = availability["status"] if availability else "Not Set"

        appointments = db.execute("""
            SELECT a.id, a.appointment_date, a.appointment_time, a.status,
                   p.name AS patient_name, p.email AS patient_email
            FROM appointments a
            JOIN patients p ON p.id = a.patient_id
            WHERE a.doctor_id = %s
            ORDER BY a.appointment_date DESC, a.appointment_time DESC
        """, (doctor_id,)).fetchall()

        date_appointments = db.execute("""
            SELECT appointment_time, status FROM appointments
            WHERE doctor_id = %s AND appointment_date = %s
              AND status NOT IN ('Cancelled', 'Rejected')
        """, (doctor_id, selected_date)).fetchall()

        saved_dates = db.execute("""
            SELECT availability_date, status FROM doctor_date_availability
            WHERE doctor_id = %s ORDER BY availability_date DESC
        """, (doctor_id,)).fetchall()

        slot_rows = db.execute("""
            SELECT slot_time, status FROM doctor_slot_availability
            WHERE doctor_id = %s AND availability_date = %s
        """, (doctor_id, selected_date)).fetchall()

    saved_slot_status = {
        normalize_time(row["slot_time"]): row["status"] for row in slot_rows
    }
    booked_slots = {
        normalize_time(row["appointment_time"]): row["status"]
        for row in date_appointments
    }

    slots = []
    for slot in generate_time_slots():
        label = datetime.strptime(slot, "%H:%M").strftime("%I:%M %p")
        past = is_past_slot(selected_date, slot)
        booked_status = booked_slots.get(slot)

        if booked_status:
            slot_status = "Booked"
        elif past or availability_status != "Available":
            slot_status = "Not Available"
        else:
            slot_status = saved_slot_status.get(slot, "Available")

        slots.append({
            "time": slot,
            "label": label,
            "status": slot_status,
            "past": past,
            "booked": bool(booked_status),
            "can_edit": (
                availability_status == "Available"
                and not past and not booked_status
            )
        })

    return render_template(
        "doctor.html",
        doctor=doctor,
        appointments=appointments,
        selected_date=selected_date,
        today=today,
        availability_status=availability_status,
        slots=slots,
        saved_dates=saved_dates,
        india_time=now.strftime("%I:%M %p")
    )


@app.route("/update_appointment/<int:appointment_id>", methods=["POST"])
@login_required("doctor")
def update_appointment(appointment_id):
    status = request.form.get("status", "").strip()

    if status not in ("Booked", "Approved", "Rejected", "Completed"):
        flash("Invalid appointment status.")
        return redirect(url_for("doctor_dashboard"))

    with get_db() as db:
        result = db.execute("""
            UPDATE appointments SET status = %s
            WHERE id = %s AND doctor_id = %s
        """, (status, appointment_id, session.get("doctor_id")))

    flash(
        "Appointment updated."
        if result.rowcount else "Appointment not found."
    )
    return redirect(url_for("doctor_dashboard"))


@app.route("/update_doctor_availability", methods=["POST"])
@login_required("doctor")
def update_doctor_availability():
    selected_date = request.form.get("availability_date", "").strip()
    status = request.form.get("availability_status", "").strip()
    slot_time = normalize_time(request.form.get("slot_time", "").strip())
    slot_status = request.form.get("slot_status", "").strip()
    doctor_id = session.get("doctor_id")

    try:
        parsed_date = date.fromisoformat(selected_date)
    except ValueError:
        flash("Please select a valid date.")
        return redirect(url_for("doctor_dashboard"))

    if parsed_date < india_now().date():
        flash("You cannot change availability for a past date.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    if slot_time:
        if slot_time not in generate_time_slots():
            flash("Invalid time slot.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        if slot_status not in ("Available", "Not Available"):
            flash("Please choose a valid slot status.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        if is_past_slot(selected_date, slot_time):
            flash("Past time slots cannot be made available.")
            return redirect(url_for("doctor_dashboard", date=selected_date))

        with get_db() as db:
            day_status = db.execute("""
                SELECT status FROM doctor_date_availability
                WHERE doctor_id = %s AND availability_date = %s
            """, (doctor_id, selected_date)).fetchone()

            if not day_status or day_status["status"] != "Available":
                flash("Mark this date Available before changing its slots.")
                return redirect(url_for("doctor_dashboard", date=selected_date))

            existing_booking = db.execute("""
                SELECT id FROM appointments
                WHERE doctor_id = %s AND appointment_date = %s
                  AND appointment_time = %s
                  AND status NOT IN ('Cancelled', 'Rejected')
            """, (doctor_id, selected_date, slot_time)).fetchone()

            if existing_booking:
                flash("This slot already has an appointment and cannot be changed.")
                return redirect(url_for("doctor_dashboard", date=selected_date))

            db.execute("""
                INSERT INTO doctor_slot_availability
                    (doctor_id, availability_date, slot_time, status)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (doctor_id, availability_date, slot_time)
                DO UPDATE SET status = EXCLUDED.status
            """, (doctor_id, selected_date, slot_time, slot_status))

        flash(f"{slot_time} marked as {slot_status}.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    if status not in ("Available", "Not Available"):
        flash("Please choose Available or Not Available.")
        return redirect(url_for("doctor_dashboard", date=selected_date))

    with get_db() as db:
        db.execute("""
            INSERT INTO doctor_date_availability
                (doctor_id, availability_date, status)
            VALUES (%s, %s, %s)
            ON CONFLICT (doctor_id, availability_date)
            DO UPDATE SET status = EXCLUDED.status
        """, (doctor_id, selected_date, status))

        if status == "Available":
            for slot in generate_time_slots():
                if not is_past_slot(selected_date, slot):
                    db.execute("""
                        INSERT INTO doctor_slot_availability
                            (doctor_id, availability_date, slot_time, status)
                        VALUES (%s, %s, %s, 'Available')
                        ON CONFLICT (doctor_id, availability_date, slot_time)
                        DO NOTHING
                    """, (doctor_id, selected_date, slot))

    flash(
        f"{selected_date} marked as {status}. "
        "Existing appointments have been preserved."
    )
    return redirect(url_for("doctor_dashboard", date=selected_date))


@app.route("/admin")
@login_required("admin")
def admin_dashboard():
    with get_db() as db:
        doctors = db.execute(
            "SELECT * FROM doctors ORDER BY name"
        ).fetchall()

        patients = db.execute("""
            SELECT id, name, email FROM users
            WHERE role = 'patient' ORDER BY name
        """).fetchall()

        appointments = db.execute("""
            SELECT a.*, u.name AS patient_name, d.name AS doctor_name
            FROM appointments a
            JOIN patients p ON p.id = a.patient_id
            JOIN users u ON LOWER(u.email) = LOWER(p.email)
            JOIN doctors d ON d.id = a.doctor_id
            ORDER BY a.appointment_date DESC, a.appointment_time
        """).fetchall()

    return render_template(
        "admin.html",
        doctors=doctors,
        patients=patients,
        appointments=appointments
    )


@app.route("/admin/add-doctor", methods=["POST"])
@login_required("admin")
def add_doctor():
    name = request.form.get("name", "").strip()
    specialization = request.form.get("specialization", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

    if not name or not specialization or not email or len(password) < 6:
        flash("Complete all fields. Password must have at least 6 characters.")
        return redirect(url_for("admin_dashboard"))

    try:
        experience = int(request.form.get("experience", 0))
        fee = float(request.form.get("fee", 500))

        if experience < 0 or fee < 0:
            raise ValueError

        with get_db() as db:
            user = db.execute("""
                INSERT INTO users (name, email, password, role)
                VALUES (%s, %s, %s, 'doctor')
                RETURNING id
            """, (name, email, generate_password_hash(password))).fetchone()

            user_id = user["id"]

            db.execute("""
                INSERT INTO doctors
                    (user_id, name, specialization, experience, fee)
                VALUES (%s, %s, %s, %s, %s)
            """, (user_id, name, specialization, experience, fee))

        flash("Doctor added. They can now log in.")

    except psycopg.IntegrityError:
        flash("Could not add doctor. This email may already be registered.")
    except ValueError:
        flash("Enter valid non-negative numbers for experience and fee.")
    except psycopg.Error:
        app.logger.exception("Could not add doctor")
        flash("Doctor could not be added. Please try again.")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-doctor/<int:doctor_id>", methods=["POST"])
@login_required("admin")
def delete_doctor(doctor_id):
    with get_db() as db:
        doctor = db.execute("""
            SELECT * FROM doctors WHERE id = %s
        """, (doctor_id,)).fetchone()

        if doctor:
            db.execute(
                "DELETE FROM doctor_reviews WHERE doctor_id = %s",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM appointments WHERE doctor_id = %s",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctor_slot_availability WHERE doctor_id = %s",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctor_date_availability WHERE doctor_id = %s",
                (doctor_id,)
            )
            db.execute(
                "DELETE FROM doctors WHERE id = %s",
                (doctor_id,)
            )

            if doctor["user_id"] is not None:
                db.execute("""
                    DELETE FROM users WHERE id = %s AND role = 'doctor'
                """, (doctor["user_id"],))

    flash("Doctor profile and associated appointment records removed.")
    return redirect(url_for("admin_dashboard"))


if __name__ == "__main__":
    init_db()
    app.run(debug=True)
