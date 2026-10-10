
from flask import (
    Flask, render_template, request,
    session, redirect, url_for
)
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from functools import wraps
import os

# Load .env from the same folder as app.py
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise ValueError("SECRET_KEY is missing in .env")

bcrypt = Bcrypt(app)

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise ValueError("MONGO_URI is missing in .env")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

db = client["bloodconnect"]
donors = db["donors"]
hospitals = db["hospitals"]


# Login protection
def donor_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "donor_email" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def hospital_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "hospital_email" not in session:
            return redirect(url_for("hospital_login"))
        return view(*args, **kwargs)
    return wrapped


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Donor registration
@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        blood_group = request.form.get("bloodGroup", "").strip()
        location = request.form.get("location", "").strip()

        if not all([name, email, phone, password,
                    blood_group, location]):
            return "Please fill in all fields.", 400

        if blood_group not in [
            "A+", "A-", "B+", "B-", "AB+", "AB-",
            "O+", "O-"
        ]:
            return "Invalid blood group.", 400

        if donors.find_one({"email": email}):
            return "Donor email already registered.", 409

        donor = {
            "name": name,
            "email": email,
            "phone": phone,
            "password": bcrypt.generate_password_hash(
                password
            ).decode("utf-8"),
            "bloodGroup": blood_group,
            "location": location,
            "availability": True
        }

        try:
            donors.insert_one(donor)
        except DuplicateKeyError:
            return "Donor email already registered.", 409

        return render_template(
            "success.html",
            name=name,
            blood_group=blood_group,
            location=location
        )

    return render_template("register.html")


# Donor login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        donor = donors.find_one({"email": email})

        if donor and bcrypt.check_password_hash(
            donor["password"], password
        ):
            session.clear()
            session["donor_email"] = email
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid donor email or password."
        )

    return render_template("login.html")


# Donor dashboard
@app.route("/dashboard")
@donor_required
def dashboard():
    donor = donors.find_one(
        {"email": session["donor_email"]},
        {"password": 0}
    )

    if not donor:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", donor=donor)


# Update donor availability
@app.route("/update-availability", methods=["POST"])
@donor_required
def update_availability():
    value = request.form.get("availability")

    if value not in ["available", "unavailable"]:
        return "Invalid availability.", 400

    donors.update_one(
        {"email": session["donor_email"]},
        {"$set": {"availability": value == "available"}}
    )

    return redirect(url_for("dashboard"))


# Hospital registration
@app.route("/hospital/register", methods=["GET", "POST"])
def hospital_register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        location = request.form.get("location", "").strip()
        password = request.form.get("password", "")

        if not all([name, email, phone, location, password]):
            return render_template(
                "hospital_register.html",
                error="Please fill in all fields."
            )

        if hospitals.find_one({"email": email}):
            return render_template(
                "hospital_register.html",
                error="Hospital email already registered."
            )

        hospital = {
            "name": name,
            "email": email,
            "phone": phone,
            "location": location,
            "password": bcrypt.generate_password_hash(
                password
            ).decode("utf-8")
        }

        try:
            hospitals.insert_one(hospital)
        except DuplicateKeyError:
            return render_template(
                "hospital_register.html",
                error="Hospital email already registered."
            )

        return redirect(url_for("hospital_login"))

    return render_template("hospital-register.html")


# Hospital login
@app.route("/hospital/login", methods=["GET", "POST"])
def hospital_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        hospital = hospitals.find_one({"email": email})

        if hospital and bcrypt.check_password_hash(
            hospital["password"], password
        ):
            session.clear()
            session["hospital_email"] = email
            return redirect(url_for("hospital_dashboard"))

        return render_template(
            "hospital_login.html",
            error="Invalid hospital email or password."
        )

    return render_template("hospital-login.html")


# Hospital dashboard
@app.route("/hospital/dashboard")
@hospital_required
def hospital_dashboard():
    hospital = hospitals.find_one(
        {"email": session["hospital_email"]},
        {"password": 0}
    )

    if not hospital:
        session.clear()
        return redirect(url_for("hospital_login"))

    return render_template(
        "hospital-dashboard.html",
        hospital=hospital
    )


# Logout
@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# Database connection test
@app.route("/db-test")
def db_test():
    try:
        client.admin.command("ping")
        return "MongoDB connected successfully!"
    except Exception:
        app.logger.exception("MongoDB connection failed")
        return "Database connection failed. Check the terminal.", 500


# Display the template directory for debugging
@app.route("/debug-templates")
def debug_templates():
    template_path = os.path.join(
        app.template_folder,
        "hospital_login.html"
    )

    return (
        f"Template folder: {app.template_folder}<br>"
        f"Hospital login file exists: "
        f"{os.path.isfile(template_path)}"
    )


if __name__ == "__main__":
    app.run(debug=True)
