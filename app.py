
from flask import (
    Flask, render_template, request,
    session, redirect, url_for
)
import certifi
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
from functools import wraps
import os

# -----------------------------------
# APP CONFIGURATION
# -----------------------------------

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
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=10000
)


db = client["bloodconnect"]
donors = db["donors"]
hospitals = db["hospitals"]
blood_requests = db["blood_requests"]

BLOOD_GROUPS = [
    "A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"
]


# -----------------------------------
# LOGIN PROTECTION
# -----------------------------------

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


# -----------------------------------
# HOME PAGE
# -----------------------------------

@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------------
# DONOR REGISTRATION
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        blood_group = request.form.get("bloodGroup", "").strip()
        location = request.form.get("location", "").strip()

        if not all([
            name, email, phone, password,
            blood_group, location
        ]):
            return "Please fill in all fields.", 400

        if blood_group not in BLOOD_GROUPS:
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


# -----------------------------------
# DONOR LOGIN
# -----------------------------------

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


# -----------------------------------
# DONOR DASHBOARD
# -----------------------------------

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


# -----------------------------------
# UPDATE DONOR AVAILABILITY
# -----------------------------------

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


# -----------------------------------
# HOSPITAL REGISTRATION
# -----------------------------------

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
                "hospital-register.html",
                error="Please fill in all fields."
            )

        if hospitals.find_one({"email": email}):
            return render_template(
                "hospital-register.html",
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
                "hospital-register.html",
                error="Hospital email already registered."
            )

        return redirect(url_for("hospital_login"))

    return render_template("hospital-register.html")


# -----------------------------------
# HOSPITAL LOGIN
# -----------------------------------

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
            "hospital-login.html",
            error="Invalid hospital email or password."
        )

    return render_template("hospital-login.html")


# -----------------------------------
# HOSPITAL DASHBOARD
# -----------------------------------

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


# -----------------------------------
# HOSPITAL DONOR SEARCH
# -----------------------------------

@app.route("/hospital/donors", methods=["GET", "POST"])
@hospital_required
def hospital_donors():
    hospital = hospitals.find_one(
        {"email": session["hospital_email"]},
        {"password": 0}
    )

    if not hospital:
        session.clear()
        return redirect(url_for("hospital_login"))

    selected_blood_group = request.values.get(
        "blood_group", ""
    ).strip()

    selected_location = request.values.get(
        "location", ""
    ).strip()

    results = []
    searched = (
        request.method == "POST"
        or bool(selected_blood_group)
        or bool(selected_location)
    )

    if selected_blood_group not in BLOOD_GROUPS:
        selected_blood_group = ""

    if searched:
        query = {"availability": True}

        if selected_blood_group:
            query["bloodGroup"] = selected_blood_group

        if selected_location:
            query["location"] = {
                "$regex": __import__("re").escape(selected_location),
                "$options": "i"
            }

        results = list(
            donors.find(
                query,
                {
                    "_id": 0,
                    "name": 1,
                    "phone": 1,
                    "bloodGroup": 1,
                    "location": 1,
                    "availability": 1
                }
            ).limit(100)
        )

    return render_template(
        "hospital-donor.html",
        hospital=hospital,
        donors=results,
        blood_groups=BLOOD_GROUPS,
        selected_blood_group=selected_blood_group,
        selected_location=selected_location,
        searched=searched
    )

# -----------------------------------
# EMERGENCY BLOOD REQUEST
# -----------------------------------

@app.route("/hospital/emergency-request", methods=["GET"])
@hospital_required
def emergency_request():
    return render_template("emergency-request.html")


@app.route("/hospital/create-request", methods=["POST"])
@hospital_required
def create_blood_request():
    blood_group = request.form.get("blood_group", "").strip()
    units_text = request.form.get("units", "").strip()
    location = request.form.get("location", "").strip()
    urgency = request.form.get("urgency", "").strip()
    contact = request.form.get("contact", "").strip()
    notes = request.form.get("notes", "").strip()

    if blood_group not in BLOOD_GROUPS:
        return render_template(
            "emergency-request.html",
            error="Please select a valid blood group."
        ), 400

    try:
        units = int(units_text)
    except ValueError:
        units = 0

    if not 1 <= units <= 100:
        return render_template(
            "emergency-request.html",
            error="Units must be between 1 and 100."
        ), 400

    if not location or not contact:
        return render_template(
            "emergency-request.html",
            error="Location and contact phone are required."
        ), 400

    if urgency not in ["Critical", "Urgent", "Normal"]:
        return render_template(
            "emergency-request.html",
            error="Please select a valid urgency."
        ), 400

    blood_requests.insert_one({
        "hospital_email": session["hospital_email"],
        "blood_group": blood_group,
        "units": units,
        "location": location,
        "urgency": urgency,
        "contact": contact,
        "notes": notes,
        "status": "Pending"
    })

    return render_template(
        "emergency-request.html",
        success="Blood request submitted successfully!"
    )


# -----------------------------------
# LOGOUT
# -----------------------------------

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# -----------------------------------
# DATABASE CONNECTION TEST
# -----------------------------------

@app.route("/db-test")
def db_test():
    try:
        client.admin.command("ping")
        return "MongoDB connected successfully!"
    except Exception:
        app.logger.exception("MongoDB connection failed")
        return "Database connection failed. Check the terminal.", 500


# -----------------------------------
# TEMPLATE DEBUGGING
# -----------------------------------

@app.route("/debug-templates")
def debug_templates():
    filenames = [
        "hospital-login.html",
        "hospital-register.html",
        "hospital-dashboard.html",
        "hospital-donor.html"
    ]

    results = []

    for filename in filenames:
        path = os.path.join(app.template_folder, filename)
        results.append(
            f"{filename}: {os.path.isfile(path)}"
        )

    return (
        f"Template folder: {app.template_folder}<br>"
        + "<br>".join(results)
    )


# -----------------------------------
# RUN APPLICATION
# -----------------------------------

if __name__ == "__main__":
    app.run(debug=True, use_reloader=False)