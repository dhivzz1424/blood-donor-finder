
from flask import (
    Flask, render_template, request,
    session, redirect, url_for
)
from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from flask_bcrypt import Bcrypt
import os

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

bcrypt = Bcrypt(app)

# MongoDB connection
MONGO_URI = os.getenv("MONGO_URI")

if not MONGO_URI:
    raise ValueError("MONGO_URI is missing in .env")

client = MongoClient(
    MONGO_URI,
    serverSelectionTimeoutMS=10000
)

db = client["bloodconnect"]
donors = db["donors"]


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

        if not all([
            name, email, phone, password,
            blood_group, location
        ]):
            return "Please fill in all fields.", 400

        valid_groups = [
            "A+", "A-", "B+", "B-",
            "AB+", "AB-", "O+", "O-"
        ]

        if blood_group not in valid_groups:
            return "Invalid blood group.", 400

        if donors.find_one({"email": email}):
            return "An account with this email already exists.", 409

        hashed_password = bcrypt.generate_password_hash(
            password
        ).decode("utf-8")

        donor = {
            "name": name,
            "email": email,
            "phone": phone,
            "password": hashed_password,
            "bloodGroup": blood_group,
            "location": location,
            "availability": True
        }

        try:
            donors.insert_one(donor)
        except DuplicateKeyError:
            return "An account with this email already exists.", 409

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
            session["donor_email"] = donor["email"]
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            error="Invalid email or password."
        )

    return render_template("login.html")


# Donor dashboard (login required)
@app.route("/dashboard")
def dashboard():
    if "donor_email" not in session:
        return redirect(url_for("login"))

    donor = donors.find_one(
        {"email": session["donor_email"]},
        {"password": 0}
    )

    if not donor:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", donor=donor)


# Logout
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# MongoDB connection test
@app.route("/db-test")
def db_test():
    try:
        client.admin.command("ping")
        return "MongoDB connected successfully!"
    except Exception:
        app.logger.exception("MongoDB connection failed")
        return "Database connection failed. Check the terminal.", 500


if __name__ == "__main__":
    app.run(debug=True)
