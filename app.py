import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///users.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    goals = db.execute(
            "SELECT * FROM goals WHERE user_id =?", session["user_id"]
        )
    if request.method == "GET":
        return render_template("home.html", goals=goals)
    else:
        name = request.form.get("goal_name")
        hours = request.form.get("hours")
        add_hours = request.form.get("add_hours")
        check_goal = db.execute("SELECT * FROM goals WHERE name = ?", name)
        option = request.form.get("option")
        # CHECK IF OPTIONS IN LIST
        if not name and not add_hours:
            return render_template("apology.html", message="Please add a new goal or update an existing goal")
        if len(check_goal) != 0:
            return render_template("apology.html", message="Goal already started")
        if not hours and not add_hours:
            return render_template("apology.html", message="Please your goal hours")
        else:
            if add_hours != None:
                # MAY FIX THIS PROBLEM
                current_hours = db.execute(
                "SELECT completed_hours FROM goals WHERE user_id = ? AND name = ?", session["user_id"], option
                )
                if len(current_hours) != 0:
                    new_hours = current_hours[0]["completed_hours"] + int(add_hours)

                    db.execute(
                        "UPDATE goals SET completed_hours = ? WHERE user_id = ? AND name = ?", new_hours, session["user_id"], option)
            if name:
                db.execute(
                    "INSERT INTO goals (user_id, set_goal, name) VALUES (?, ?, ?)", session["user_id"], hours, name)

            goals = db.execute(
            "SELECT * FROM goals WHERE user_id =?", session["user_id"]
            )
            return render_template("goals.html", goals=goals)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")

        check_repeat_username = db.execute("SELECT username FROM users WHERE username = ?", username)
        if not username:
            return render_template("apology.html", message="Please enter a username")
        if len(check_repeat_username) != 0:
            return render_template("apology.html", message="Username is already taken")
        if not password:
            return render_template("apology.html", message="Please enter a password")
        if not first_name:
            return render_template("apology.html", message="Please enter your first name")
        if not last_name:
            return render_template("apology.html", message="Please enter your last name")

        hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
        db.execute("INSERT INTO users (username, hash, first_name, last_name) VALUES (?, ?, ?, ?)", username, hash, first_name, last_name)
        return redirect("/")

    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return render_template("apology.html", message="Please enter username")
        # Ensure password was submitted
        elif not request.form.get("password"):
            return render_template("apology.html", message="Please enter password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return render_template("apology.html", message="Incorrect username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        goals = db.execute("SELECT * FROM goals WHERE user_id = ?", session["user_id"])
        return render_template("home.html", goals=goals)

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

@app.route("/goals")
@login_required
def goals():
    goals = db.execute(
            "SELECT * FROM goals WHERE user_id =?", session["user_id"]
        )
    return render_template("goals.html", goals=goals)


@app.route("/delete", methods=["POST"])
@login_required
def delete():
    delete = request.form.get("delete")
    if delete:
        goals = db.execute(
                "DELETE FROM goals WHERE name = ? and user_id = ?", delete, session["user_id"]
            )
    return redirect("/goals", goals=goals)

#TODO
@app.route("/scenery", methods=["GET", "POST"])
@login_required
def scenery():
    goals = db.execute(
            "SELECT * FROM goals WHERE user_id =?", session["user_id"]
            )
    if request.method == "GET":
        return render_template("scenery.html", goals=goals)

    else:
        list = ["static/1.jpg", "static/2.jpg", "static/3.jpg"]
        scenery_selected = request.form.get("option")
        progress = db.execute("SELECT completed_hours FROM goals WHERE name = ? and user_id = ?", scenery_selected, session["user_id"])
        goal = db.execute("SELECT set_goal FROM goals WHERE name = ? and user_id = ?", scenery_selected, session["user_id"])
        percentage = 100 * int(progress[0]["completed_hours"]) / int(goal[0]["set_goal"])

        if percentage < 33:
            number = 0
        if percentage > 33 and percentage < 66:
            number = 1
        if percentage > 66:
            number = 2

        return render_template("scenery.html", img = list[number], goals = goals,)

