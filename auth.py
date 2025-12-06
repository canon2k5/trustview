from flask import Blueprint, render_template, request, redirect, url_for, session
from utils import load_data

auth = Blueprint("auth", __name__)

def check_login(password):
    import bcrypt
    data = load_data()
    stored = data.get("admin", {}).get("password", "")
    return bcrypt.checkpw(password.encode(), stored.encode()) if stored else False

@auth.route("/login", methods=["GET","POST"])
def login():
    msg = ""
    if request.method == "POST":
        if check_login(request.form["password"]):
            session["logged_in"] = True
            return redirect(url_for("admin.index"))
        msg = "Invalid password"
    return render_template("login.html", message=msg)

@auth.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))

