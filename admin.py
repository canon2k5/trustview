from flask import Blueprint, render_template, request, redirect, url_for
from utils import load_data, save_data

admin = Blueprint("admin", __name__, url_prefix="/admin")

def login_required(fn):
    from functools import wraps
    from flask import session
    @wraps(fn)
    def wrapped(*args, **kw):
        if not session.get("logged_in"):
            return redirect(url_for("auth.login"))
        return fn(*args, **kw)
    return wrapped

@admin.route("/", methods=["GET","POST"])
@login_required
def index():
    message = ""
    data = load_data()
    websites = data.get("websites", [])

    if request.method == "POST":
        action = request.form.get("action")
        idx    = request.form.get("index")
        name   = request.form.get("name","").strip()
        url    = request.form.get("url","").strip()

        if action == "add" and name and url:
            websites.append({"name": name, "url": url})
            message = f"Added: {name}"
        elif action == "edit" and idx is not None:
            i = int(idx)
            if 0 <= i < len(websites):
                websites[i] = {"name": name, "url": url}
                message = f"Updated: {name}"
        elif action == "delete" and idx is not None:
            i = int(idx)
            if 0 <= i < len(websites):
                rem = websites.pop(i)
                message = f"Deleted: {rem['name']}"

        data["websites"] = websites
        save_data(data)

    return render_template("admin.html", current=websites, message=message)

