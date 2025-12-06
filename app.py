import os
import io
import csv
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, render_template, jsonify, Response
from utils import load_data, ensure_admin_password, check_website_status
import utils
import auth, admin

def get_bool(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in {"1", "true", "yes", "on"}

app = Flask(__name__, static_folder="static")

# Config
app.secret_key = os.getenv("SECRET_KEY", os.urandom(32))
DEBUG = get_bool("FLASK_DEBUG", True)
MAX_THREADS = int(os.getenv("STATUS_THREADS", "8"))
DEFAULT_MAX_T = int(os.getenv("MAX_GAUGE", "500"))

# Blueprints
app.register_blueprint(auth.auth, url_prefix="/auth")
app.register_blueprint(admin.admin, url_prefix="/admin")

# Template globals
@app.context_processor
def inject_globals():
    return {"current_year": datetime.now(timezone.utc).year}

# Filters
@app.template_filter("clamp")
def clamp(value, maximum):
    try:
        return min(int(value), int(maximum))
    except (TypeError, ValueError):
        return 0

@app.before_first_request
def _init_once():
    # Create/set admin password if needed
    ensure_admin_password()

def _collect_status(sites):
    """Collect site status with limited parallelism."""
    results = []
    if not sites:
        return results

    # Parallelize external checks to speed up the dashboard/export
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as ex:
        future_map = {ex.submit(check_website_status, site): site for site in sites}
        for fut in as_completed(future_map):
            site = future_map[fut]
            base = {"name": site.get("name", ""), "url": site.get("url", "")}
            try:
                base.update(fut.result())
            except Exception as e:
                # Ensure the UI does not break on exceptions
                base.update({
                    "status": "error",
                    "error": str(e),
                    "cert": {"issuer": "", "expires": "", "days_left": None}
                })
            results.append(base)

    # Sort by status then days_left (robust to missing keys)
    order = {
        "healthy": 0,
        "expiring": 1,
        "critical": 2,
        "error": 3,
        "warning": 4,
        "offline": 5,
        "online": 6,
    }
    def sort_key(x):
        status_rank = order.get(x.get("status"), 9)
        cert = x.get("cert") or {}
        days_left = cert.get("days_left")
        try:
            dl = int(days_left) if days_left is not None else 9999
        except (TypeError, ValueError):
            dl = 9999
        return (status_rank, dl)

    results.sort(key=sort_key)
    return results

@app.route("/health")
def health():
    return jsonify({"ok": True, "time": datetime.now(timezone.utc).isoformat()})

@app.route("/")
def dashboard():
    data = utils.load_data().get("websites", [])
    results = _collect_status(data)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    return render_template("dashboard.html", results=results, now=now, max_t=DEFAULT_MAX_T)

@app.route("/export.<fmt>")
def export(fmt):
    data = utils.load_data().get("websites", [])
    results = _collect_status(data)

    out = []
    for r in results:
        c = (r.get("cert") or {})
        out.append({
            "name":      r.get("name", ""),
            "url":       r.get("url", ""),
            "status":    r.get("status", ""),
            "issuer":    c.get("issuer", ""),
            "expires":   c.get("expires", ""),
            "days_left": c.get("days_left", ""),
        })

    if fmt == "json":
        return jsonify(out)

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["name","url","status","issuer","expires","days_left"])
        writer.writeheader()
        for row in out:
            writer.writerow(row)
        resp = Response(buf.getvalue(), mimetype="text/csv; charset=utf-8")
        resp.headers["Content-Disposition"] = 'attachment; filename="trustcheck_export.csv"'
        return resp

    if fmt == "xml":
        import xml.etree.ElementTree as ET
        root = ET.Element("websites")
        for row in out:
            e = ET.SubElement(root, "site")
            for k, v in row.items():
                ET.SubElement(e, k).text = "" if v is None else str(v)
        def _indent(elem, level=0):
            pad = "\n" + ("  " * level)
            children = list(elem)
            if children:
                if not elem.text or not elem.text.strip():
                    elem.text = pad + "  "
                for child in children:
                    _indent(child, level + 1)
                if not children[-1].tail or not children[-1].tail.strip():
                    children[-1].tail = pad
            elif level and (not elem.tail or not elem.tail.strip()):
                elem.tail = pad

        _indent(root)
        tree = ET.ElementTree(root)
        buf = io.BytesIO()
        tree.write(buf, encoding="utf-8", xml_declaration=True)
        xml_bytes = buf.getvalue()
        resp = Response(xml_bytes, mimetype="application/xml; charset=utf-8")
        resp.headers["Content-Disposition"] = 'attachment; filename="trustcheck_export.xml"'
        return resp

    return "Invalid format", 400

if __name__ == "__main__":
    app.run(debug=DEBUG, host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")))
