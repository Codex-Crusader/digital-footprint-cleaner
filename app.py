import os
import logging
from flask import Flask, render_template, request, session, flash, redirect, url_for
from scanner import find_footprint
from utils import petition_writer

# Set up basic logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Still works out-of-the-box; no env variables needed

@app.route("/", methods=["GET", "POST"])
def index():
    """
    Render the homepage and handle digital footprint search form.
    """
    results = []
    user_info = ""
    error = None

    if request.method == "POST":
        user_info = request.form.get("user_info", "").strip()
        if not user_info:
            error = "Please provide your information."
            logger.warning("No user_info provided in form submission.")
        else:
            try:
                results = find_footprint(user_info)
                session["result_map"] = {item["id"]: item["url"] for item in results}
            except Exception as e:
                error = "There was an error processing your request."
                logger.error("Error in find_footprint: %s", e)

    return render_template("index.html", results=results, user_info=user_info, error=error)

@app.route("/send", methods=["POST"])
def send():
    """
    Handle sending petitions based on selected sites.
    """
    selected_ids = request.form.getlist("selected_sites")
    user_name = request.form.get("user_name", "John Doe")  # keeps existing default
    result_map = session.get("result_map", {})

    if not selected_ids:
        flash("No sites selected. Please select at least one site.", "warning")
        logger.warning("No sites selected for petition send.")
        return redirect(url_for("index"))

    if not isinstance(result_map, dict):
        flash("Session expired or invalid. Please start again.", "danger")
        logger.error("Invalid session result_map.")
        return redirect(url_for("index"))

    try:
        petition_writer.send_petitions(selected_ids, result_map, user_name)
        logger.info("Petitions sent by %s to: %s", user_name, selected_ids)
        flash("Petitions sent successfully! Check console/logs for details.", "success")
    except Exception as e:
        logger.error("Error sending petitions: %s", e)
        flash("An error occurred while sending petitions.", "danger")

    return redirect(url_for("index"))

@app.route("/legal")
def legal():
    """Display the legal information page."""
    return render_template("legal.html")

if __name__ == "__main__":
    app.run(debug=True)
