import os
from flask import Flask, render_template, request, session
from scanner import find_footprint
from utils import petition_writer

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Enables Flask session storage

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        user_info = request.form["user_info"]
        results = find_footprint(user_info)

        # Store ID → URL mapping in session
        session["result_map"] = {item["id"]: item["url"] for item in results}

        return render_template("index.html", results=results, user_info=user_info)

    return render_template("index.html", results=[], user_info="")

@app.route("/send", methods=["POST"])
def send():
    selected_ids = request.form.getlist("selected_sites")
    user_name = request.form.get("user_name", "John Doe")  # default if empty
    result_map = session.get("result_map", {})

    petition_writer.send_petitions(selected_ids, result_map, user_name)
    return "<h2>Petitions sent (check console/logs)</h2><p><a href='/'>← Go back</a></p>"

@app.route("/legal")
def legal():
    return render_template("legal.html")

if __name__ == "__main__":
    app.run(debug=True)