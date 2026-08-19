from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q")
    return q or ""


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")
    return user or ""
