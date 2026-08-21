# Flask mirror — multi-language SAST surface (sast/params + framework detect).
from flask import Flask, request

app = Flask(__name__)


@app.route("/search")
def search():
    q = request.args.get("q")  # param source
    return f"results for {q}"


@app.route("/login", methods=["POST"])
def login():
    user = request.form.get("user")  # param source
    return f"hello {user}"
