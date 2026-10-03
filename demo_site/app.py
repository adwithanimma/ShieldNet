

from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)


@app.route('/')
def login_page():
    return render_template("login.html")


@app.route('/welcome', methods=["POST"])
def welcome():
    # Demo only - accepts any username/password, no real authentication.
    username = request.form.get("username", "Guest")
    return render_template("welcome.html", username=username)


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=6060, debug=False)