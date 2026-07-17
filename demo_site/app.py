"""
Demo Site — the website ShieldNet is protecting.

This is intentionally a separate, simple Flask app with NO detection or
blocking logic of its own. All protection is meant to happen upstream in
ShieldNet's reverse proxy (/protected/...) - this app just represents "the
real site behind the shield" and runs on its own port.

Run this alongside app.py (ShieldNet), on a different port:
    python demo_site/app.py
Then access it THROUGH ShieldNet at:
    http://127.0.0.1:5000/protected/
Not directly at port 6000, if you want ShieldNet's protection to apply.
"""

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