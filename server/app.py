"""
Minimal login web app for the HTTP-session-hijack demo (Design Report
Section 3.5 / Phase 4). Runs on the SERVER VM (192.168.56.20).

Deliberately weak, on purpose:
  - Plain HTTP, no TLS -> the Cookie/Set-Cookie header is sniffable in the
    clear by anyone on-path (Section 2.2).
  - Cookie has none of Section 6's hardening (no Secure/HttpOnly/SameSite,
    no IP/User-Agent binding) -> a bare replay of the token is enough.
  - Session store is a plain server-side dict keyed by the literal token
    value, matching the "Cookie: session=abc123xyz" example in Section 3.5.

Run:
    sudo python3 server/app.py --host 0.0.0.0 --port 80
"""

import argparse
import secrets

from flask import Flask, make_response, redirect, render_template_string, request

app = Flask(__name__)

# username -> password (plaintext on purpose; this is a hijack demo, not a
# credential-storage demo). Not used by the attack itself -- the attacker
# never needs these, only the cookie.
USERS = {"alice": "password123"}

# session token -> username. This dict IS the server's notion of "logged in".
# Anyone who presents a known token is treated as that user; the server has
# no way to distinguish the real client from a replay (Section 3.5, last line).
SESSIONS = {}

LOGIN_PAGE = """
<!doctype html>
<title>Lab Login</title>
<h2>Session Hijack Demo - Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post" action="/login">
  <input name="username" placeholder="username" value="alice"><br>
  <input name="password" type="password" placeholder="password"><br>
  <button type="submit">Log in</button>
</form>
"""

ACCOUNT_PAGE = """
<!doctype html>
<title>Account</title>
<h2>Welcome, {{ username }}</h2>
<p>This is the protected page. If you can read this, your session cookie
was accepted -- with or without a password.</p>
"""


@app.route("/", methods=["GET"])
def login_form():
    return render_template_string(LOGIN_PAGE, error=None)


@app.route("/login", methods=["POST"])
def login():
    # Credentials arrive in the POST body over plain HTTP, same as the
    # Cookie header later -- both are cleartext to an on-path attacker,
    # but this project only needs the *cookie* to be stealable.
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    if USERS.get(username) != password:
        return render_template_string(LOGIN_PAGE, error="Invalid credentials"), 401

    # Mint a fresh opaque session token. This is the value that will show
    # up on the wire as "Set-Cookie: session=<token>" (Section 3.5) and is
    # the entire target of Phase 4.
    token = secrets.token_hex(8)
    SESSIONS[token] = username

    response = make_response(redirect("/account"))
    # Section 3.5: Set-Cookie: session=abc123xyz; Path=/
    # No Secure/HttpOnly/SameSite -- see Section 6 for what those would add.
    response.set_cookie("session", token, path="/")
    return response


@app.route("/account", methods=["GET"])
def account():
    # Section 3.5: the server's entire authentication check for this
    # request is "was this token in the Cookie header issued by /login?" --
    # it cannot tell a replayed cookie from the original request.
    token = request.cookies.get("session")
    username = SESSIONS.get(token)
    if not username:
        return "401 Unauthorized: no valid session cookie", 401
    return render_template_string(ACCOUNT_PAGE, username=username)


@app.route("/logout", methods=["GET"])
def logout():
    token = request.cookies.get("session")
    SESSIONS.pop(token, None)
    response = make_response(redirect("/"))
    response.delete_cookie("session", path="/")
    return response


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args()

    print(f"[server] plaintext HTTP login app on http://{args.host}:{args.port}")
    print(f"[server] test user: alice / password123")
    app.run(host=args.host, port=args.port, debug=False)
