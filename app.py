"""Smart Network Traffic Analyzer - Flask application factory."""
import hmac
import logging
import secrets

from flask import Flask, jsonify, render_template, request, session
from werkzeug.exceptions import HTTPException

import config
import database
import models
from routes import alerts, analysis, capture, dashboard, history, packets, reports, settings
from routes.common import ApiError

PAGES = {  # endpoint path -> (template, title)
    "/": ("index.html", "Home"), "/dashboard": ("dashboard.html", "Dashboard"),
    "/monitor": ("monitor.html", "Live Monitor"), "/upload": ("upload.html", "Upload PCAP"),
    "/packets": ("packets.html", "Packet Explorer"), "/protocols": ("protocols.html", "Protocols"),
    "/alerts": ("alerts.html", "Alerts"), "/history": ("history.html", "History"),
    "/settings": ("settings.html", "Settings"), "/about": ("about.html", "About"),
}
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def create_app(test_config=None):
    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=config.MAX_UPLOAD_MB * 1024 * 1024, SESSION_COOKIE_HTTPONLY=True,
                      SESSION_COOKIE_SAMESITE="Lax")
    app.json.sort_keys = False
    app.config["SECRET_KEY"] = config.load_secret_key()
    app.config.update(test_config or {})
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    database.init_db()
    models.mark_stale_processing()
    models.purge_expired(database.get_settings()["retention_days"])

    for module in (dashboard, analysis, capture, packets, alerts, reports, history, settings):
        app.register_blueprint(module.bp, url_prefix="/api")

    # ---------- CSRF (session token sent as X-CSRF-Token by static/js/main.js) ----------
    def token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    @app.before_request
    def csrf_protect():
        if request.method in UNSAFE and request.path.startswith("/api/"):
            sent = request.headers.get("X-CSRF-Token", "")
            if not hmac.compare_digest(sent, session.get("csrf", "\0")):
                raise ApiError("Missing or invalid CSRF token. Reload the page and try again.", 403)

    @app.after_request
    def security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        return resp

    # ---------- pages ----------
    @app.context_processor
    def inject():
        return {"csrf_token": token(), "theme": database.get_settings()["theme"], "nav": PAGES}

    def make_page(template, title):
        def view():
            return render_template(template, title=title, active=request.path)
        return view

    for path, (template, title) in PAGES.items():
        app.add_url_rule(path, endpoint=f"page_{template}", view_func=make_page(template, title))

    # ---------- centralised error handling (JSON for the API, no stack traces) ----------
    @app.errorhandler(ApiError)
    def api_error(e):
        return jsonify({"error": e.message}), e.status

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith("/api/"):
            msg = ("File too large. Maximum upload size is %d MB" % config.MAX_UPLOAD_MB
                   if e.code == 413 else e.description)
            return jsonify({"error": msg}), e.code
        return render_template("error.html", title=e.name, code=e.code, message=e.description, active=""), e.code

    @app.errorhandler(Exception)
    def unexpected(e):
        app.logger.exception("Unhandled error")
        if request.path.startswith("/api/"):
            return jsonify({"error": "Internal server error"}), 500
        return render_template("error.html", title="Error", code=500,
                               message="Something went wrong on the server.", active=""), 500

    return app


if __name__ == "__main__":
    # debug stays OFF: the Werkzeug debugger would expose code execution. Localhost-only by default.
    create_app().run(host=config.HOST, port=config.PORT, debug=False, threaded=True)
