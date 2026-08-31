"""Web Application Reconnaissance Tool — Flask entrypoint."""

import logging

from flask import Flask, render_template, request, redirect, url_for, abort, jsonify, make_response

import config
from core.validator import validate_target, ValidationError
from core import job_manager
from reports.pdf_report import render_pdf

app = Flask(__name__)
app.config.from_object(config)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("recon-tool")


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    raw_target = request.form.get("target", "")
    port_scan_requested = request.form.get("port_scan") == "1"
    authorize_confirm = (request.form.get("authorize_confirm") or "").strip().lower()

    try:
        target = validate_target(raw_target)
    except ValidationError as exc:
        return render_template("index.html", error=str(exc), submitted_target=raw_target), 400

    port_scan_authorized = False
    if port_scan_requested:
        if authorize_confirm != target["hostname"].lower():
            return render_template(
                "index.html",
                error="To run the port scan you must re-type the exact target domain "
                      "in the authorization box to confirm you're authorized to test it.",
                submitted_target=raw_target,
            ), 400
        port_scan_authorized = True
        # Authorized port scans are logged server-side per the design's
        # authorization-gate requirement.
        logger.info("AUTHORIZED PORT SCAN requested for %s from %s",
                     target["hostname"], request.remote_addr)

    options = {"port_scan": port_scan_requested, "port_scan_authorized": port_scan_authorized}
    job_id = job_manager.start_scan(target, options)

    return redirect(url_for("scan_progress", job_id=job_id, hostname=target["hostname"]))


@app.route("/scan/<job_id>/progress")
def scan_progress(job_id):
    job = job_manager.get_job(job_id)
    if job is None:
        abort(404)
    if job["status"] == "complete":
        return redirect(url_for("report_view", scan_id=job_id))
    hostname = request.args.get("hostname", "")
    return render_template("progress.html", job_id=job_id, hostname=hostname)


@app.route("/scan/<job_id>/status")
def scan_status(job_id):
    job = job_manager.get_job(job_id)
    if job is None:
        return jsonify({"error": "not found"}), 404
    return jsonify({
        "status": job["status"],
        "modules_total": job["modules_total"],
        "modules_complete": job["modules_complete"],
        "error": job["error"],
    })


@app.route("/scan/<job_id>/report")
def report_view(job_id):
    job = job_manager.get_job(job_id)
    if job is None or job["status"] != "complete":
        abort(404)
    return render_template("report.html", report=job["report"], is_pdf=False)


@app.route("/report/<scan_id>/pdf")
def report_pdf(scan_id):
    job = job_manager.get_job(scan_id)
    if job is None or job["status"] != "complete":
        abort(404)
    html_string = render_template("report_pdf.html", report=job["report"])
    pdf_bytes = render_pdf(html_string)
    response = make_response(pdf_bytes)
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = (
        f'attachment; filename="recon-profile-{job["report"]["target"]["hostname"]}.pdf"'
    )
    return response


# --- JSON API ----------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.json or {}
    raw_target = payload.get("target", "")
    try:
        target = validate_target(raw_target)
    except ValidationError as exc:
        return jsonify({"error": str(exc)}), 400

    options = {
        "port_scan": bool(payload.get("port_scan")) and payload.get("authorize_confirm", "").strip().lower() == target["hostname"].lower(),
    }
    options["port_scan_authorized"] = options["port_scan"]
    job_id = job_manager.start_scan(target, options)
    return jsonify({"job_id": job_id})


@app.route("/api/scan/<job_id>/status")
def api_scan_status(job_id):
    return scan_status(job_id)


@app.route("/api/scan/<job_id>/report")
def api_scan_report(job_id):
    job = job_manager.get_job(job_id)
    if job is None:
        return jsonify({"error": "not found"}), 404
    if job["status"] != "complete":
        return jsonify({"status": job["status"]}), 202
    return jsonify(job["report"])


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=config.DEBUG)
