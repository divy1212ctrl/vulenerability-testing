"""
VulnScan Pro — API Server
===========================
Flask REST API that serves scan results to the React dashboard.
Runs on port 8000.  The React dashboard (port 3000) talks to this.

Endpoints:
  GET  /api/results          — latest scan results (from results.json)
  GET  /api/results/history  — list of past scan files
  POST /api/scan             — trigger a new scan (async, streamed progress)
  GET  /api/health           — server health check

Usage:
  python api_server.py                      # standalone
  python main.py --target ... --serve       # auto-started after scan
"""

import json
import os
import glob
import subprocess
import sys
import datetime
from flask import Flask, jsonify, request, Response, stream_with_context
from flask_cors import CORS                  # pip install flask-cors


def create_app(results_dir: str = "reports") -> Flask:
    app = Flask(__name__)
    CORS(app, origins=["http://localhost:3000", "http://127.0.0.1:3000"])

    RESULTS_DIR = os.path.abspath(results_dir)
    RESULTS_JSON = os.path.join(RESULTS_DIR, "results.json")

    def _load_results(path: str) -> dict:
        if not os.path.exists(path):
            return {"error": "No results file found. Run a scan first.", "findings": []}
        try:
            with open(path, encoding="utf-8") as fp:
                return json.load(fp)
        except json.JSONDecodeError as e:
            return {"error": f"Malformed results file: {e}", "findings": []}

    def _severity_summary(findings: list) -> dict:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in findings:
            sev = f.get("severity", "Info")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @app.route("/api/health")
    def health():
        return jsonify({
            "status":      "ok",
            "service":     "VulnScan Pro API",
            "version":     "1.0.0",
            "results_dir": RESULTS_DIR,
            "has_results": os.path.exists(RESULTS_JSON),
            "timestamp":   datetime.datetime.now().isoformat(),
        })

    @app.route("/api/results")
    def get_results():
        data = _load_results(RESULTS_JSON)
        if "findings" in data:
            data["summary"] = _severity_summary(data["findings"])
            type_counts: dict = {}
            for f in data["findings"]:
                t = f.get("type", "Unknown")
                type_counts[t] = type_counts.get(t, 0) + 1
            data["by_type"] = [
                {"name": k, "count": v} for k, v in
                sorted(type_counts.items(), key=lambda x: -x[1])
            ]
        return jsonify(data)

    @app.route("/api/results/history")
    def get_history():
        pattern = os.path.join(RESULTS_DIR, "*.json")
        files = sorted(glob.glob(pattern), key=os.path.getmtime, reverse=True)
        history = []
        for fpath in files:
            try:
                stat = os.stat(fpath)
                with open(fpath, encoding="utf-8") as fp:
                    d = json.load(fp)
                history.append({
                    "filename":  os.path.basename(fpath),
                    "target":    d.get("target", "unknown"),
                    "timestamp": d.get("timestamp", ""),
                    "total":     d.get("total", 0),
                    "size_kb":   round(stat.st_size / 1024, 1),
                })
            except Exception:
                continue
        return jsonify({"history": history, "count": len(history)})

    @app.route("/api/scan", methods=["POST"])
    def trigger_scan():
        body   = request.get_json(silent=True) or {}
        target = body.get("target", "").strip()
        fmt    = body.get("format", "html")

        if not target:
            return jsonify({"error": "target is required"}), 400
        if not target.startswith(("http://", "https://")):
            return jsonify({"error": "target must start with http:// or https://"}), 400
        if fmt not in ("html", "pdf", "both"):
            fmt = "html"

        def generate():
            scanner_path = os.path.join(os.path.dirname(__file__), "main.py")
            cmd = [
                sys.executable, scanner_path,
                "--target", target,
                "--format", fmt,
                "--out", RESULTS_DIR,
            ]

            yield json.dumps({"event": "start", "target": target,
                              "timestamp": datetime.datetime.now().isoformat()}) + "\n"

            try:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                for line in proc.stdout:
                    line = line.rstrip()
                    if line:
                        import re
                        clean = re.sub(r"\033\[[0-9;]*m", "", line)
                        yield json.dumps({"event": "log", "line": clean}) + "\n"

                proc.wait()
                status = "done" if proc.returncode == 0 else "error"
                yield json.dumps({"event": status,
                                  "returncode": proc.returncode,
                                  "timestamp": datetime.datetime.now().isoformat()}) + "\n"
            except Exception as exc:
                yield json.dumps({"event": "error", "message": str(exc)}) + "\n"

        return Response(
            stream_with_context(generate()),
            mimetype="application/x-ndjson",
            headers={"X-Accel-Buffering": "no"},
        )

    @app.route("/api/findings/export")
    def export_findings():
        data = _load_results(RESULTS_JSON)
        resp = jsonify(data)
        resp.headers["Content-Disposition"] = "attachment; filename=vulnscan-results.json"
        return resp

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Endpoint not found"}), 404

    return app


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="VulnScan Pro API Server")
    p.add_argument("--results-dir", default="reports",
                   help="Directory containing results.json (default: reports/)")
    p.add_argument("--port", type=int, default=8000)
    args = p.parse_args()

    flask_app = create_app(results_dir=args.results_dir)
    print(f"[*] VulnScan Pro API Server starting on http://0.0.0.0:{args.port}")
    print(f"[*] Serving results from: {os.path.abspath(args.results_dir)}")
    print(f"[*] Dashboard: http://localhost:3000\n")
    flask_app.run(host="0.0.0.0", port=args.port, debug=False)
