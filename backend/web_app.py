
import os
import sys
import subprocess
import threading
from pathlib import Path

from flask import Flask, jsonify, send_from_directory

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
REPORTS_DIR = ROOT_DIR / "reports"
PYTHON_EXE = ROOT_DIR / "venv" / "Scripts" / "python.exe"
HTML_REPORT = REPORTS_DIR / "cloudsentinel_report.html"

app = Flask(__name__)

scan_lock = threading.Lock()
scan_state = {
    "running": False,
    "success": None,
    "message": "No scan has been started from the web app."
}


@app.route("/")
def dashboard():
    if not HTML_REPORT.exists():
        return (
            "Dashboard report not found. Run the scanner first.",
            404
        )

    html = HTML_REPORT.read_text(encoding="utf-8")

    # Add a Run Scan control without changing report_generator.py.
    injection = """
    <style>
      #cs-control {
        position: fixed;
        right: 22px;
        bottom: 22px;
        z-index: 99999;
        background: #101827;
        color: white;
        padding: 16px;
        border-radius: 12px;
        box-shadow: 0 6px 25px #0005;
        font-family: Arial, sans-serif;
      }
      #cs-scan-button {
        background: #16a34a;
        color: white;
        border: 0;
        padding: 10px 16px;
        border-radius: 7px;
        cursor: pointer;
        font-weight: bold;
      }
      #cs-scan-button:disabled {
        opacity: 0.6;
        cursor: wait;
      }
      #cs-status {
        margin-top: 9px;
        font-size: 12px;
        max-width: 260px;
      }
    </style>

    <div id="cs-control">
      <button id="cs-scan-button" onclick="runCloudSentinelScan()">
        Run New Scan
      </button>
      <div id="cs-status">Ready to scan.</div>
    </div>

    <script>
      async function runCloudSentinelScan() {
        const button = document.getElementById("cs-scan-button");
        const status = document.getElementById("cs-status");

        button.disabled = true;
        status.textContent = "Scan running. Please wait...";

        try {
          const response = await fetch("/api/scan", {
            method: "POST"
          });
          const result = await response.json();

          if (!response.ok) {
            throw new Error(result.message || "Scan failed");
          }

          status.textContent = result.message;

          if (result.success) {
            status.textContent += " Refreshing dashboard...";
            setTimeout(() => window.location.reload(), 1200);
          }
        } catch (error) {
          status.textContent = "Error: " + error.message;
        } finally {
          button.disabled = false;
        }
      }
    </script>
    """

    if "</body>" in html.lower():
        position = html.lower().rfind("</body>")
        html = html[:position] + injection + html[position:]
    else:
        html += injection

    return html


@app.route("/api/scan", methods=["POST"])
def run_scan():
    if not scan_lock.acquire(blocking=False):
        return jsonify({
            "success": False,
            "message": "A scan is already running."
        }), 409

    scan_state["running"] = True

    try:
        if not PYTHON_EXE.exists():
            return jsonify({
                "success": False,
                "message": f"Python environment not found: {PYTHON_EXE}"
            }), 500

        result = subprocess.run(
            [str(PYTHON_EXE), "-m", "backend.run_scan"],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=600,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode == 0:
            scan_state["success"] = True
            scan_state["message"] = "Scan completed successfully."
            return jsonify({
                "success": True,
                "message": scan_state["message"],
                "output": result.stdout[-5000:]
            })

        scan_state["success"] = False
        scan_state["message"] = "Scanner failed. Check the terminal output."
        return jsonify({
            "success": False,
            "message": scan_state["message"],
            "output": result.stdout[-3000:],
            "error": result.stderr[-5000:]
        }), 500

    except subprocess.TimeoutExpired:
        scan_state["success"] = False
        scan_state["message"] = "Scan timed out after 10 minutes."
        return jsonify({
            "success": False,
            "message": scan_state["message"]
        }), 504

    except Exception as exc:
        scan_state["success"] = False
        scan_state["message"] = str(exc)
        return jsonify({
            "success": False,
            "message": str(exc)
        }), 500

    finally:
        scan_state["running"] = False
        scan_lock.release()


@app.route("/api/scan-status")
def scan_status():
    return jsonify(scan_state)


@app.route("/reports/<path:filename>")
def report_file(filename):
    return send_from_directory(str(REPORTS_DIR), filename)


@app.route("/cloudsentinel_report.json")
def json_report():
    return send_from_directory(
        str(REPORTS_DIR), "cloudsentinel_report.json"
    )


@app.route("/cloudsentinel_findings.csv")
def csv_report():
    return send_from_directory(
        str(REPORTS_DIR), "cloudsentinel_findings.csv"
    )


if __name__ == "__main__":
    print("CloudSentinel dashboard: http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
