"""XSS-001 to XSS-005 HTTP-level validation plus browser-evidence linkage.

The headless browser run (browser/browser_xss.js) provides actual execution
evidence.  This module records the corresponding raw HTTP request/response,
the filter or token precondition, and the stored-write database state.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wp4lib import (  # noqa: E402
    BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, db_query, dvwa_login, extract_token,
)

DEPLOYMENT = "dvwa-wsl-01"
ADMIN_USER = "admin"
ADMIN_PASS = "password"


def payload(marker: str, short: bool = False) -> str:
    if short:
        return f"<svg onload=\"window.__wp4xss='{marker}'\">"
    return f"<svg onload=\"window.__wp4xss='{marker}';document.title='{marker}'\">"


def attach_browser(run: Run) -> dict:
    data = {}
    for name in ("browser.json", "browser.png"):
        path = run.dir / name
        if path.exists():
            run.add_artifact(path, f"headless browser evidence: {name}")
            if name.endswith(".json"):
                data = json.loads(path.read_text(encoding="utf-8"))
    return data


def reflected_case(number: str, level: str, filter_control: str | None = None) -> dict:
    marker = f"WP4XSS{number}"
    run = Run(
        f"wp4-20261019-xss{number}-{level}", f"XSS-{number}",
        "vulnerabilities/xss_r/index.php:name",
        f"env=dvwa-wsl-01|role=admin|security={level}|object=none|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_DVWA,
    )
    client = Client(BASE_DVWA, forced_security=level)
    index = dvwa_login(client, ADMIN_USER, ADMIN_PASS)
    run.add_response("login-index", index)
    run.requests.extend(client.requests)
    client.requests.clear()

    normal = client.get("/vulnerabilities/xss_r/?name=WP4_CONTROL")
    run.add_response("normal-control", normal)
    xss_payload = payload(marker)
    test = client.get("/vulnerabilities/xss_r/?name=" + __import__("urllib.parse").parse.quote(xss_payload))
    run.add_response("xss-payload", test)

    observation = {
        "endpoint": "/vulnerabilities/xss_r/index.php",
        "parameter": "name (GET)",
        "security_level": level,
        "identity": {"logged_in": "You have logged in as" in index.text},
        "normal_control": {
            "status": normal.status,
            "control_reflected": "WP4_CONTROL" in normal.text,
        },
        "test": {
            "status": test.status,
            "payload": xss_payload,
            "payload_reflected_verbatim": xss_payload in test.text,
            "response_bytes": len(test.body),
        },
    }
    if filter_control:
        control = client.get("/vulnerabilities/xss_r/?name=" + __import__("urllib.parse").parse.quote(filter_control))
        run.add_response("filter-control", control)
        observation["filter_control"] = {
            "input": filter_control,
            "raw_script_tag_present": filter_control in control.text,
            "script_keyword_present": "<script>" in control.text,
        }
    browser = attach_browser(run)
    observation["browser_execution"] = {
        "executed": browser.get("executed"),
        "marker_in_raw_html": browser.get("marker_in_raw_html"),
        "page_errors": browser.get("page_errors", []),
        "screenshot": browser.get("screenshot"),
    }
    run.requests.extend(client.requests)
    run.observation = observation
    run.success_criteria = [
        "The page returns an authenticated response and reflects the control text.",
        "The payload reaches the final HTML position without an applicable output filter.",
        "Headless Chrome sets the JS marker in the page context, proving execution, not just reflection.",
    ]
    run.limitations = [
        f"Only the {level} xss_r path is covered in one desktop Chrome version.",
        "The marker is harmless and creates no network request.",
    ]
    executed = bool(browser.get("executed"))
    run.finalize("触发" if executed else "未触发", "有漏洞" if executed else "证据不足")
    return observation


def impossible_case() -> dict:
    run = Run(
        "wp4-20261019-xss004-impossible", "XSS-004",
        "vulnerabilities/xss_r/index.php:name",
        "env=dvwa-wsl-01|role=admin|security=impossible|object=none|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_DVWA,
    )
    client = Client(BASE_DVWA, forced_security="impossible")
    index = dvwa_login(client, ADMIN_USER, ADMIN_PASS)
    run.add_response("login-index", index)
    run.requests.extend(client.requests)
    client.requests.clear()

    page = client.get("/vulnerabilities/xss_r/")
    token = extract_token(page.text)
    run.add_response("token-page", page)
    xss_payload = payload("WP4XSS004")
    encoded = client.get(
        "/vulnerabilities/xss_r/?name=" + __import__("urllib.parse").parse.quote(xss_payload)
        + "&user_token=" + (token or ""))
    run.add_response("valid-token-encoded", encoded)
    missing = client.get("/vulnerabilities/xss_r/?name=" + __import__("urllib.parse").parse.quote(xss_payload))
    run.add_response("missing-token-precondition", missing)
    browser = attach_browser(run)
    observation = {
        "endpoint": "/vulnerabilities/xss_r/index.php",
        "parameter": "name (GET) plus user_token",
        "security_level": "impossible",
        "identity": {"logged_in": "You have logged in as" in index.text},
        "token_obtained": token is not None,
        "valid_token_request": {
            "status": encoded.status,
            "raw_svg_present": xss_payload in encoded.text,
            "encoded_lt_present": "&lt;svg" in encoded.text,
            "encoded_quote_present": "&quot;" in encoded.text,
        },
        "missing_token_request": {
            "status": missing.status,
            "redirected": missing.status == 302,
            "location": missing.header("Location"),
            "payload_present": xss_payload in missing.text,
        },
        "browser_execution": {
            "executed": browser.get("executed"),
            "encoded_output_observed": browser.get("encoded_output_observed"),
            "missing_token_redirected": browser.get("missing_token_redirected"),
            "screenshot": browser.get("screenshot"),
        },
    }
    run.requests.extend(client.requests)
    run.observation = observation
    run.success_criteria = [
        "A fresh token is required; omitting it is a precondition failure, not proof of encoding.",
        "With a valid token the input is encoded and no malformed HTML is produced.",
        "Headless Chrome reports no marker execution in the encoded output.",
        "The negative result is limited to the impossible xss_r path.",
    ]
    run.limitations = [
        "Token refusal is recorded separately and is not treated as XSS protection.",
        "Only one browser and this DVWA commit are covered.",
    ]
    protected = (observation["valid_token_request"]["status"] == 200
                 and observation["valid_token_request"]["encoded_lt_present"]
                 and not observation["valid_token_request"]["raw_svg_present"]
                 and not browser.get("executed"))
    run.finalize("未触发", "无所关注漏洞" if protected else "证据不足")
    return observation


def stored_case() -> dict:
    run = Run(
        "wp4-20261019-xss005-low", "XSS-005",
        "vulnerabilities/xss_s/index.php:btnSign/mtxMessage",
        "env=dvwa-wsl-01|role=admin|security=low|object=dedicated-guestbook|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_DVWA,
    )
    client = Client(BASE_DVWA, forced_security="low")
    index = dvwa_login(client, ADMIN_USER, ADMIN_PASS)
    run.add_response("login-index", index)
    run.requests.extend(client.requests)
    client.requests.clear()

    name = "wp4x5h"
    marker = "WP4XSS005"
    xss_payload = payload(marker, short=True)
    db_query(f"DELETE FROM dvwa.guestbook WHERE name='{name}'")
    page = client.get("/vulnerabilities/xss_s/")
    run.add_response("write-page", page)
    write = client.post("/vulnerabilities/xss_s/", {
        "btnSign": "Sign Guestbook", "txtName": name, "mtxMessage": xss_payload,
    })
    run.add_response("write-request", write)
    rows = db_query(
        "SELECT comment_id, name, comment FROM dvwa.guestbook "
        f"WHERE name='{name}' ORDER BY comment_id")
    persisted = bool(rows) and rows[0][2] == xss_payload
    read = client.get("/vulnerabilities/xss_s/")
    run.add_response("read-page", read)
    browser = attach_browser(run)
    observation = {
        "endpoint": "/vulnerabilities/xss_s/index.php",
        "parameters": "btnSign, txtName, mtxMessage (POST); guestbook read on GET",
        "security_level": "low",
        "identity": {"logged_in": "You have logged in as" in index.text},
        "write": {
            "status": write.status,
            "payload": xss_payload,
            "payload_length": len(xss_payload),
            "maxlength_client_side": 50,
            "marker_in_write_response": xss_payload in write.text,
        },
        "persistence": {
            "row_count": len(rows),
            "comment_id": rows[0][0] if rows else None,
            "stored_verbatim": persisted,
        },
        "read": {
            "status": read.status,
            "payload_in_read_html": xss_payload in read.text,
        },
        "browser_execution": {
            "executed": browser.get("executed"),
            "marker_in_raw_html": browser.get("marker_in_raw_html"),
            "screenshot": browser.get("screenshot"),
        },
    }
    # Targeted cleanup of both the HTTP-run row and the browser-run row.
    db_query("DELETE FROM dvwa.guestbook WHERE name IN ('wp4x5h','wp4x5')")
    remaining = db_query("SELECT COUNT(*) FROM dvwa.guestbook WHERE name IN ('wp4x5h','wp4x5')")
    observation["cleanup"] = {
        "targeted_delete_names": ["wp4x5h", "wp4x5"],
        "remaining_rows": int(remaining[0][0]) if remaining else None,
    }
    run.requests.extend(client.requests)
    run.restore_result = {
        "required": True,
        "action": "delete dedicated guestbook rows by name (not TRUNCATE)",
        "result": "restored" if (remaining and remaining[0][0] == "0") else "failed",
    }
    run.observation = observation
    run.success_criteria = [
        "A dedicated guestbook row is written and read back verbatim from MariaDB.",
        "The read page renders the row without output encoding at low.",
        "Headless Chrome executes the marker from the stored payload.",
        "Only the dedicated rows are deleted by name; the rest of the guestbook is untouched.",
    ]
    run.limitations = [
        "The write path covered is low.php; other write levels are outside this input packet.",
        "The payload is deliberately shortened to respect the 50-character textarea limit.",
    ]
    positive = (persisted and browser.get("executed")
                and observation["cleanup"]["remaining_rows"] == 0)
    run.finalize("触发" if positive else "未触发", "有漏洞" if positive else "证据不足")
    return observation


CASES = {"001": ("low", None), "002": ("medium", "<script>alert(1)</script>"),
         "003": ("high", "<script>alert(1)</script>"), "004": None, "005": None}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=["001", "002", "003", "004", "005", "all"], default="all")
    args = parser.parse_args()
    selected = ["001", "002", "003", "004", "005"] if args.case == "all" else [args.case]
    results = {}
    for key in selected:
        if key == "004":
            results[key] = impossible_case()
        elif key == "005":
            results[key] = stored_case()
        else:
            level, control = CASES[key]
            results[key] = reflected_case(key, level, control)
    print(json.dumps({"executed": selected}, ensure_ascii=False))


if __name__ == "__main__":
    main()
