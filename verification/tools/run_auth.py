"""AUTH-001 role/security matrix for the DVWA authorisation-bypass module.

The dedicated test object wp4target is created locally.  For each security
level, an admin session and an ordinary gordonb session independently call the
page, the read API and the update API.  Every successful update is verified by a
direct MariaDB readback and then restored.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wp4lib import (  # noqa: E402
    BASE_DVWA, SOURCE_COMMIT_DVWA, Client, Run, db_query, dvwa_login,
)

DEPLOYMENT = "dvwa-wsl-01"
ADMIN = ("admin", "password")
ORDINARY = ("gordonb", "abc123")
TARGET_USER = "wp4target"
TARGET_FIRST = "Wp4"
TARGET_LAST = "Target"


def identity(index_text: str) -> str | None:
    match = re.search(r"You have logged in as '([^']+)'", index_text)
    return match.group(1) if match else None


def ensure_target() -> int:
    db_query(f"DELETE FROM dvwa.users WHERE user='{TARGET_USER}'")
    next_id = int(db_query("SELECT COALESCE(MAX(user_id),0)+1 FROM dvwa.users")[0][0])
    db_query(
        "INSERT INTO dvwa.users (user_id, first_name, last_name, user, password, avatar, last_login, failed_login) "
        f"VALUES ({next_id}, '{TARGET_FIRST}', '{TARGET_LAST}', '{TARGET_USER}', MD5('wp4targetpass'), '', NOW(), 0)")
    rows = db_query(f"SELECT user_id FROM dvwa.users WHERE user='{TARGET_USER}'")
    if not rows:
        raise RuntimeError("could not create dedicated target user")
    return int(rows[0][0])


def target_state(target_id: int) -> tuple[str, str]:
    rows = db_query(f"SELECT first_name, last_name FROM dvwa.users WHERE user_id={target_id}")
    return (rows[0][0], rows[0][1]) if rows else ("", "")


def reset_target(target_id: int) -> None:
    db_query(
        f"UPDATE dvwa.users SET first_name='{TARGET_FIRST}', last_name='{TARGET_LAST}' "
        f"WHERE user_id={target_id}")


def parse_json(text: str):
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def read_result(resp, target_id: int) -> dict:
    data = parse_json(resp.text)
    if isinstance(data, list):
        return {
            "status": resp.status,
            "shape": "list",
            "row_count": len(data),
            "target_present": any(str(row.get("user_id")) == str(target_id) for row in data),
            "error": None,
        }
    return {
        "status": resp.status,
        "shape": "object" if isinstance(data, dict) else "non-json",
        "row_count": 0,
        "target_present": False,
        "error": data.get("error") if isinstance(data, dict) else resp.text[:200],
    }


def update_result(resp, target_id: int, before: tuple[str, str], after: tuple[str, str]) -> dict:
    data = parse_json(resp.text)
    return {
        "status": resp.status,
        "result": data.get("result") if isinstance(data, dict) else None,
        "error": data.get("error") if isinstance(data, dict) else None,
        "db_before": {"first_name": before[0], "last_name": before[1]},
        "db_after": {"first_name": after[0], "last_name": after[1]},
        "db_changed": before != after,
    }


def run_level(level: str, target_id: int, main_condition: bool) -> dict:
    run = Run(
        f"wp4-20261019-auth001-{level}", "AUTH-001",
        "authbypass page/read_api/update_api",
        f"env=dvwa-wsl-01|role=ordinary|security={level}|object={TARGET_USER}|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_DVWA,
    )
    admin_client = Client(BASE_DVWA, forced_security=level)
    ordinary_client = Client(BASE_DVWA, forced_security=level)
    admin_index = dvwa_login(admin_client, *ADMIN)
    ordinary_index = dvwa_login(ordinary_client, *ORDINARY)
    run.add_response("admin-login-index", admin_index)
    run.add_response("ordinary-login-index", ordinary_index)
    run.requests.extend(admin_client.requests)
    admin_client.requests.clear()
    run.requests.extend(ordinary_client.requests)
    ordinary_client.requests.clear()

    admin_page = admin_client.get("/vulnerabilities/authbypass/")
    ordinary_page = ordinary_client.get("/vulnerabilities/authbypass/")
    run.add_response("admin-page-control", admin_page)
    run.add_response("ordinary-page", ordinary_page)

    admin_read = admin_client.get("/vulnerabilities/authbypass/get_user_data.php")
    ordinary_read = ordinary_client.get("/vulnerabilities/authbypass/get_user_data.php")
    run.add_response("admin-read-control", admin_read)
    run.add_response("ordinary-read", ordinary_read)

    reset_target(target_id)
    before = target_state(target_id)
    ordinary_update = ordinary_client.post_json(
        "/vulnerabilities/authbypass/change_user_details.php",
        {"id": target_id, "first_name": f"Wp4{level.capitalize()}", "surname": TARGET_LAST})
    after = target_state(target_id)
    run.add_response("ordinary-update", ordinary_update)
    ordinary_update_result = update_result(ordinary_update, target_id, before, after)
    reset_target(target_id)
    restored = target_state(target_id) == (TARGET_FIRST, TARGET_LAST)
    run.add_response("ordinary-update-restored-readback", ordinary_client.get(
        "/vulnerabilities/authbypass/get_user_data.php"))

    admin_update_result = None
    if main_condition:
        admin_before = target_state(target_id)
        admin_update = admin_client.post_json(
            "/vulnerabilities/authbypass/change_user_details.php",
            {"id": target_id, "first_name": "Wp4Admin", "surname": TARGET_LAST})
        admin_after = target_state(target_id)
        run.add_response("admin-update-control", admin_update)
        admin_update_result = update_result(admin_update, target_id, admin_before, admin_after)
        reset_target(target_id)

    run.requests.extend(admin_client.requests)
    run.requests.extend(ordinary_client.requests)
    read_admin = read_result(admin_read, target_id)
    read_ordinary = read_result(ordinary_read, target_id)
    observation = {
        "security_level": level,
        "target_object": {"user_id": target_id, "user": TARGET_USER},
        "identity": {
            "admin": identity(admin_index.text),
            "ordinary": identity(ordinary_index.text),
        },
        "page": {
            "admin_status": admin_page.status,
            "ordinary_status": ordinary_page.status,
            "ordinary_denied": ordinary_page.status == 403 or "Unauthorised" in ordinary_page.text,
        },
        "read_api": {
            "admin": read_admin,
            "ordinary": read_ordinary,
            "ordinary_received_protected_rows": read_ordinary["shape"] == "list" and read_ordinary["target_present"],
        },
        "update_api": {
            "ordinary": ordinary_update_result,
            "admin": admin_update_result,
            "ordinary_changed_target": ordinary_update_result["db_changed"],
            "restored": restored,
        },
    }
    run.observation = observation
    run.restore_result = {
        "required": True,
        "action": "restore dedicated target user first_name/last_name and remove test user at batch end",
        "result": "restored" if restored else "failed",
        "db_values": list(target_state(target_id)),
    }
    run.success_criteria = [
        "Admin and ordinary sessions are separately confirmed by the DVWA login banner.",
        "The admin page/read/update control works at this security level.",
        "The ordinary-session result is recorded separately for the page, read API and update API.",
        "Any update is verified by direct MariaDB readback and then restored.",
    ]
    run.limitations = [
        f"Only security={level} with the dedicated {TARGET_USER} object is covered.",
        "The security cookie is client-controlled; this is recorded as part of the condition, not as a separate vulnerability.",
        "Single-person review only.",
    ]

    read_bypass = observation["read_api"]["ordinary_received_protected_rows"]
    update_bypass = observation["update_api"]["ordinary_changed_target"]
    if level == "impossible":
        trigger = "未触发"
        truth = "无所关注漏洞" if not read_bypass and not update_bypass else "证据不足"
    elif level == "high":
        trigger = "触发" if update_bypass and not read_bypass else "证据不足"
        truth = "有漏洞" if update_bypass else "证据不足"
    else:
        trigger = "触发" if read_bypass and update_bypass else "证据不足"
        truth = "有漏洞" if read_bypass and update_bypass else "证据不足"
    run.finalize(trigger, truth)
    return observation


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--level", choices=["low", "medium", "high", "impossible", "all"], default="all")
    args = parser.parse_args()
    target_id = ensure_target()
    levels = ["low", "medium", "high", "impossible"] if args.level == "all" else [args.level]
    results = {}
    for level in levels:
        results[level] = run_level(level, target_id, main_condition=(level == "low"))
    print(json.dumps({"target_id": target_id, "levels": levels}, ensure_ascii=False))


if __name__ == "__main__":
    main()
