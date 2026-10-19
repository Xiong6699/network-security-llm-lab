"""Shared helpers for work package 4 local validation runs.

Standard library only. All HTTP traffic is restricted to the declared local
origins (127.0.0.1:9080 for DVWA, 127.0.0.1:9081 for SQLi-Labs).
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "verification" / "evidence"
VALIDATION = ROOT / "verification" / "validation_log"
BATCH_ID = "wp4-poc-01"
TZ = timezone(timedelta(hours=8))
BASE_DVWA = "http://127.0.0.1:9080"
BASE_SQLI = "http://127.0.0.1:9081"

SOURCE_COMMIT_DVWA = "068d974487a297c155c48722f9fcf7180a83adc4"
SOURCE_COMMIT_SQLI = "e96f21776372c8613a7e565106e62bc01a59355e"

# Per-sample adapted POC and adaptation level.  Shared harness files are used by
# several samples; the original model/trial draft is kept separately.
POC_META = {
    "SQLI-001": ("run_sqli.py", "B", "prompts/trial/pocs/sqli_001.py"),
    "SQLI-002": ("run_sqli.py", "C", None),
    "SQLI-003": ("run_sqli.py", "C", None),
    "SQLI-005": ("run_sqli005.py", "C", None),
    "XSS-001": ("run_xss.py", "B", "prompts/trial/pocs/xss_001.py"),
    "XSS-002": ("run_xss.py", "C", None),
    "XSS-003": ("run_xss.py", "C", None),
    "XSS-004": ("run_xss.py", "C", None),
    "XSS-005": ("run_xss.py", "C", None),
    "CMD-001": ("run_cmd.py", "B", "prompts/trial/pocs/cmd_001.py"),
    "CMD-002": ("run_cmd.py", "C", None),
    "CMD-003": ("run_cmd.py", "C", None),
    "CMD-004": ("run_cmd.py", "C", None),
    "AUTH-001": ("run_auth.py", "C", "prompts/trial/pocs/auth_001_read.py"),
}

SENSITIVE_KEYS = {
    "password", "passwd", "current_password", "re_password",
    "login_password", "pwd",
}
SENSITIVE_PATTERNS = [
    (re.compile(r"(PHPSESSID=)[^;,\s]+"), r"\1<redacted>"),
    (re.compile(r"(Auth=)[^;,\s]+"), r"\1<redacted>"),
]


def now_iso() -> str:
    return datetime.now(TZ).isoformat(timespec="seconds")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_text(text: str) -> str:
    for pattern, repl in SENSITIVE_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def redact_body(obj):
    if isinstance(obj, dict):
        return {
            key: ("<redacted>" if key.lower() in SENSITIVE_KEYS else redact_body(value))
            for key, value in obj.items()
        }
    if isinstance(obj, list):
        return [redact_body(item) for item in obj]
    return obj


def redact_headers(headers) -> dict:
    result = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in {"cookie", "set-cookie", "authorization"}:
            continue
        result[key] = value
    if headers.get("Set-Cookie"):
        result["X-WP4-Set-Cookie-Names"] = sorted(
            item.split("=", 1)[0].strip()
            for item in headers.get_all("Set-Cookie") or []
        )
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Response:
    def __init__(self, status, headers, body, url):
        self.status = status
        self.headers = headers
        self.body = body
        self.url = url
        try:
            self.text = body.decode("utf-8", errors="replace")
        except Exception:
            self.text = ""

    def header(self, name, default=None):
        return self.headers.get(name, default)


class Client:
    """Small cookie-aware client that never follows redirects."""

    def __init__(self, base: str, forced_security: str | None = None):
        self.base = base.rstrip("/") + "/"
        self.cookies: dict[str, str] = {}
        self.forced_security = forced_security
        self.requests: list[dict] = []
        self.opener = urllib.request.build_opener(NoRedirect())

    def _check_origin(self, url: str) -> None:
        original = urllib.parse.urlparse(self.base)
        target = urllib.parse.urlparse(url)
        if target.scheme != "http":
            raise ValueError("Only plain http is accepted for this lab")
        if target.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("Only local targets are accepted")
        if target.port != original.port:
            raise ValueError("Target port differs from the declared lab port")

    def _url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = urllib.parse.urljoin(self.base, path.lstrip("/"))
        self._check_origin(url)
        return url

    def _cookie_header(self) -> str:
        cookies = dict(self.cookies)
        if self.forced_security:
            cookies["security"] = self.forced_security
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    def _store_cookies(self, response_headers) -> None:
        for raw in response_headers.get_all("Set-Cookie") or []:
            pair = raw.split(";", 1)[0]
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            name, value = name.strip(), value.strip()
            if name == "security" and self.forced_security:
                continue
            self.cookies[name] = value

    def request(self, method: str, path: str, data=None, json_body=None,
                headers: dict | None = None, timeout: int = 20) -> Response:
        url = self._url(path)
        body_bytes = None
        body_for_log = None
        request_headers = {"User-Agent": "wp4-local-poc/1.0", "Accept": "*/*"}
        if json_body is not None:
            body_bytes = json.dumps(json_body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
            body_for_log = redact_body(json_body)
        elif data is not None:
            body_bytes = urllib.parse.urlencode(data).encode("utf-8")
            request_headers["Content-Type"] = "application/x-www-form-urlencoded"
            body_for_log = redact_body({k: str(v) for k, v in data.items()})
        if headers:
            request_headers.update(headers)
        cookie_header = self._cookie_header()
        if cookie_header:
            request_headers["Cookie"] = cookie_header
        req = urllib.request.Request(url, data=body_bytes, method=method,
                                     headers=request_headers)
        started = now_iso()
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                status, resp_headers = resp.status, resp.headers
                body = resp.read()
        except urllib.error.HTTPError as exc:
            status, resp_headers = exc.code, exc.headers
            body = exc.read()
        except urllib.error.URLError as exc:
            raise RuntimeError(f"request failed: {exc.reason}") from exc
        self._store_cookies(resp_headers)
        record = {
            "method": method,
            "url": url,
            "request_headers": {k: v for k, v in request_headers.items() if k.lower() != "cookie"},
            "cookie_names": sorted(self._cookie_header_names()),
            "body": body_for_log,
            "body_sha256": sha256_bytes(body_bytes) if body_bytes else None,
            "status": status,
            "response_headers": redact_headers(resp_headers),
            "response_bytes": len(body),
            "response_sha256": sha256_bytes(body),
            "started_at": started,
        }
        self.requests.append(record)
        return Response(status, resp_headers, body, url)

    def _cookie_header_names(self) -> list[str]:
        names = set(self.cookies)
        if self.forced_security:
            names.add("security")
        return names

    def get(self, path: str, **kwargs) -> Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, data, **kwargs) -> Response:
        return self.request("POST", path, data=data, **kwargs)

    def post_json(self, path: str, obj, **kwargs) -> Response:
        return self.request("POST", path, json_body=obj, **kwargs)

    def set_security(self, level: str) -> None:
        if level not in ("low", "medium", "high", "impossible"):
            raise ValueError("bad security level")
        self.forced_security = level


def extract_token(html: str) -> str | None:
    patterns = [
        r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-fA-F]+)['\"]",
        r"value=['\"]([0-9a-fA-F]+)['\"]\s+name=['\"]user_token['\"]",
    ]
    for pattern in patterns:
        match = re.search(pattern, html)
        if match:
            return match.group(1)
    return None


def extract_pre(text: str) -> str | None:
    match = re.search(r"<pre>(.*?)</pre>", text, re.S | re.I)
    return match.group(1) if match else None


def db_query(sql: str) -> list[list[str]]:
    """Independent readback through the local MariaDB client (root socket)."""
    proc = subprocess.run(
        ["mariadb", "-N", "-B", "--default-character-set=utf8mb4", "-e", sql],
        capture_output=True, text=True, timeout=30,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"db query failed: {proc.stderr.strip()}")
    rows = []
    for line in proc.stdout.splitlines():
        rows.append(line.split("\t"))
    return rows


def db_scalar(sql: str) -> str:
    rows = db_query(sql)
    if not rows or not rows[0]:
        return ""
    return rows[0][0]


def dvwa_login(client: Client, username: str, password: str) -> Response:
    page = client.get("/login.php")
    token = extract_token(page.text)
    if not token:
        raise RuntimeError("DVWA login token not found")
    client.post("/login.php", {
        "username": username,
        "password": password,
        "Login": "Login",
        "user_token": token,
    })
    return client.get("/index.php")


def dvwa_confirm_identity(client: Client, username: str) -> dict:
    page = client.get("/index.php")
    logged_in = "You have logged in as" in page.text
    return {
        "declared_user": username,
        "logged_in_banner": logged_in,
        "banner_contains_user": f"'{username}'" in page.text or f"&quot;{username}&quot;" in page.text,
    }


class Run:
    def __init__(self, run_id: str, sample_id: str, path_id: str,
                 condition_key: str, deployment_id: str, source_commit: str,
                 input_version: str = "v2", prompt_version: str | None = None):
        self.run_id = run_id
        self.sample_id = sample_id
        self.path_id = path_id
        self.condition_key = condition_key
        self.deployment_id = deployment_id
        self.source_commit = source_commit
        self.input_version = input_version
        self.prompt_version = prompt_version
        self.dir = EVIDENCE / run_id
        self.dir.mkdir(parents=True, exist_ok=True)
        self.started_at = now_iso()
        self.requests: list[dict] = []
        self.responses: list[str] = []
        self.observation: dict = {}
        self.artifacts: list[dict] = []
        self.restore_result: dict | None = None
        self.limitations: list[str] = []
        self.success_criteria: list[str] = []

    def attach(self, client: Client) -> None:
        self.requests.extend(client.requests)
        for idx, resp in enumerate(client.requests, 1):
            # Re-fetch body is not stored on the record; bodies are added by add_response.
            pass

    def add_response(self, label: str, response: Response) -> None:
        self.responses.append(
            f"===== {label} | HTTP {response.status} | {response.url} =====\n"
            + redact_text(response.text) + "\n"
        )

    def add_artifact(self, path: Path, description: str) -> None:
        self.artifacts.append({
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": sha256_file(path),
            "description": description,
        })

    def save_json(self, name: str, obj) -> Path:
        path = self.dir / name
        path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")
        self.add_artifact(path, name)
        return path

    def save_text(self, name: str, text: str) -> Path:
        path = self.dir / name
        path.write_text(text, encoding="utf-8")
        self.add_artifact(path, name)
        return path

    def finalize(self, trigger_result: str, ground_truth: str,
                 model_prediction: str | None = None,
                 failure_kind: str | None = None,
                 adaptation_level: str = "C",
                 adaptation_notes: str = "") -> dict:
        self.requests = [
            {**record, "body": redact_body(record.get("body"))}
            for record in self.requests
        ]
        self.save_json("request.redacted.json", self.requests)
        self.save_text("response.redacted.txt", "\n".join(self.responses))
        observation = {
            "run_id": self.run_id,
            "sample_id": self.sample_id,
            "path_id": self.path_id,
            "condition_key": self.condition_key,
            "observations": self.observation,
            "success_criteria": self.success_criteria,
            "limitations": self.limitations,
            "artifacts": self.artifacts,
        }
        self.save_json("observation.json", observation)
        if self.restore_result is None:
            self.restore_result = {"required": False, "result": "not_applicable"}
        self.save_json("restore_result.json", self.restore_result)
        script_name, level, original_source = POC_META.get(
            self.sample_id, (None, adaptation_level, None))
        script_path = Path(__file__).with_name(script_name) if script_name else Path(__file__)
        adapted_rel = str(script_path.relative_to(ROOT)).replace("\\", "/")
        adapted_hash = sha256_file(script_path)
        original_hash = sha256_file(ROOT / original_source) if original_source else None
        log = {
            "run_id": self.run_id,
            "batch_id": BATCH_ID,
            "case_id": self.run_id,
            "sample_id": self.sample_id,
            "path_id": self.path_id,
            "condition_key": self.condition_key,
            "input_version": self.input_version,
            "prompt_version": self.prompt_version,
            "source_commit": self.source_commit,
            "deployment_id": self.deployment_id,
            "started_at": self.started_at,
            "finished_at": now_iso(),
            "timezone": "+08:00",
            "executor": "wp4-agent",
            "reviewer": None,
            "review_status": "single_person_review_only",
            "poc": {
                "original_source": original_source,
                "original_sha256": original_hash,
                "adapted_source": adapted_rel,
                "adapted_sha256": adapted_hash,
                "adaptation_level": level,
                "adaptation_notes": adaptation_notes,
            },
            "requests": len(self.requests),
            "trigger_result": trigger_result,
            "ground_truth": ground_truth,
            "model_prediction": model_prediction,
            "failure_kind": failure_kind,
            "success_criteria": self.success_criteria,
            "limitations": self.limitations,
            "artifacts": self.artifacts,
        }
        VALIDATION.mkdir(parents=True, exist_ok=True)
        (VALIDATION / f"{self.run_id}.json").write_text(
            json.dumps(log, ensure_ascii=False, indent=2), encoding="utf-8")
        summary = {
            "run_id": self.run_id,
            "sample_id": self.sample_id,
            "path_id": self.path_id,
            "trigger_result": trigger_result,
            "ground_truth": ground_truth,
            "observation": self.observation,
        }
        print(json.dumps(summary, ensure_ascii=False, indent=2))
        return log
