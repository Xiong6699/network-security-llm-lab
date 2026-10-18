"""Read-only local role comparison draft for AUTH-001's data interface."""
import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def local_url(base, path):
    url = urljoin(base.rstrip("/") + "/", path)
    original, target = urlparse(base), urlparse(url)
    if target.scheme not in ("http", "https") or target.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Only a local teaching target is accepted")
    if target.username or target.password or (target.scheme, target.netloc) != (original.scheme, original.netloc):
        raise ValueError("Target must remain on the declared local origin")
    return url


def cookie_for(path, security):
    value = path.read_text(encoding="utf-8").strip()
    if "\r" in value or "\n" in value:
        raise ValueError("Cookie file must contain one header value")
    parts = [p.strip() for p in value.split(";") if p.strip() and not p.strip().startswith("security=")]
    return "; ".join(parts + ["security=" + security])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--path", required=True, help="Deployed get_user_data.php path, not the page URL")
    parser.add_argument("--admin-cookie-file", type=Path, required=True)
    parser.add_argument("--low-cookie-file", type=Path, required=True)
    parser.add_argument("--security", choices=("low", "medium", "high", "impossible"), required=True)
    args = parser.parse_args()
    url = local_url(args.base_url, args.path)
    opener = build_opener(NoRedirect())
    observations = []
    for role, path in (("admin", args.admin_cookie_file), ("ordinary", args.low_cookie_file)):
        request = Request(url, headers={"Cookie": cookie_for(path, args.security)})
        try:
            with opener.open(request, timeout=10) as response:
                status, body = response.status, response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", errors="replace")
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            data = None
        users = data if isinstance(data, list) and all(isinstance(u, dict) and {"user_id", "first_name", "surname"} <= u.keys() for u in data) else None
        observations.append({"declared_role": role, "security": args.security, "status": status, "protected_row_count": len(users) if users is not None else None, "error": data.get("error") if isinstance(data, dict) else None})
    print(json.dumps({"observations": observations, "verdict": "Independently verify both session identities and protected data access. HTTP 200 alone is insufficient. This script does not test the update API."}, indent=2))


if __name__ == "__main__":
    main()
