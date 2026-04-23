from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib import error, request


class ProxyHandler(BaseHTTPRequestHandler):
    upstream = "http://192.168.1.10:5000"

    def do_GET(self) -> None:
        target = self.upstream.rstrip("/") + self.path
        try:
            with request.urlopen(target, timeout=15) as resp:
                body = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
        except error.HTTPError as exc:
            body = exc.read()
            self.send_response(exc.code)
            self.send_header("Content-Type", exc.headers.get("Content-Type", "application/json"))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        except Exception as exc:
            body = f'{{"error":"historian proxy failed","detail":"{exc}"}}'.encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    parser = argparse.ArgumentParser(description="Expose the historian API to Docker-hosted Grafana.")
    parser.add_argument("--listen", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5001)
    parser.add_argument("--upstream", default="http://192.168.1.10:5000")
    args = parser.parse_args()

    ProxyHandler.upstream = args.upstream
    server = ThreadingHTTPServer((args.listen, args.port), ProxyHandler)
    print(f"historian proxy listening on {args.listen}:{args.port} -> {args.upstream}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
