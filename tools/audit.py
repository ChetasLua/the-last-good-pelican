# Python 3 | tools/audit.py | standard library | inspect the standalone film's source
"""Usage: python3 tools/audit.py [pelican.html]. Exit nonzero on an audit finding."""
import hashlib
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


class FilmPage(HTMLParser):
    def __init__(self):
        super().__init__()
        self.executable, self.css, self.findings = [], [], []
        self.section = None
        self.canvas_count = 0
        self.csp = ""

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in {"img", "image", "picture", "svg", "video", "audio", "source", "track",
                   "embed", "object", "iframe", "frame", "link", "base"}:
            self.findings.append("External/media element: <" + tag + ">")
        for key, _ in attrs:
            if key in {"src", "srcset", "href", "xlink:href", "poster", "action", "srcdoc", "data-src"}:
                self.findings.append("Resource attribute: " + tag + "[" + key + "]")
        if tag == "meta" and a.get("http-equiv", "").lower() == "content-security-policy":
            self.csp = a.get("content", "")
        if tag == "canvas":
            self.canvas_count += 1
        if tag == "script":
            self.section = None if a.get("type") == "text/plain" else self.executable
        elif tag == "style":
            self.section = self.css

    def handle_endtag(self, tag):
        if tag in {"script", "style"}:
            self.section = None

    def handle_data(self, data):
        if self.section is not None:
            self.section.append(data)


def audit(file):
    raw = file.read_bytes()
    source = raw.decode("utf-8", errors="strict")
    page = FilmPage()
    page.feed(source)
    page.close()
    js = "\n".join(page.executable)
    problems = page.findings.copy()
    if page.canvas_count != 1:
        problems.append("Expected a single presentation canvas.")
    if len(page.executable) != 2:
        problems.append("Expected two inline programs: film and projection notes.")
    contexts = set(re.findall(r"""getContext\(\s*['"]([^'"]+)""", js))
    if contexts != {"2d"}:
        problems.append("Unexpected drawing context(s): " + repr(contexts))
    rules = {s.split()[0].lower(): s.split()[1:] for k in page.csp.split(";") if (s := k.strip())}
    for directive in ("default-src", "connect-src", "img-src", "media-src", "font-src"):
        if rules.get(directive) != ["'none'"]:
            problems.append("CSP must forbid " + directive)
    checks = [
        ("a URL or inline media payload", source,
         r"""\b(?:https?|wss?|ftp)://|\bdata:(?:audio|video|image|font|application)/|;base64,|[A-Za-z0-9+/]{170,}={0,2}"""),
        ("binary control characters", source, r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"),
        ("CSS resource import", "\n".join(page.css), r"@import\b|@font-face\b|\burl\s*\("),
        ("network, dependency or binary-loading API", js,
         r"\b(?:fetch|XMLHttpRequest|WebSocket|WebTransport|EventSource|sendBeacon|importScripts|require|atob|btoa|decodeAudioData|createMediaElementSource)\s*\(|\bimport\s*(?:\(|\{)|\bWebAssembly\b"),
        ("3D or GPU rendering API", js, r"\b(?:WebGL2?|GPUCanvasContext|THREE\.Scene|navigator\.gpu)\b"),
        ("private local path or common secret signature", source,
         r"/(?:Users|home|private/tmp|tmp)/|[a-z]:\\Users\\|github_pat_[\w]{24,}|gh[pousr]_[A-Za-z0-9]{25,}|sk-(?:proj-|live_)?[\w-]{22,}|AKIA[0-9A-Z]{16}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    ]
    for label, body, pattern in checks:
        if re.search(pattern, body, re.IGNORECASE):
            problems.append("Found " + label)
    for marker in ("window.render", "createOscillator", "createBufferSource", "createGain", "createBiquadFilter"):
        if marker not in js:
            problems.append("Missing expected film mechanism: " + marker)
    print(f"{file.name}: {len(raw):,} bytes UTF-8; SHA-256 {hashlib.sha256(raw).hexdigest()}")
    if problems:
        for problem in problems:
            print("FAIL:", problem)
        return 1
    print("PASS: Canvas 2D, live Web Audio, inline source only; no asset URLs or embedded media found.")
    return 0


if __name__ == "__main__":
    target = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).resolve().parents[1] / "pelican.html"
    if len(sys.argv) > 2:
        raise SystemExit("Usage: python3 tools/audit.py [pelican.html]")
    try:
        raise SystemExit(audit(target))
    except (OSError, ValueError) as exc:
        print("FAIL:", exc, file=sys.stderr)
        raise SystemExit(1)
