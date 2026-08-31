#!/usr/bin/env python3
"""ffn_uiaudit.py -- audit the FFN WebUI for dead ends and vendor-specific text.

ffn_jscheck.py answers "does this parse". This answers the next two questions,
which are the ones that actually bite users:

  * Does every menu item go somewhere?  A nav entry with no dispatch target, or
    a dispatch target that names a function nobody defined, is a menu item that
    does nothing when clicked -- and it looks identical to a working one.
  * Does every button work?  An onclick naming a function that does not exist
    throws only when a user presses it, so it survives every page-load test.
  * Is it presenting someone else's product?  FFN is its own firewall. Vendor
    product names belong in reverse-engineering notes, not in the interface a
    user of FFN is looking at -- both because it is misleading and because those
    are other people's trademarks.

    ffn_uiaudit.py /opt/ffn-ngfw-v2/static/index.html
    ffn_uiaudit.py --selftest
"""
import re
import sys

# Product names that must not appear in FFN's own interface. FFN reimplements
# behaviour and documents the originals elsewhere; presenting their names to a
# user implies a relationship that does not exist.
VENDOR_TERMS = [
    "Palo Alto", "PAN-OS", "PANOS", "Panorama", "WildFire", "App-ID", "AppID",
    "GlobalProtect", "AutoFocus", "Cortex", "MineMeld", "Expedition",
    "Prisma", "WF-500", "Traps", "Aperture", "Magnifier",
]

# Terms that are legitimate: generic industry vocabulary FFN uses on purpose.
ALLOWED_NEAR = ["app-id-like", "panos-compatible"]

# Places where naming the vendor is CORRECT rather than branding:
#   * describing whose signature we cannot verify (a security statement),
#   * describing what the operator should point the firmware importer at,
#   * the interface-alias feature, whose entire job is mapping PAN-OS slot
#     names onto Linux interfaces -- calling that anything else would obscure
#     what it does.
# Anything not listed here is treated as branding and flagged, so new vendor
# naming still gets caught.
LEGITIMATE = [
    "signed them",
    "sysroot",
    "slot maps to exactly one",
    "<label>PAN-OS name</label>",
    "PAN-OS slot",
]


def js_of(html):
    out = []
    for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html,
                         re.S | re.I):
        out.append((m.start(1), m.group(1)))
    return out


def line_of(text, idx):
    return text.count("\n", 0, idx) + 1



def _comment_spans(text):
    """Character ranges covered by comments, so a match inside one can be told
    apart from visible copy. Handles multi-line /* */ and <!-- --> blocks, which
    a per-line check misses -- the banner comments in this file span many lines,
    and only the FIRST line starts with the marker."""
    spans = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            spans.append((i, j))
            i = j
        elif text.startswith("<!--", i):
            j = text.find("-->", i + 4)
            j = n if j < 0 else j + 3
            spans.append((i, j))
            i = j
        elif text.startswith("//", i):
            j = text.find(chr(10), i)
            j = n if j < 0 else j
            spans.append((i, j))
            i = j
        else:
            i += 1
    return spans


def _in_spans(idx, spans):
    for a, b in spans:
        if a <= idx < b:
            return True
        if a > idx:
            break
    return False


def _is_identifier_context(text, start, end):
    """True when the match is part of a longer identifier or a URL path --
    loadWildFire, renderWildFire, /api/wildfire/status. Those are code, not copy,
    and renaming them is a refactor with no user-visible effect."""
    before = text[start - 1] if start > 0 else " "
    after = text[end] if end < len(text) else " "
    if before.isalnum() or before in "_$":
        return True
    if after.isalnum() or after in "_$":
        return True
    # inside a quoted path such as '/api/wildfire/status'
    lo = max(0, start - 40)
    seg = text[lo:end + 20]
    if "/api/" in seg or "/static/" in seg:
        return True
    # a quoted all-lowercase token is an internal id key ('wildfire'), not copy
    quoted = text[start - 1:end + 1]
    if len(quoted) >= 2 and quoted[0] in "'\"" and quoted[-1] in "'\"":
        if text[start:end].islower():
            return True
    return False

def audit(path):
    html = open(path, encoding="utf-8", errors="replace").read()
    scripts = js_of(html)
    js = "\n".join(s for _o, s in scripts)
    problems = []

    # ---- what functions exist? -------------------------------------------
    defined = set(re.findall(r"(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(", js))
    defined |= set(re.findall(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*"
                              r"(?:async\s*)?(?:function|\()", js))
    # window.foo = ... assignments
    defined |= set(re.findall(r"window\.([A-Za-z_$][\w$]*)\s*=", js))

    # ---- nav entries and dispatch targets --------------------------------
    nav_ids = set(re.findall(r"\{\s*id:\s*'([^']+)'\s*,\s*label:", js))
    dispatch = dict(re.findall(r"'([^']+)'\s*:\s*([A-Za-z_$][\w$]*)\s*,", js))

    for nid in sorted(nav_ids):
        if nid not in dispatch:
            problems.append(("dead-menu", 0,
                             "menu item '%s' has no render target -- clicking it "
                             "does nothing" % nid))
    for key, fn in sorted(dispatch.items()):
        if fn not in defined:
            problems.append(("missing-render", 0,
                             "dispatch '%s' -> %s(), which is never defined" % (key, fn)))

    # ---- inline handlers naming functions that do not exist --------------
    handlers = set()
    for m in re.finditer(r'on(?:click|change|input|submit|keyup)\s*=\s*"([^"]+)"', html):
        body = m.group(1)
        # A call preceded by a dot is a METHOD on some object
        # (classList.add, document.getElementById) -- not a global function, so
        # looking it up in the set of declared functions is meaningless.
        for cm in re.finditer(r"(\.?)([A-Za-z_$][\w$]*)\s*\(", body):
            if cm.group(1) == ".":
                continue
            handlers.add(cm.group(2))
    builtin = {"alert", "confirm", "prompt", "event", "return", "if", "this",
               "parseInt", "parseFloat", "String", "Number", "JSON", "Object",
               "Array", "Math", "Date", "encodeURIComponent", "decodeURIComponent",
               "setTimeout", "setInterval", "console", "window", "document"}
    for h in sorted(handlers - builtin):
        if h not in defined:
            problems.append(("dead-handler", 0,
                             "a control calls %s(), which is never defined -- it "
                             "throws only when pressed" % h))

    # ---- vendor product names ------------------------------------------
    # Only VISIBLE copy is a problem. A source comment saying "PAN-OS style" is
    # useful to a developer and invisible to a user; a menu item called
    # "WildFire" presents someone else's product as an FFN feature. Config paths
    # are also left alone: mirroring PAN-OS's schema is deliberate interop, not
    # branding.
    spans = _comment_spans(html)

    for term in VENDOR_TERMS:
        for m in re.finditer(re.escape(term), html, re.I):
            ln_no = line_of(html, m.start())
            ctx = html[max(0, m.start() - 60):m.start() + 60].replace("\n", " ")
            if any(a in ctx.lower() for a in ALLOWED_NEAR):
                continue
            if any(g.lower() in ctx.lower() for g in LEGITIMATE):
                problems.append(("vendor-legitimate", ln_no,
                                 "%r naming the vendor accurately (kept on purpose)"
                                 % term))
                continue
            if _in_spans(m.start(), spans):
                problems.append(("vendor-comment", ln_no,
                                 "%r in a source comment (dev-facing)" % term))
                continue
            if _is_identifier_context(html, m.start(), m.end()):
                problems.append(("vendor-identifier", ln_no,
                                 "%r in a code identifier or API path (not copy)" % term))
                continue
            # config.device.setup.wildfire mirrors PAN-OS's schema on purpose
            around = html[max(0, m.start() - 30):m.end() + 5]
            if re.search(r"[\w.]+\.%s" % re.escape(term.lower()), around.lower()):
                problems.append(("vendor-configpath", ln_no,
                                 "%r inside a config path (interop -- leave it)" % term))
                continue
            problems.append(("vendor-visible", ln_no,
                             "%r in VISIBLE text: ...%s..." % (term, ctx.strip()[:90])))

    return problems, {
        "defined": len(defined), "nav": len(nav_ids), "dispatch": len(dispatch),
        "handlers": len(handlers),
    }


def report(path):
    problems, stats = audit(path)
    print("%s" % path)
    print("  %d functions, %d menu items, %d dispatch entries, %d handlers"
          % (stats["defined"], stats["nav"], stats["dispatch"], stats["handlers"]))
    by = {}
    for kind, line, msg in problems:
        by.setdefault(kind, []).append((line, msg))
    order = ["missing-render", "dead-menu", "dead-handler", "vendor-visible",
             "vendor-identifier", "vendor-configpath", "vendor-legitimate",
             "vendor-comment"]
    for kind in order:
        rows = by.get(kind) or []
        if not rows:
            continue
        print("\n  %s (%d)" % (kind, len(rows)))
        seen = set()
        for line, msg in rows:
            key = msg[:70]
            if key in seen:
                continue
            seen.add(key)
            print("    %s%s" % (("line %-6d " % line) if line else " " * 12, msg))
        if len(rows) > len(seen):
            print("    ... and %d more occurrences" % (len(rows) - len(seen)))
    hard = [x for x in problems
            if x[0] in ("missing-render", "dead-menu", "dead-handler",
                        "vendor-visible")]
    print("\n  %d actionable, %d informational" % (len(hard), len(problems) - len(hard)))
    return 1 if hard else 0


def selftest():
    import tempfile, os, io, contextlib
    fails = []

    def chk(c, m):
        print(("  ok   " if c else "  FAIL ") + m)
        if not c:
            fails.append(m)

    d = tempfile.mkdtemp()

    def write(js, extra_html=""):
        p = os.path.join(d, "t.html")
        open(p, "w", encoding="utf-8").write(
            "<html>%s<script>\n%s\n</script></html>" % (extra_html, js))
        return p

    clean = write("function renderA(c){}\nconst NAV={x:[{id:'a',label:'A'}]};\n"
                  "const R={'a': renderA,};")
    pr, _ = audit(clean)
    chk(not pr, "a clean UI reports nothing")

    dead = write("const NAV={x:[{id:'a',label:'A'},{id:'b',label:'B'}]};\n"
                 "function renderA(c){}\nconst R={'a': renderA,};")
    pr, _ = audit(dead)
    chk(any(k == "dead-menu" for k, _l, _m in pr), "a menu item with no target is caught")

    miss = write("const NAV={x:[{id:'a',label:'A'}]};\nconst R={'a': renderMissing,};")
    pr, _ = audit(miss)
    chk(any(k == "missing-render" for k, _l, _m in pr),
        "a dispatch to an undefined function is caught")

    hand = write("function renderA(c){}", '<button onclick="doesNotExist()">x</button>')
    pr, _ = audit(hand)
    chk(any(k == "dead-handler" for k, _l, _m in pr),
        "a button calling an undefined function is caught")

    hand2 = write("function reallyExists(){}",
                  '<button onclick="reallyExists()">x</button>')
    pr, _ = audit(hand2)
    chk(not any(k == "dead-handler" for k, _l, _m in pr),
        "a button calling a real function is not flagged")

    vend = write("function a(){}", "<h2>WildFire Analysis</h2>")
    pr, _ = audit(vend)
    chk(any(k == "vendor-visible" for k, _l, _m in pr),
        "a vendor product name in visible text is caught")

    chk(not any(k == "dead-handler" for k, _l, _m in audit(
        write("function a(){}", '<button onclick="alert(1)">x</button>'))[0]),
        "browser builtins are not mistaken for missing functions")

    import shutil
    shutil.rmtree(d, ignore_errors=True)
    print("\n==== ffn_uiaudit selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = [x for x in sys.argv[1:]]
    if not a or a[0] == "--selftest":
        sys.exit(selftest())
    rc = 0
    for f in a:
        rc |= report(f)
    sys.exit(rc)
