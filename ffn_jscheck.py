#!/usr/bin/env python3
"""ffn_jscheck.py -- structural sanity check for the FFN WebUI's inline JS.

The WebUI is one large HTML file with a single inline <script>. There is no JS
engine on the appliance, so a syntax error introduced by an automated edit is
invisible until a browser refuses to run the whole script and the entire UI goes
blank. Two such bugs have already shipped this way:

  * `async async function ...`  -- an insertion anchored on a substring that
    began inside another declaration, so the inserted block split it.
  * a function silently losing its `async` keyword, while still using `await`.

Neither is caught by brace counting alone, and neither shows up in the served
HTML (the markers are all present -- the text is there, it just cannot parse).

This checks the things that actually go wrong when a script is edited by anchor
substitution:

  1. brace/paren/bracket balance across the whole script (catches truncation and
     insertions that swallow a closing brace),
  2. every `function name(...)` declaration sits at depth 0 -- i.e. no function
     was accidentally inserted INSIDE another one,
  3. no doubled keywords (`async async`, `function function`, ...),
  4. any function body containing `await` is declared `async`.

It tokenizes well enough to skip comments, quoted strings and template literals
(including nested `${...}`), which is where naive brace counting goes wrong.

    ffn_jscheck.py /opt/ffn-ngfw-v2/static/index.html
    ffn_jscheck.py --selftest
"""
import re
import sys

KEYWORDS_BEFORE_REGEX = {"return", "typeof", "instanceof", "in", "of", "new",
                         "delete", "void", "throw", "case", "do", "else", "yield"}


def extract_scripts(html):
    """Return [(offset_in_html, script_text), ...] for each inline <script>."""
    out = []
    for m in re.finditer(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", html,
                         re.S | re.I):
        out.append((m.start(1), m.group(1)))
    return out


def scan(src):
    """Walk the source, tracking nesting depth outside strings/comments.

    Returns (events, errors) where events is a list of
    (kind, index, line, depth, text) and errors is a list of (line, message).
    """
    events, errors = [], []
    depth = 0
    stack = []          # open brackets, for mismatch reporting
    tmpl = []           # template-literal nesting: depth at which each ` opened
    i, n = 0, len(src)
    line = 1
    prev_sig = ""       # last significant (non-space) char, for regex detection
    prev_word = ""
    # Enclosing-function tracking. An `await` belongs to the innermost function
    # whose body brace is still open -- NOT merely to the nearest preceding
    # `function` keyword, which is usually an inner callback.
    func_stack = []     # (name, is_async, body_depth)
    pending = None      # (name, is_async) waiting for its opening '{'

    while i < n:
        ch = src[i]
        if ch == "\n":
            line += 1
            i += 1
            continue

        # --- template-literal TEXT ---
        # Must come first: inside `...` text an apostrophe ("box's") is a
        # literal character, not a string opener, and // is not a comment.
        if tmpl and not tmpl_in_expr(tmpl, depth):
            if ch == "\\":
                i += 2
                continue
            if ch == "`":
                tmpl.pop()
                i += 1
                prev_sig, prev_word = "`", ""
                continue
            if ch == "$" and i + 1 < n and src[i + 1] == "{":
                depth += 1
                stack.append(("{", line))
                i += 2
                continue
            i += 1
            continue

        # --- comments ---
        if ch == "/" and i + 1 < n:
            nxt = src[i + 1]
            if nxt == "/":
                j = src.find("\n", i)
                i = n if j < 0 else j
                continue
            if nxt == "*":
                j = src.find("*/", i + 2)
                if j < 0:
                    errors.append((line, "unterminated /* block comment"))
                    break
                line += src.count("\n", i, j)
                i = j + 2
                continue
            # regex literal?
            if prev_sig in "(,=:[!&|?{};+-*%~^<>" or prev_word in KEYWORDS_BEFORE_REGEX:
                j, ok, incls = i + 1, False, False
                while j < n:
                    c = src[j]
                    if c == "\\":
                        j += 2
                        continue
                    if c == "\n":
                        break
                    if c == "[":
                        incls = True
                    elif c == "]":
                        incls = False
                    elif c == "/" and not incls:
                        ok = True
                        break
                    j += 1
                if ok:
                    i = j + 1
                    prev_sig = "/"
                    prev_word = ""
                    continue

        # --- quoted strings ---
        if ch in "'\"":
            q, j = ch, i + 1
            while j < n:
                if src[j] == "\\":
                    j += 2
                    continue
                if src[j] == q:
                    break
                if src[j] == "\n":
                    errors.append((line, "unterminated %s string" % q))
                    break
                j += 1
            i = j + 1
            prev_sig, prev_word = q, ""
            continue

        # --- template literal opens (we are in code, not template text) ---
        if ch == "`":
            tmpl.append(depth)
            i += 1
            prev_sig, prev_word = "`", ""
            continue

        # --- arrow functions: `=>` immediately followed by a block body ---
        if ch == "=" and i + 1 < n and src[i + 1] == ">":
            j = i + 2
            while j < n and src[j].isspace():
                j += 1
            if j < n and src[j] == "{":
                win = src[max(0, i - 200):i]
                is_async = bool(re.search(
                    r"\basync\s*(\([^()]*\)|[A-Za-z_$][\w$]*)\s*$", win))
                pending = ("<arrow>", is_async)
            i += 2
            prev_sig, prev_word = ">", ""
            continue

        # --- brackets ---
        if ch in "{[(":
            depth += 1
            stack.append((ch, line))
            if ch == "{" and pending:
                func_stack.append((pending[0], pending[1], depth))
                pending = None
            i += 1
            prev_sig, prev_word = ch, ""
            continue
        if ch in "}])":
            want = {"}": "{", "]": "[", ")": "("}[ch]
            if not stack:
                errors.append((line, "unmatched closing '%s'" % ch))
            else:
                op, oline = stack.pop()
                if op != want:
                    errors.append((line, "'%s' closes '%s' opened on line %d"
                                   % (ch, op, oline)))
            depth = max(0, depth - 1)
            while func_stack and func_stack[-1][2] > depth:
                func_stack.pop()
            i += 1
            prev_sig, prev_word = ch, ""
            continue

        # --- words: function declarations & doubled keywords ---
        if ch.isalpha() or ch in "_$":
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            word = src[i:j]
            if word == "function":
                m = re.match(r"\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(", src[j:])
                name = (m.group(1) if m and m.group(1) else "<anonymous>")
                events.append(("function", i, line, depth, name))
                pending = (name, prev_word == "async")
            elif word == "await":
                owner = func_stack[-1] if func_stack else None
                if owner and not owner[1]:
                    errors.append((line, "'await' inside function '%s' "
                                   "(opened at brace depth %d) which is not "
                                   "declared async" % (owner[0], owner[2])))
            if word == prev_word and word in ("async", "function", "const",
                                              "let", "var", "return"):
                errors.append((line, "doubled keyword '%s %s'" % (word, word)))
            i = j
            prev_sig, prev_word = word[-1], word
            continue

        if not ch.isspace():
            prev_sig, prev_word = ch, ""
        i += 1

    if stack:
        for op, oline in stack[-5:]:
            errors.append((oline, "unclosed '%s'" % op))
    return events, errors, depth


def tmpl_in_expr(tmpl, depth):
    """True when we are inside a ${...} expression rather than template text."""
    return bool(tmpl) and depth > tmpl[-1]


def check(path, verbose=False):
    src = open(path, encoding="utf-8", errors="replace").read()
    scripts = extract_scripts(src) if "<script" in src.lower() else [(0, src)]
    if not scripts:
        print("no inline <script> found in %s" % path)
        return 1

    total_err = 0
    for idx, (off, text) in enumerate(scripts):
        base = src.count("\n", 0, off) + 1
        events, errors, depth = scan(text)
        if depth != 0:
            errors.append((0, "script ends at brace depth %d (expected 0)" % depth))

        # functions must be declared at top level, not inside another function
        nested = [e for e in events if e[0] == "function" and e[3] > 0]
        # a function at depth>0 is legal (callbacks, methods) -- only flag ones
        # that look like top-level declarations: `function name(` at line start
        for kind, i2, ln, d, name in nested:
            ls = text.rfind("\n", 0, i2) + 1
            prefix = text[ls:i2].strip()
            if name != "<anonymous>" and prefix in ("", "async"):
                errors.append((base + ln - 1,
                               "declaration 'function %s' is nested at depth %d "
                               "-- an edit may have landed inside another function"
                               % (name, d)))

        # `await` in a non-async function is reported by scan(), which knows the
        # real enclosing scope.
        funcs = [e for e in events if e[0] == "function"]

        if verbose:
            print("script #%d: %d chars, %d function declarations"
                  % (idx, len(text), len(funcs)))
        for ln, msg in errors:
            print("  %s:%s: %s" % (path, base + ln - 1 if ln else "?", msg))
        total_err += len(errors)

    print("%s: %d problem(s)" % (path, total_err))
    return 1 if total_err else 0


def selftest():
    import tempfile, os
    fails = []

    def case(name, js, should_fail):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "t.html")
        open(p, "w").write("<html><script>\n%s\n</script></html>" % js)
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = check(p)
        bad = (rc != 0) != should_fail
        print(("  FAIL " if bad else "  ok   ") + name +
              ("" if not bad else "  -> " + buf.getvalue().strip().replace("\n", " | ")))
        if bad:
            fails.append(name)

    case("clean script", "async function a(){ await b(); }\nfunction b(){ return 1; }", False)
    case("doubled async", "async async function a(){ await b(); }", True)
    case("await without async", "function a(){ await b(); }", True)
    case("unbalanced brace", "function a(){ if(1){ return 2; }", True)
    case("template literal with braces",
         "function a(){ const s=`x${ {k:1}.k }y`; return s; }", False)
    case("template with unbalanced-looking text",
         "function a(){ return `a } b { c`; }", False)
    case("string with braces", "function a(){ return '}{'; }", False)
    # regression: an apostrophe inside template TEXT is a literal character,
    # not a string opener -- this is what desynchronized the first version.
    case("apostrophe in template text",
         "function a(){ return `the box's on-board NPU`; }\n"
         "function b(){ return 1; }", False)
    case("// inside template text",
         "function a(){ return `see http://x/y`; }\nfunction b(){ return 1; }", False)
    case("quote in nested template expr",
         "function a(){ return `x${ b('y') }z`; }\nfunction c(){ return 1; }", False)
    case("apostrophe in template, real error after",
         "function a(){ return `box's`; }\nasync async function b(){}", True)
    case("regex with braces", "function a(){ return /[{}]/.test('x'); }", False)
    case("comment with braces", "function a(){ /* } { */ return 1; }", False)
    case("nested top-level decl",
         "function a(){\nfunction b(){ return 1; }\n", True)
    case("legal callback function",
         "function a(){ setTimeout(function(){ return 1; }, 5); }", False)
    case("legal nested arrow", "const f = () => { const g = () => 2; return g(); };", False)

    print("\n==== ffn_jscheck selftest: %d failed ====" % len(fails))
    return 1 if fails else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if not a or a[0] == "--selftest":
        sys.exit(selftest())
    v = "-v" in a
    files = [x for x in a if not x.startswith("-")]
    rc = 0
    for f in files:
        rc |= check(f, verbose=v)
    sys.exit(rc)
