#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_fpga_emu.py -- Software FPGA emulator of the Lynceus DPI engine.

Implements REWORK_CONTRACT.md §7: a pure-software emulation of the on-card
Lynceus deep-packet-inspection engine (multi-pattern Aho-Corasick + a regex
DFA) behind exactly the shape the engine registry's FPGA-offload path expects.
This makes the `dpi_l7` / `dpi_regex` "offload" functional *now* (when no card
is present), and hardware-swappable later: the DFA is kept as an explicit
state/transition table so it maps 1:1 onto gateware.

Two engines, one façade:

    +--------------------------------------------------------------+
    | FpgaEmulator                                                 |
    |                                                              |
    |   load_ac(patterns)   -> Aho-Corasick automaton  (engine=ac) |
    |   load_dfa(regexes)   -> Thompson-NFA -> subset  (engine=dfa)|
    |                          construction -> DFA byte table      |
    |                          (fallback: Python `re`)             |
    |                                                              |
    |   scan(data) -> [EmuMatch{tag, sid, offset, engine, which}]  |
    |                 + per-engine counters (packets/matches/drops)|
    |   emu_status(name) -> {enabled,packets,matches,drops,        |
    |                        mode:"emulated"}   (get_engine_status)|
    +--------------------------------------------------------------+

Design notes for the eventual gateware port:
  * The Aho-Corasick automaton is the reference for the DPI content-match BRAM
    (goto/fail/output tables).
  * The regex DFA is built as an *explicit* transition table -- a dense
    `trans[state][byte] -> next_state` array over the full 0..255 byte alphabet
    plus an `accept` state set. That is precisely the artefact a gateware DFA
    block consumes (one BRAM-addressed transition table + an accept bitmap).
    A production one-pass streaming scan simply prepends a `.*` self-loop on the
    start state; here we run the anchored table at each start position so match
    *start offsets* are exact and verifiable.
  * Regexes the first-cut Thompson/subset compiler cannot express (bounded
    repetition `{m,n}`, anchors, groups `(?...)`, backreferences, `\b`, ...)
    fall back to Python `re`; `dfa_paths()` records which path each pattern
    took so the hardware bring-up knows what still needs a host slow-path.

CLI:
    ffn_fpga_emu.py selftest
"""

import re
import sys
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Reuse the repo's Aho-Corasick; fall back to a compact equivalent if the
# import is awkward (module run from another cwd, path issues, offline box).
# ---------------------------------------------------------------------------
try:
    import os as _os
    _here = _os.path.dirname(_os.path.abspath(__file__))
    if _here and _here not in sys.path:
        sys.path.insert(0, _here)
    from inline_payload_det import AhoCorasick  # noqa: E402
    _AC_SOURCE = "inline_payload_det"
except Exception:  # pragma: no cover - exercised only when the sibling import fails
    _AC_SOURCE = "builtin"

    class AhoCorasick:  # type: ignore
        """Compact Aho-Corasick over the byte alphabet (fallback reimpl).

        Same public API as inline_payload_det.AhoCorasick:
          .add(pattern: bytes, tag) / .build() / .iter_matches(data) ->
          yields (end_offset, tag) for each pattern occurrence.
        """

        __slots__ = ("_goto", "_fail", "_out", "_built", "_npat")

        def __init__(self):
            self._goto: List[Dict[int, int]] = [{}]
            self._fail: List[int] = [0]
            self._out: List[list] = [[]]
            self._built = False
            self._npat = 0

        def add(self, pattern: bytes, tag) -> None:
            if self._built:
                raise RuntimeError("cannot add patterns after build()")
            if not pattern:
                raise ValueError("empty pattern")
            node = 0
            for b in pattern:
                nxt = self._goto[node].get(b)
                if nxt is None:
                    nxt = len(self._goto)
                    self._goto.append({})
                    self._fail.append(0)
                    self._out.append([])
                    self._goto[node][b] = nxt
                node = nxt
            self._out[node].append(tag)
            self._npat += 1

        def build(self) -> "AhoCorasick":
            q = deque()
            for b, nxt in self._goto[0].items():
                self._fail[nxt] = 0
                q.append(nxt)
            while q:
                cur = q.popleft()
                for b, nxt in self._goto[cur].items():
                    q.append(nxt)
                    f = self._fail[cur]
                    while f and b not in self._goto[f]:
                        f = self._fail[f]
                    self._fail[nxt] = (self._goto[f].get(b, 0)
                                       if f or b in self._goto[0] else 0)
                    self._out[nxt].extend(self._out[self._fail[nxt]])
            self._built = True
            return self

        def iter_matches(self, data: bytes):
            if not self._built:
                self.build()
            goto, fail, out = self._goto, self._fail, self._out
            node = 0
            for i, b in enumerate(data):
                while node and b not in goto[node]:
                    node = fail[node]
                node = goto[node].get(b, 0)
                if out[node]:
                    for tag in out[node]:
                        yield i, tag

        @property
        def pattern_count(self) -> int:
            return self._npat


# ===========================================================================
# Match record (drop-in-friendly: has both dict-like and attribute access)
# ===========================================================================
@dataclass
class EmuMatch:
    """One DPI hit produced by the emulator.

    Fields required by the contract: tag/sid, offset, engine (name), which
    (``"ac"`` or ``"dfa"``). ``end`` is the exclusive end offset (== offset +
    len for AC; the DFA-longest-match end for regex hits).
    """
    tag: Any
    sid: Optional[int]
    offset: int
    engine: str
    which: str          # "ac" | "dfa"
    end: int = 0

    # convenience so callers can treat a match like a small mapping
    def as_dict(self) -> Dict[str, Any]:
        return {"tag": self.tag, "sid": self.sid, "offset": self.offset,
                "engine": self.engine, "which": self.which, "end": self.end}


def _derive_sid(tag: Any) -> Optional[int]:
    """Best-effort sid extraction from an opaque tag (int, or has .sid/['sid'])."""
    if isinstance(tag, bool):
        return None
    if isinstance(tag, int):
        return tag
    sid = getattr(tag, "sid", None)
    if isinstance(sid, int):
        return sid
    if isinstance(tag, dict) and isinstance(tag.get("sid"), int):
        return tag["sid"]
    return None


# ===========================================================================
# Regex -> Thompson NFA -> subset-construction DFA (explicit byte table)
# ===========================================================================
class _Unsupported(Exception):
    """Raised when the first-cut compiler cannot express a regex construct."""


# character-class helpers over the 0..255 byte alphabet
_ALL = frozenset(range(256))


def _cls_digit() -> frozenset:
    return frozenset(range(0x30, 0x3A))


def _cls_word() -> frozenset:
    s = set(range(0x30, 0x3A)) | set(range(0x41, 0x5B)) | set(range(0x61, 0x7B))
    s.add(0x5F)  # underscore
    return frozenset(s)


def _cls_space() -> frozenset:
    return frozenset({0x20, 0x09, 0x0A, 0x0D, 0x0C, 0x0B})


_SIMPLE_ESCAPE = {
    "n": 0x0A, "r": 0x0D, "t": 0x09, "f": 0x0C, "v": 0x0B, "0": 0x00,
    ".": ord("."), "\\": ord("\\"), "*": ord("*"), "+": ord("+"),
    "?": ord("?"), "(": ord("("), ")": ord(")"), "[": ord("["),
    "]": ord("]"), "{": ord("{"), "}": ord("}"), "|": ord("|"),
    "^": ord("^"), "$": ord("$"), "/": ord("/"), "-": ord("-"),
    " ": 0x20,
}


class _NFA:
    """Thompson NFA with epsilon moves and byte-set symbol transitions."""

    def __init__(self):
        self.eps: List[set] = []          # eps[state] = set(target states)
        self.sym: List[List[Tuple[frozenset, int]]] = []  # (byteset, target)

    def new_state(self) -> int:
        self.eps.append(set())
        self.sym.append([])
        return len(self.eps) - 1


class _RegexParser:
    """Recursive-descent parser producing a Thompson NFA fragment.

    Supported: literals, ``.``, character classes ``[...]`` (ranges + negation),
    escapes (``\\d \\w \\s`` and their negations, ``\\xHH``, escaped meta),
    concatenation, alternation ``|``, grouping ``( )``, and the ``* + ?``
    quantifiers. Everything else raises _Unsupported -> caller uses `re`.
    """

    def __init__(self, pattern: str):
        self.p = pattern
        self.i = 0
        self.n = len(pattern)
        self.nfa = _NFA()

    # -- small scanner helpers --
    def _peek(self) -> str:
        return self.p[self.i] if self.i < self.n else ""

    def _next(self) -> str:
        c = self.p[self.i]
        self.i += 1
        return c

    # fragment = (start_state, accept_state)
    def parse(self) -> Tuple[int, int]:
        frag = self._alt()
        if self.i != self.n:
            raise _Unsupported("trailing input at %d: %r" % (self.i, self.p[self.i:]))
        return frag

    def _alt(self) -> Tuple[int, int]:
        frags = [self._concat()]
        while self._peek() == "|":
            self._next()
            frags.append(self._concat())
        if len(frags) == 1:
            return frags[0]
        s = self.nfa.new_state()
        a = self.nfa.new_state()
        for (fs, fa) in frags:
            self.nfa.eps[s].add(fs)
            self.nfa.eps[fa].add(a)
        return (s, a)

    def _concat(self) -> Tuple[int, int]:
        frags = []
        while True:
            c = self._peek()
            if c == "" or c == "|" or c == ")":
                break
            frags.append(self._repeat())
        if not frags:
            # empty (epsilon) fragment
            s = self.nfa.new_state()
            a = self.nfa.new_state()
            self.nfa.eps[s].add(a)
            return (s, a)
        start, acc = frags[0]
        for (fs, fa) in frags[1:]:
            self.nfa.eps[acc].add(fs)
            acc = fa
        return (start, acc)

    def _repeat(self) -> Tuple[int, int]:
        frag = self._atom()
        c = self._peek()
        if c in ("*", "+", "?"):
            self._next()
            if self._peek() in ("*", "+", "?"):
                # non-greedy / possessive markers -> beyond the first cut
                raise _Unsupported("stacked quantifier near %d" % self.i)
            frag = self._apply_quant(frag, c)
        elif c == "{":
            raise _Unsupported("bounded repetition {m,n}")
        return frag

    def _apply_quant(self, frag: Tuple[int, int], q: str) -> Tuple[int, int]:
        fs, fa = frag
        s = self.nfa.new_state()
        a = self.nfa.new_state()
        if q == "*":
            self.nfa.eps[s].update((fs, a))
            self.nfa.eps[fa].update((fs, a))
        elif q == "+":
            self.nfa.eps[s].add(fs)
            self.nfa.eps[fa].update((fs, a))
        else:  # "?"
            self.nfa.eps[s].update((fs, a))
            self.nfa.eps[fa].add(a)
        return (s, a)

    def _atom(self) -> Tuple[int, int]:
        c = self._peek()
        if c == "(":
            self._next()
            if self._peek() == "?":
                raise _Unsupported("extension group (?...)")
            frag = self._alt()
            if self._peek() != ")":
                raise _Unsupported("unbalanced (")
            self._next()
            return frag
        if c == "[":
            return self._char_class()
        if c == ".":
            self._next()
            return self._byteset_frag(_ALL)
        if c in ("^", "$"):
            raise _Unsupported("anchor %r" % c)
        if c == ")":
            raise _Unsupported("unbalanced )")
        if c == "\\":
            self._next()
            return self._byteset_frag(self._escape())
        if c == "":
            raise _Unsupported("unexpected end of pattern")
        # a plain literal byte (latin-1 code point)
        self._next()
        bval = ord(c)
        if bval > 0xFF:
            raise _Unsupported("non-byte literal %r" % c)
        return self._byteset_frag(frozenset({bval}))

    def _escape(self) -> frozenset:
        if self.i >= self.n:
            raise _Unsupported("dangling escape")
        e = self._next()
        if e == "d":
            return _cls_digit()
        if e == "D":
            return _ALL - _cls_digit()
        if e == "w":
            return _cls_word()
        if e == "W":
            return _ALL - _cls_word()
        if e == "s":
            return _cls_space()
        if e == "S":
            return _ALL - _cls_space()
        if e == "x":
            if self.i + 2 > self.n:
                raise _Unsupported(r"truncated \x escape")
            hx = self.p[self.i:self.i + 2]
            self.i += 2
            try:
                return frozenset({int(hx, 16)})
            except ValueError:
                raise _Unsupported(r"bad \x%s" % hx)
        if e in _SIMPLE_ESCAPE:
            return frozenset({_SIMPLE_ESCAPE[e]})
        if e.isdigit():
            raise _Unsupported("backreference \\%s" % e)
        if e in ("b", "B", "A", "Z"):
            raise _Unsupported("zero-width \\%s" % e)
        raise _Unsupported("unknown escape \\%s" % e)

    def _char_class(self) -> Tuple[int, int]:
        assert self._next() == "["
        negate = False
        if self._peek() == "^":
            self._next()
            negate = True
        members = set()
        first = True
        while True:
            c = self._peek()
            if c == "":
                raise _Unsupported("unterminated [")
            if c == "]" and not first:
                self._next()
                break
            first = False
            # low bound (byte or escape-class)
            if c == "\\":
                self._next()
                esc = self._escape()
                # a range like [\d-x] is nonsense; a class-escape contributes a set
                if len(esc) != 1:
                    members |= esc
                    continue
                lo = next(iter(esc))
            else:
                self._next()
                if ord(c) > 0xFF:
                    raise _Unsupported("non-byte class member")
                lo = ord(c)
            # optional range "lo-hi"
            if self._peek() == "-" and self.i + 1 < self.n and self.p[self.i + 1] != "]":
                self._next()  # consume '-'
                d = self._peek()
                if d == "\\":
                    self._next()
                    esc2 = self._escape()
                    if len(esc2) != 1:
                        raise _Unsupported("class range against a class")
                    hi = next(iter(esc2))
                else:
                    self._next()
                    hi = ord(d)
                if hi < lo:
                    raise _Unsupported("inverted class range")
                members.update(range(lo, hi + 1))
            else:
                members.add(lo)
        bs = frozenset(members)
        if negate:
            bs = _ALL - bs
        if not bs:
            raise _Unsupported("empty character class")
        return self._byteset_frag(bs)

    def _byteset_frag(self, bs: frozenset) -> Tuple[int, int]:
        s = self.nfa.new_state()
        a = self.nfa.new_state()
        self.nfa.sym[s].append((bs, a))
        return (s, a)


@dataclass
class _DFA:
    """Explicit, table-driven DFA over the 0..255 byte alphabet.

    trans[state] is a 256-entry list mapping byte -> next state (or -1 = dead).
    accept is the set of accepting states. This is the gateware-facing artefact.
    """
    trans: List[List[int]]
    accept: set
    start: int = 0
    n_states: int = 0


def _eps_closure(nfa: _NFA, states) -> frozenset:
    stack = list(states)
    seen = set(states)
    while stack:
        s = stack.pop()
        for t in nfa.eps[s]:
            if t not in seen:
                seen.add(t)
                stack.append(t)
    return frozenset(seen)


def _subset_construct(nfa: _NFA, start: int, accept: int,
                      max_states: int = 4096) -> _DFA:
    """Classic subset construction -> dense byte transition table."""
    start_set = _eps_closure(nfa, {start})
    id_of: Dict[frozenset, int] = {start_set: 0}
    order: List[frozenset] = [start_set]
    trans: List[List[int]] = []
    accept_states = set()

    idx = 0
    while idx < len(order):
        cur = order[idx]
        row = [-1] * 256
        # collect all symbol transitions available from this NFA-state set
        # byte -> set of target NFA states
        by_byte: Dict[int, set] = {}
        for st in cur:
            for (bs, tgt) in nfa.sym[st]:
                for b in bs:
                    by_byte.setdefault(b, set()).add(tgt)
        for b, tgts in by_byte.items():
            nxt = _eps_closure(nfa, tgts)
            j = id_of.get(nxt)
            if j is None:
                if len(order) >= max_states:
                    raise _Unsupported("DFA state explosion (> %d)" % max_states)
                j = len(order)
                id_of[nxt] = j
                order.append(nxt)
            row[b] = j
        trans.append(row)
        if accept in cur:
            accept_states.add(idx)
        idx += 1

    return _DFA(trans=trans, accept=accept_states, start=0, n_states=len(order))


# constructs that force the `re` fallback even if the parser might limp along
_FORCE_RE = re.compile(r"\{|\(\?|\\b|\\B|\\A|\\Z|\\[1-9]|(?<!\\)\^|(?<!\\)\$")


class _RegexDFA:
    """Compiled regex: either a real DFA table or a Python `re` fallback."""

    def __init__(self, pattern: str, tag: Any):
        self.pattern = pattern
        self.tag = tag
        self.sid = _derive_sid(tag)
        self.dfa: Optional[_DFA] = None
        self.rx: Optional["re.Pattern"] = None
        self.path = "dfa"
        self._compile()

    def _compile(self) -> None:
        if _FORCE_RE.search(self.pattern):
            self._fallback("unsupported construct")
            return
        try:
            parser = _RegexParser(self.pattern)
            s, a = parser.parse()
            self.dfa = _subset_construct(parser.nfa, s, a)
            self.path = "dfa"
        except _Unsupported:
            self._fallback("compiler limit")
        except Exception:
            self._fallback("compiler error")

    def _fallback(self, _why: str) -> None:
        self.path = "re"
        self.dfa = None
        # DOTALL so `.` in fallback regexes behaves byte-oriented like the DFA
        self.rx = re.compile(self.pattern.encode("latin-1", "ignore"), re.S)

    # -- matching --
    def _dfa_match_at(self, data: bytes, i: int) -> int:
        """Longest anchored match starting at i; returns end offset or -1."""
        dfa = self.dfa
        state = dfa.start
        last = -1
        if state in dfa.accept:
            last = i  # empty-match capable start (guarded by caller)
        j = i
        n = len(data)
        trans = dfa.trans
        acc = dfa.accept
        while j < n:
            nxt = trans[state][data[j]]
            if nxt < 0:
                break
            state = nxt
            j += 1
            if state in acc:
                last = j
        return last

    def find_all(self, data: bytes) -> List[Tuple[int, int]]:
        """Non-overlapping (start, end) match spans, left to right."""
        spans: List[Tuple[int, int]] = []
        n = len(data)
        if self.dfa is not None:
            i = 0
            while i < n:
                end = self._dfa_match_at(data, i)
                if end > i:               # ignore empty matches
                    spans.append((i, end))
                    i = end
                else:
                    i += 1
            return spans
        # `re` fallback path
        for m in self.rx.finditer(data):
            if m.end() > m.start():
                spans.append((m.start(), m.end()))
        return spans


# ===========================================================================
# The emulator façade
# ===========================================================================
def _new_counter(enabled: bool = True) -> Dict[str, Any]:
    return {"enabled": enabled, "packets": 0, "matches": 0, "drops": 0}


class FpgaEmulator:
    """Software emulation of the Lynceus DPI offload engine.

    Two named engines back the two contract engines:
      * an Aho-Corasick engine (default name ``dpi_l7``) for literal
        multi-pattern content signatures, and
      * a regex DFA engine (default name ``dpi_regex``) for PCRE-style rules.

    Both surface through :meth:`emu_status`, shaped like the FPGA
    ``get_engine_status(i)`` so this is a drop-in offload backend.
    """

    AC_ENGINE = "dpi_l7"
    DFA_ENGINE = "dpi_regex"

    def __init__(self):
        self._ac: Optional[AhoCorasick] = None
        self._ac_engine = self.AC_ENGINE
        self._ac_patlen: Dict[Any, int] = {}
        self._ac_loaded = 0

        self._dfa: List[_RegexDFA] = []
        self._dfa_engine = self.DFA_ENGINE

        # per-engine telemetry, keyed by engine name
        self._counters: Dict[str, Dict[str, Any]] = {}
        self.ac_source = _AC_SOURCE

    # -- loading -----------------------------------------------------------
    def load_ac(self, patterns: List[Tuple[bytes, Any]],
                engine: Optional[str] = None) -> int:
        """Build the Aho-Corasick automaton from (pattern_bytes, tag) pairs."""
        if engine:
            self._ac_engine = engine
        ac = AhoCorasick()
        self._ac_patlen = {}
        n = 0
        for pat, tag in patterns:
            if not pat:
                continue
            pb = bytes(pat)
            ac.add(pb, tag)
            self._ac_patlen[tag] = len(pb)
            n += 1
        ac.build()
        self._ac = ac if n else None
        self._ac_loaded = n
        self._counters.setdefault(self._ac_engine, _new_counter(enabled=bool(n)))
        self._counters[self._ac_engine]["enabled"] = bool(n)
        return n

    def load_dfa(self, regexes: List[Tuple[str, Any]],
                 engine: Optional[str] = None) -> int:
        """Compile (regex_str, tag) pairs to DFA tables (or `re` fallback)."""
        if engine:
            self._dfa_engine = engine
        compiled: List[_RegexDFA] = []
        for rx, tag in regexes:
            compiled.append(_RegexDFA(rx, tag))
        self._dfa = compiled
        self._counters.setdefault(self._dfa_engine, _new_counter(enabled=bool(compiled)))
        self._counters[self._dfa_engine]["enabled"] = bool(compiled)
        return len(compiled)

    def dfa_paths(self) -> List[Tuple[str, str]]:
        """Report (pattern, path) where path is 'dfa' or 're' for each regex."""
        return [(r.pattern, r.path) for r in self._dfa]

    # -- scanning ----------------------------------------------------------
    def scan(self, data: bytes, engine: Optional[str] = None) -> List[EmuMatch]:
        """Scan a buffer with the loaded engine(s); update counters.

        `engine` restricts the scan to a single engine name; by default both
        the AC and DFA engines run. Returns all matches ordered by offset.
        """
        data = bytes(data)
        matches: List[EmuMatch] = []

        run_ac = self._ac is not None and (engine in (None, self._ac_engine))
        run_dfa = bool(self._dfa) and (engine in (None, self._dfa_engine))

        if run_ac:
            ac_hits = self._scan_ac(data)
            self._account(self._ac_engine, ac_hits)
            matches.extend(ac_hits)

        if run_dfa:
            dfa_hits = self._scan_dfa(data)
            self._account(self._dfa_engine, dfa_hits)
            matches.extend(dfa_hits)

        matches.sort(key=lambda m: (m.offset, m.which))
        return matches

    def _scan_ac(self, data: bytes) -> List[EmuMatch]:
        out: List[EmuMatch] = []
        for end, tag in self._ac.iter_matches(data):
            plen = self._ac_patlen.get(tag, 0)
            start = end - plen + 1 if plen else end
            out.append(EmuMatch(tag=tag, sid=_derive_sid(tag), offset=start,
                                engine=self._ac_engine, which="ac", end=end + 1))
        return out

    def _scan_dfa(self, data: bytes) -> List[EmuMatch]:
        out: List[EmuMatch] = []
        for rd in self._dfa:
            for (start, end) in rd.find_all(data):
                out.append(EmuMatch(tag=rd.tag, sid=rd.sid, offset=start,
                                    engine=self._dfa_engine, which="dfa", end=end))
        return out

    def _account(self, engine: str, hits: List[EmuMatch]) -> None:
        c = self._counters.setdefault(engine, _new_counter())
        c["packets"] += 1
        c["matches"] += len(hits)
        # firewall semantics: a packet with >=1 DPI hit is dropped
        if hits:
            c["drops"] += 1

    # -- status (drop-in for FPGA get_engine_status) -----------------------
    def emu_status(self, engine_name: str) -> Dict[str, Any]:
        """Return {enabled, packets, matches, drops, mode:"emulated"}.

        Shaped like the FPGA ``get_engine_status(i)`` so the manager's
        offload path can consume it unchanged when no card is present.
        """
        c = self._counters.get(engine_name)
        if c is None:
            return {"enabled": False, "packets": 0, "matches": 0, "drops": 0,
                    "mode": "emulated"}
        return {"enabled": bool(c["enabled"]), "packets": c["packets"],
                "matches": c["matches"], "drops": c["drops"], "mode": "emulated"}

    def status_all(self) -> Dict[str, Dict[str, Any]]:
        return {name: self.emu_status(name) for name in self._counters}

    def reset_counters(self) -> None:
        for c in self._counters.values():
            c["packets"] = c["matches"] = c["drops"] = 0


# ===========================================================================
# Self-test -- no hardware, no network
# ===========================================================================
EICAR = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$"
         b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
LOG4SHELL = b"${jndi:ldap://"


def selftest() -> int:
    print("ffn_fpga_emu selftest (AC source: %s)" % _AC_SOURCE)

    emu = FpgaEmulator()

    # -- 1. Aho-Corasick engine: EICAR + Log4Shell literal ----------------
    n_ac = emu.load_ac([(EICAR, 1000), (LOG4SHELL, 1001)])
    assert n_ac == 2, "expected 2 AC patterns, got %d" % n_ac

    # -- 2. DFA engine: a couple of regexes (exercise DFA + `re` fallback) -
    #   * union<ws>select   -> pure DFA (concat, \s, +)
    #   * evil[0-9]+\.com   -> DFA (class, +, escaped '.')
    #   * \d{3}-\d{4}        -> `re` fallback (bounded repetition {m,n})
    n_dfa = emu.load_dfa([
        (r"union\s+select", 2001),
        (r"evil[0-9]+\.com", 2002),
        (r"\d{3}-\d{4}", 2003),
    ])
    assert n_dfa == 3, "expected 3 DFA regexes, got %d" % n_dfa

    paths = dict(emu.dfa_paths())
    assert paths[r"union\s+select"] == "dfa", "union..select should compile to DFA"
    assert paths[r"evil[0-9]+\.com"] == "dfa", "evil[0-9]+.com should compile to DFA"
    assert paths[r"\d{3}-\d{4}"] == "re", r"\d{3}-\d{4} should fall back to re"
    print("  [ok] regex paths:", paths)

    # -- 3. build a buffer with known offsets and scan --------------------
    prefix = b"harmless preamble >>> "
    mid = b" ... union   select passwd from users ... "
    tail = b" callback evil12345.com and phone 555-1234 end"
    buf = prefix + EICAR + b" xx " + LOG4SHELL + b"attacker/a} " + mid + tail

    eicar_off = buf.index(EICAR)
    log4_off = buf.index(LOG4SHELL)
    union_off = buf.index(b"union   select")
    evil_off = buf.index(b"evil12345.com")
    phone_off = buf.index(b"555-1234")

    hits = emu.scan(buf)
    by_sid = {}
    for m in hits:
        by_sid.setdefault(m.sid, m)

    # AC hits at exact start offsets
    assert 1000 in by_sid, "EICAR not detected"
    assert by_sid[1000].offset == eicar_off, \
        "EICAR offset %d != %d" % (by_sid[1000].offset, eicar_off)
    assert by_sid[1000].which == "ac" and by_sid[1000].engine == emu.AC_ENGINE
    assert buf[by_sid[1000].offset:by_sid[1000].end] == EICAR, "EICAR span mismatch"

    assert 1001 in by_sid, "Log4Shell not detected"
    assert by_sid[1001].offset == log4_off, \
        "Log4Shell offset %d != %d" % (by_sid[1001].offset, log4_off)
    assert by_sid[1001].which == "ac"
    print("  [ok] AC: EICAR @%d, Log4Shell @%d" % (eicar_off, log4_off))

    # DFA hits at exact start offsets
    assert 2001 in by_sid, "union..select (DFA) not detected"
    assert by_sid[2001].offset == union_off, \
        "union offset %d != %d" % (by_sid[2001].offset, union_off)
    assert by_sid[2001].which == "dfa" and by_sid[2001].engine == emu.DFA_ENGINE
    assert buf[by_sid[2001].offset:by_sid[2001].end] == b"union   select"

    assert 2002 in by_sid, "evil[0-9]+.com (DFA) not detected"
    assert by_sid[2002].offset == evil_off, \
        "evil offset %d != %d" % (by_sid[2002].offset, evil_off)
    assert buf[by_sid[2002].offset:by_sid[2002].end] == b"evil12345.com"

    # `re`-fallback hit at exact start offset
    assert 2003 in by_sid, "phone (re fallback) not detected"
    assert by_sid[2003].offset == phone_off, \
        "phone offset %d != %d" % (by_sid[2003].offset, phone_off)
    assert by_sid[2003].which == "dfa"  # engine label, path was `re`
    print("  [ok] DFA: union @%d, evil @%d; re-fallback: phone @%d"
          % (union_off, evil_off, phone_off))

    # -- 4. counters incremented as expected ------------------------------
    ac_st = emu.emu_status(emu.AC_ENGINE)
    dfa_st = emu.emu_status(emu.DFA_ENGINE)
    assert ac_st["mode"] == "emulated" and dfa_st["mode"] == "emulated"
    assert ac_st["enabled"] and dfa_st["enabled"]
    assert ac_st["packets"] == 1 and ac_st["matches"] == 2 and ac_st["drops"] == 1, ac_st
    assert dfa_st["packets"] == 1 and dfa_st["matches"] == 3 and dfa_st["drops"] == 1, dfa_st
    for key in ("enabled", "packets", "matches", "drops", "mode"):
        assert key in ac_st, "emu_status missing %r (get_engine_status shape)" % key
    print("  [ok] counters:", {"ac": ac_st, "dfa": dfa_st})

    # -- 5. benign buffer yields no matches, but still counts a packet ----
    benign = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\nhello world"
    bhits = emu.scan(benign)
    assert bhits == [], "benign buffer produced matches: %r" % bhits
    ac_st2 = emu.emu_status(emu.AC_ENGINE)
    dfa_st2 = emu.emu_status(emu.DFA_ENGINE)
    assert ac_st2["packets"] == 2 and ac_st2["matches"] == 2 and ac_st2["drops"] == 1
    assert dfa_st2["packets"] == 2 and dfa_st2["matches"] == 3 and dfa_st2["drops"] == 1
    print("  [ok] benign buffer clean; packet counted, no new matches/drops")

    # -- 6. single-engine scan + unknown engine status --------------------
    only_ac = emu.scan(EICAR, engine=emu.AC_ENGINE)
    assert any(m.sid == 1000 for m in only_ac) and all(m.which == "ac" for m in only_ac)
    assert emu.emu_status("no_such_engine") == {
        "enabled": False, "packets": 0, "matches": 0, "drops": 0, "mode": "emulated"}
    print("  [ok] single-engine scan + unknown-engine status shape")

    # -- 7. DFA table is an explicit state/transition table (gateware-ready)
    dfa_obj = emu._dfa[0].dfa
    assert dfa_obj is not None and dfa_obj.n_states >= 2
    assert len(dfa_obj.trans[dfa_obj.start]) == 256, "transition row must span byte alphabet"
    assert dfa_obj.accept, "DFA must have >=1 accept state"
    print("  [ok] explicit DFA table: %d states x 256 bytes, accept=%s"
          % (dfa_obj.n_states, sorted(dfa_obj.accept)))

    print("  all assertions passed:", emu.status_all())
    return 0


if __name__ == "__main__":
    if "selftest" in sys.argv:
        sys.exit(selftest())
    print(__doc__)
    sys.exit(0)
