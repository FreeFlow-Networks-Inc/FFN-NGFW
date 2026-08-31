#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
ffn_ml_engine.py -- FFN NGFW inline ML anti-malware / verdict engine.

Contract: REWORK_CONTRACT.md ADDENDUM section 8 (Inline ML engine) + section 9
(MlModelUpdate wire payload). Pass 1.5-modules; owner = ML.

What this module provides
-------------------------
  extract_features(data: bytes) -> list[float]
      Deterministic static feature vector for a file/flow buffer:
        - Shannon entropy (1 float, bits/byte / 8 normalized)
        - 256-bin byte histogram, normalized to sum 1.0 (256 floats)
        - a few header/structure features (magic bits, length buckets)
        - byte n-gram feature hashing (configurable n, hashed to fixed width)
      The layout is frozen and documented by FEATURES_VERSION.

  class XGBoostModel
      Gradient-boosted trees. Trained OFFLINE with the `xgboost` library when
      importable, else a pure-Python gradient-boosted-stumps fallback. Either
      way the model is serialized to a PORTABLE FLAT TREE TABLE (a list of
      nodes {feature, threshold, left, right, leaf}) and INFERENCE is a pure
      -Python array walk with NO xgboost dependency. predict(features)->float
      returns a probability in [0,1]. dump()/load(blob) round-trip the table.

  class NGramModel
      Byte n-gram feature-hash -> logistic scorer. predict(data: bytes)->float.

  class MlEngine
      load(model_blob) / update(model_blob) (atomic hot-swap + version),
      score(data) -> {verdict, score(0..100), model, features_version},
      export()/import_() returning the section 9 MlModelUpdate wire payload dict.
      Verdict thresholds mirror ffn_antimalware: score>=60 malware, >=30
      grayware, else benign.

Design constraints (offline box, stdlib-first)
---------------------------------------------
  * Pure-Python + stdlib by default. `xgboost` is an OPTIONAL training-time
    accelerator, guarded in try/except; inference never imports it. The wire
    blob is portable JSON (utf-8) so no third-party serializer is required.
  * Deterministic feature extraction and deterministic fallback training
    (fixed seed) so selftest() is reproducible and GREEN with or without
    xgboost installed.

selftest(): builds a tiny synthetic labeled set (high-entropy packed +
EICAR-string samples = malware, plain text = benign), trains a model, and
asserts the malware sample scores verdict "malware", benign scores "benign",
and that a portable-table reload predicts byte-identically to the trained
model.
"""

from __future__ import annotations

import hashlib
import json
import math
import struct
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Optional xgboost -- TRAINING ONLY. Never imported at inference time.
# ---------------------------------------------------------------------------
try:  # pragma: no cover - depends on host
    import xgboost as _xgb  # type: ignore
    HAVE_XGBOOST = True
except Exception:  # ImportError or a broken install
    _xgb = None
    HAVE_XGBOOST = False


# ===========================================================================
# Feature extraction
# ===========================================================================
#
# FEATURES_VERSION bumps whenever the vector layout / hashing changes. A model
# blob records the features_version it was trained against; MlEngine refuses to
# score with a mismatched extractor.
FEATURES_VERSION = "ffn-ml-feat-1"

# n-gram config: byte n-grams of length NGRAM_N hashed into NGRAM_WIDTH bins.
NGRAM_N = 2
NGRAM_WIDTH = 256

# Feature vector layout (indices are stable == FEATURES_VERSION contract):
#   [0]              Shannon entropy (bits/byte / 8) in [0,1]
#   [1..256]         256-bin byte histogram, normalized (sum == 1.0, or 0 empty)
#   [257..260]       header/structure features (4 floats)
#   [261..516]       n-gram feature-hash bucket counts, L1-normalized (256)
FEAT_OFF_ENTROPY = 0
FEAT_OFF_HIST = 1
FEAT_OFF_HEADER = FEAT_OFF_HIST + 256          # 257
FEAT_HEADER_LEN = 4
FEAT_OFF_NGRAM = FEAT_OFF_HEADER + FEAT_HEADER_LEN  # 261
FEATURE_LEN = FEAT_OFF_NGRAM + NGRAM_WIDTH      # 261 + 256 = 517

# A handful of well-known file magics -> a single scalar "magic class" feature.
_MAGICS: List[Tuple[bytes, float]] = [
    (b"MZ", 1.0),                    # PE / DOS
    (b"\x7fELF", 2.0),              # ELF
    (b"\xca\xfe\xba\xbe", 3.0),    # Mach-O fat / Java class
    (b"PK\x03\x04", 4.0),          # zip / office / jar
    (b"%PDF", 5.0),                 # PDF
    (b"\x1f\x8b", 6.0),            # gzip
    (b"Rar!", 7.0),                 # rar
    (b"\x89PNG", 8.0),             # png
    (b"GIF8", 9.0),                 # gif
    (b"\xff\xd8\xff", 10.0),      # jpeg
]


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy in bits/byte, range [0, 8]."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = float(len(data))
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def _magic_class(data: bytes) -> float:
    for sig, val in _MAGICS:
        if data.startswith(sig):
            return val
    return 0.0


def _hash_ngrams(data: bytes, n: int, width: int) -> List[float]:
    """Feature-hash byte n-grams into `width` bins, L1-normalized.

    Deterministic: uses a fixed FNV-1a hash over each n-gram window so the
    result is identical across runs, machines and Python builds (no reliance
    on the salted builtin hash()).
    """
    buckets = [0.0] * width
    if len(data) < n:
        return buckets
    total = 0
    for i in range(len(data) - n + 1):
        h = 0x811C9DC5
        for j in range(n):
            h ^= data[i + j]
            h = (h * 0x01000193) & 0xFFFFFFFF
        buckets[h % width] += 1.0
        total += 1
    if total:
        inv = 1.0 / total
        for k in range(width):
            buckets[k] *= inv
    return buckets


def extract_features(data: bytes) -> List[float]:
    """Deterministic static feature vector; length == FEATURE_LEN.

    See the layout table above. features_version == FEATURES_VERSION.
    """
    if data is None:
        data = b""
    if not isinstance(data, (bytes, bytearray)):
        data = bytes(data)
    data = bytes(data)

    feats = [0.0] * FEATURE_LEN

    # [0] entropy, normalized to [0,1]
    ent = shannon_entropy(data)
    feats[FEAT_OFF_ENTROPY] = ent / 8.0

    # [1..256] normalized byte histogram
    n = len(data)
    if n:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        inv = 1.0 / n
        base = FEAT_OFF_HIST
        for i in range(256):
            feats[base + i] = counts[i] * inv

    # [257..260] header/structure features
    h = FEAT_OFF_HEADER
    feats[h + 0] = _magic_class(data)
    # length in a log bucket, normalized (0..~1 for up to ~1 GiB)
    feats[h + 1] = math.log10(n + 1.0) / 9.0
    # printable-ASCII ratio (text vs binary discriminator)
    if n:
        printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
        feats[h + 2] = printable / float(n)
    # zero-byte ratio (padding / binary discriminator)
    if n:
        feats[h + 3] = data.count(0) / float(n)

    # [261..516] n-gram feature hash
    ng = _hash_ngrams(data, NGRAM_N, NGRAM_WIDTH)
    base = FEAT_OFF_NGRAM
    for i in range(NGRAM_WIDTH):
        feats[base + i] = ng[i]

    return feats


# ===========================================================================
# Portable flat tree table + pure-Python evaluator
# ===========================================================================
#
# A "node" is a dict {feature, threshold, left, right, leaf}:
#   * internal node: feature>=0, left/right are child indices, go LEFT when
#     x[feature] < threshold else RIGHT.  leaf is ignored.
#   * leaf node:      feature == -1, left == right == -1, leaf == value.
# A "tree" is a list[node] with node[0] the root. The ensemble is a list of
# trees; the raw margin is base_score + sum(leaf reached in each tree).

LEAF = -1


def _eval_tree(tree: List[Dict[str, Any]], x: Sequence[float]) -> float:
    """Walk one flat tree; pure array indexing, no recursion."""
    idx = 0
    # guard against a malformed table (cycle) with a hard cap
    for _ in range(len(tree) + 1):
        node = tree[idx]
        f = node["feature"]
        if f == LEAF:
            return node["leaf"]
        if x[f] < node["threshold"]:
            idx = node["left"]
        else:
            idx = node["right"]
    return 0.0


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


# ===========================================================================
# XGBoostModel -- offline train, portable-table inference
# ===========================================================================
class XGBoostModel:
    """Gradient-boosted trees with a portable flat-table representation.

    Training path (offline): uses the real `xgboost` library when importable,
    otherwise a deterministic pure-Python gradient-boosted-stumps trainer.
    Either path is distilled into `self.trees` (list of flat trees) so that
    INFERENCE (`predict`) is a pure-Python array walk with no xgboost import.
    """

    def __init__(self) -> None:
        self.trees: List[List[Dict[str, Any]]] = []
        self.base_score: float = 0.0   # raw-margin bias (pre-sigmoid)
        self.n_features: int = FEATURE_LEN
        self.trained_with: str = "none"
        self.features_version: str = FEATURES_VERSION

    # -- inference ---------------------------------------------------------
    def predict(self, features: Sequence[float]) -> float:
        """Return P(malware) in [0,1] from the portable table (no xgboost)."""
        margin = self.base_score
        for tree in self.trees:
            margin += _eval_tree(tree, features)
        return _sigmoid(margin)

    # -- serialization -----------------------------------------------------
    def dump(self) -> bytes:
        """Serialize the portable tree table to a JSON utf-8 blob."""
        obj = {
            "kind": "xgboost",
            "trained_with": self.trained_with,
            "n_features": self.n_features,
            "base_score": self.base_score,
            "features_version": self.features_version,
            "trees": self.trees,
        }
        return json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def load(cls, blob: bytes) -> "XGBoostModel":
        if isinstance(blob, (bytes, bytearray)):
            obj = json.loads(bytes(blob).decode("utf-8"))
        elif isinstance(blob, str):
            obj = json.loads(blob)
        else:
            obj = dict(blob)
        m = cls()
        m.trees = obj.get("trees", [])
        m.base_score = float(obj.get("base_score", 0.0))
        m.n_features = int(obj.get("n_features", FEATURE_LEN))
        m.trained_with = obj.get("trained_with", "none")
        m.features_version = obj.get("features_version", FEATURES_VERSION)
        return m

    # -- training ----------------------------------------------------------
    def fit(self, X: Sequence[Sequence[float]], y: Sequence[int],
            n_estimators: int = 24, max_depth: int = 3,
            learning_rate: float = 0.3) -> "XGBoostModel":
        """Train offline. Prefers xgboost; falls back to pure-Python GBM."""
        self.n_features = len(X[0]) if X else FEATURE_LEN
        if HAVE_XGBOOST:
            try:
                self._fit_xgboost(X, y, n_estimators, max_depth, learning_rate)
                self.trained_with = "xgboost"
                return self
            except Exception:
                # any xgboost hiccup -> deterministic fallback
                self.trees = []
        self._fit_python(X, y, n_estimators, max_depth, learning_rate)
        self.trained_with = "python-gbm"
        return self

    # -- xgboost training, distilled to the portable table -----------------
    def _fit_xgboost(self, X, y, n_estimators, max_depth, learning_rate) -> None:  # pragma: no cover
        dtrain = _xgb.DMatrix(list([list(map(float, r)) for r in X]),
                              label=list(map(float, y)))
        params = {
            "objective": "binary:logistic",
            "max_depth": int(max_depth),
            "eta": float(learning_rate),
            "base_score": 0.5,
            "verbosity": 0,
        }
        booster = _xgb.train(params, dtrain, num_boost_round=int(n_estimators))
        # base_score 0.5 -> raw-margin bias 0 (sigmoid(0)=0.5)
        self.base_score = 0.0
        self.trees = self._parse_xgb_dump(booster.get_dump(with_stats=False))

    @staticmethod
    def _parse_xgb_dump(dumps: Sequence[str]) -> List[List[Dict[str, Any]]]:  # pragma: no cover
        """Parse xgboost text dump into flat tree tables.

        Each dump is a text tree like:
            0:[f12<0.5] yes=1,no=2,missing=1
                1:leaf=0.3
                2:[f7<1.2] yes=3,no=4,missing=3
                    3:leaf=-0.1
                    4:leaf=0.2
        We remap the sparse xgb node ids to dense array indices, sending the
        `missing` direction to the same child xgb chose (default = yes/left).
        """
        import re
        trees: List[List[Dict[str, Any]]] = []
        node_re = re.compile(
            r"(\d+):\[f(\d+)<([-\d.eE+]+)\]\s+yes=(\d+),no=(\d+)")
        leaf_re = re.compile(r"(\d+):leaf=([-\d.eE+]+)")
        for text in dumps:
            raw: Dict[int, Dict[str, Any]] = {}
            for line in text.strip().splitlines():
                line = line.strip()
                mm = node_re.match(line)
                if mm:
                    nid = int(mm.group(1))
                    raw[nid] = {
                        "feature": int(mm.group(2)),
                        "threshold": float(mm.group(3)),
                        "yes": int(mm.group(4)),
                        "no": int(mm.group(5)),
                    }
                    continue
                ml = leaf_re.match(line)
                if ml:
                    raw[int(ml.group(1))] = {"leaf": float(ml.group(2))}
            # dense remap in ascending xgb-id order (root == smallest id)
            order = sorted(raw.keys())
            remap = {nid: i for i, nid in enumerate(order)}
            flat: List[Dict[str, Any]] = []
            for nid in order:
                nd = raw[nid]
                if "leaf" in nd:
                    flat.append({"feature": LEAF, "threshold": 0.0,
                                 "left": LEAF, "right": LEAF, "leaf": nd["leaf"]})
                else:
                    flat.append({
                        "feature": nd["feature"],
                        "threshold": nd["threshold"],
                        "left": remap[nd["yes"]],
                        "right": remap[nd["no"]],
                        "leaf": 0.0,
                    })
            trees.append(flat)
        return trees

    # -- pure-Python gradient-boosted trees (deterministic fallback) -------
    def _fit_python(self, X, y, n_estimators, max_depth, learning_rate) -> None:
        X = [list(map(float, r)) for r in X]
        y = [float(v) for v in y]
        n = len(X)
        # log-odds base score from class balance
        pos = sum(1 for v in y if v >= 0.5)
        pos = min(max(pos, 1), n - 1) if n > 1 else max(pos, 0)
        p0 = pos / float(n) if n else 0.5
        p0 = min(max(p0, 1e-6), 1 - 1e-6)
        self.base_score = math.log(p0 / (1.0 - p0))

        margins = [self.base_score] * n
        self.trees = []
        for _ in range(int(n_estimators)):
            # gradient/hessian for logistic loss
            grad = []
            hess = []
            for i in range(n):
                p = _sigmoid(margins[i])
                grad.append(p - y[i])
                hess.append(max(p * (1.0 - p), 1e-6))
            tree = self._build_tree(X, grad, hess, list(range(n)),
                                    depth=0, max_depth=int(max_depth))
            # scale leaves by learning rate and update margins
            self._scale_leaves(tree, learning_rate)
            for i in range(n):
                margins[i] += _eval_tree(tree, X[i])
            self.trees.append(tree)

    def _build_tree(self, X, grad, hess, idxs, depth, max_depth,
                    reg_lambda: float = 1.0) -> List[Dict[str, Any]]:
        """Build one regression tree; returns a flat node table (root == 0)."""
        nodes: List[Dict[str, Any]] = []

        def leaf_value(rows: List[int]) -> float:
            g = sum(grad[i] for i in rows)
            h = sum(hess[i] for i in rows)
            return -g / (h + reg_lambda)

        def recurse(rows: List[int], d: int) -> int:
            my = len(nodes)
            nodes.append({"feature": LEAF, "threshold": 0.0,
                          "left": LEAF, "right": LEAF, "leaf": 0.0})
            if d >= max_depth or len(rows) < 2:
                nodes[my]["leaf"] = leaf_value(rows)
                return my
            feat, thr, lrows, rrows = self._best_split(X, grad, hess, rows,
                                                       reg_lambda)
            if feat is None or not lrows or not rrows:
                nodes[my]["leaf"] = leaf_value(rows)
                return my
            li = recurse(lrows, d + 1)
            ri = recurse(rrows, d + 1)
            nodes[my] = {"feature": feat, "threshold": thr,
                         "left": li, "right": ri, "leaf": 0.0}
            return my

        recurse(idxs, depth)
        return nodes

    @staticmethod
    def _best_split(X, grad, hess, rows, reg_lambda):
        """Exact greedy split on gain; deterministic feature/threshold scan.

        To stay fast on the 517-dim vector we only consider features that vary
        across `rows`, and candidate thresholds = midpoints of sorted unique
        values (capped) for each such feature.
        """
        G = sum(grad[i] for i in rows)
        H = sum(hess[i] for i in rows)
        parent = (G * G) / (H + reg_lambda)
        best_gain = 0.0
        best = (None, 0.0, None, None)
        nfeat = len(X[0]) if X and rows else 0
        for f in range(nfeat):
            vals = sorted({X[i][f] for i in rows})
            if len(vals) < 2:
                continue
            # candidate thresholds = midpoints (cap to keep it bounded)
            cands = vals
            if len(cands) > 33:
                step = len(cands) / 33.0
                cands = [cands[int(k * step)] for k in range(33)]
            for vi in range(1, len(cands)):
                thr = 0.5 * (cands[vi - 1] + cands[vi])
                GL = HL = 0.0
                for i in rows:
                    if X[i][f] < thr:
                        GL += grad[i]
                        HL += hess[i]
                GR = G - GL
                HR = H - HL
                if HL <= 0 or HR <= 0:
                    continue
                gain = (GL * GL) / (HL + reg_lambda) + \
                       (GR * GR) / (HR + reg_lambda) - parent
                if gain > best_gain + 1e-12:
                    best_gain = gain
                    lrows = [i for i in rows if X[i][f] < thr]
                    rrows = [i for i in rows if X[i][f] >= thr]
                    best = (f, thr, lrows, rrows)
        return best

    def _scale_leaves(self, tree: List[Dict[str, Any]], lr: float) -> None:
        for node in tree:
            if node["feature"] == LEAF:
                node["leaf"] *= lr


# ===========================================================================
# NGramModel -- byte n-gram feature-hash -> logistic scorer
# ===========================================================================
class NGramModel:
    """Streaming byte-n-gram feature-hash logistic model.

    Independent of the full feature vector: hashes byte n-grams directly from
    the raw buffer into `width` weights + a bias, so it can score a partial
    stream cheaply. predict(data)->P(malware) in [0,1].
    """

    def __init__(self, n: int = NGRAM_N, width: int = NGRAM_WIDTH) -> None:
        self.n = int(n)
        self.width = int(width)
        self.weights: List[float] = [0.0] * self.width
        self.bias: float = 0.0

    def _vec(self, data: bytes) -> List[float]:
        return _hash_ngrams(bytes(data), self.n, self.width)

    def predict(self, data: bytes) -> float:
        x = self._vec(data)
        z = self.bias
        for i in range(self.width):
            z += self.weights[i] * x[i]
        return _sigmoid(z)

    def fit(self, samples: Sequence[bytes], y: Sequence[int],
            epochs: int = 200, lr: float = 0.5, reg: float = 1e-4) -> "NGramModel":
        """Deterministic logistic-regression SGD (fixed order, no randomness)."""
        X = [self._vec(bytes(s)) for s in samples]
        yy = [float(v) for v in y]
        n = len(X)
        for _ in range(int(epochs)):
            for i in range(n):
                p = self._forward(X[i])
                err = p - yy[i]
                self.bias -= lr * err
                xi = X[i]
                for k in range(self.width):
                    if xi[k]:
                        self.weights[k] -= lr * (err * xi[k] + reg * self.weights[k])
        return self

    def _forward(self, x: List[float]) -> float:
        z = self.bias
        for i in range(self.width):
            z += self.weights[i] * x[i]
        return _sigmoid(z)

    def dump(self) -> bytes:
        obj = {"kind": "ngram", "n": self.n, "width": self.width,
               "bias": self.bias, "weights": self.weights}
        return json.dumps(obj, separators=(",", ":")).encode("utf-8")

    @classmethod
    def load(cls, blob: bytes) -> "NGramModel":
        if isinstance(blob, (bytes, bytearray)):
            obj = json.loads(bytes(blob).decode("utf-8"))
        elif isinstance(blob, str):
            obj = json.loads(blob)
        else:
            obj = dict(blob)
        m = cls(n=int(obj.get("n", NGRAM_N)), width=int(obj.get("width", NGRAM_WIDTH)))
        m.weights = [float(w) for w in obj.get("weights", [0.0] * m.width)]
        m.bias = float(obj.get("bias", 0.0))
        if len(m.weights) != m.width:
            m.weights = (m.weights + [0.0] * m.width)[:m.width]
        return m


# ===========================================================================
# MlEngine -- orchestrator, hot-swap, wire payload
# ===========================================================================
# Verdict thresholds mirror ffn_antimalware (score>=60 malware, >=30 grayware).
THRESH_MALWARE = 60
THRESH_GRAYWARE = 30

# Fusion weight between the XGBoost tree model and the n-gram model when both
# are present in a blob. Trees carry most of the signal.
_W_TREE = 0.7
_W_NGRAM = 0.3


class MlEngine:
    """Inline ML verdict engine with atomic hot-swap and a §9 wire payload.

    A model blob (dict or its JSON bytes) contains:
        {
          "kind": "ml-model",
          "version": <int>,
          "features_version": <str>,
          "tree_blob":  <bytes/str JSON of XGBoostModel.dump()> | None,
          "ngram_params": <bytes/str JSON of NGramModel.dump()> | None,
        }
    export()/import_() speak the §9 MlModelUpdate shape.
    """

    def __init__(self) -> None:
        self.version: int = 0
        self.features_version: str = FEATURES_VERSION
        self.tree: Optional[XGBoostModel] = None
        self.ngram: Optional[NGramModel] = None
        self.model_name: str = "empty"
        self.stats: Dict[str, int] = {"benign": 0, "grayware": 0, "malware": 0}

    # -- (de)serialization of the combined engine blob --------------------
    @staticmethod
    def _as_obj(model_blob: Any) -> Dict[str, Any]:
        if isinstance(model_blob, dict):
            return model_blob
        if isinstance(model_blob, (bytes, bytearray)):
            return json.loads(bytes(model_blob).decode("utf-8"))
        if isinstance(model_blob, str):
            return json.loads(model_blob)
        raise TypeError("unsupported model_blob type: %r" % type(model_blob))

    def _build_from(self, obj: Dict[str, Any]) -> Tuple[Optional[XGBoostModel],
                                                         Optional[NGramModel]]:
        tree = None
        ngram = None
        tb = obj.get("tree_blob")
        if tb:
            tree = XGBoostModel.load(tb)
        ng = obj.get("ngram_params")
        if ng:
            ngram = NGramModel.load(ng)
        return tree, ngram

    def load(self, model_blob: Any) -> "MlEngine":
        """Load a model blob into this engine (non-atomic initial load)."""
        obj = self._as_obj(model_blob)
        self.tree, self.ngram = self._build_from(obj)
        self.version = int(obj.get("version", 0))
        self.features_version = obj.get("features_version", FEATURES_VERSION)
        self.model_name = obj.get("kind", "ml-model")
        return self

    def update(self, model_blob: Any) -> int:
        """Atomic hot-swap: fully build the new model set, then flip pointers.

        Returns the new version. Raises before mutating anything if the blob is
        malformed, so a live engine is never left half-swapped.
        """
        obj = self._as_obj(model_blob)
        new_tree, new_ngram = self._build_from(obj)          # may raise -> no swap
        new_version = int(obj.get("version", self.version + 1))
        new_fv = obj.get("features_version", FEATURES_VERSION)
        # single-statement pointer flip == atomic w.r.t. GIL-serialized readers
        self.tree, self.ngram = new_tree, new_ngram
        self.version = new_version
        self.features_version = new_fv
        self.model_name = obj.get("kind", "ml-model")
        return self.version

    # -- scoring ----------------------------------------------------------
    def _raw_prob(self, data: bytes) -> float:
        """Fuse available models into P(malware) in [0,1]."""
        probs = []
        weights = []
        if self.tree is not None:
            feats = extract_features(data)
            probs.append(self.tree.predict(feats))
            weights.append(_W_TREE)
        if self.ngram is not None:
            probs.append(self.ngram.predict(data))
            weights.append(_W_NGRAM)
        if not probs:
            return 0.0
        wsum = sum(weights)
        return sum(p * w for p, w in zip(probs, weights)) / wsum

    def score(self, data: bytes) -> Dict[str, Any]:
        """Return {verdict, score(0..100), model, features_version}."""
        if data is None:
            data = b""
        p = self._raw_prob(data)
        score = int(round(p * 100.0))
        score = max(0, min(100, score))
        if score >= THRESH_MALWARE:
            verdict = "malware"
        elif score >= THRESH_GRAYWARE:
            verdict = "grayware"
        else:
            verdict = "benign"
        self.stats[verdict] = self.stats.get(verdict, 0) + 1
        return {
            "verdict": verdict,
            "score": score,
            "model": self.model_name,
            "version": self.version,
            "features_version": self.features_version,
        }

    # -- §9 MlModelUpdate wire payload ------------------------------------
    def export(self) -> Dict[str, Any]:
        """Return the §9 MlModelUpdate wire payload dict.

        Shapes to `MlModelUpdate { version, kind, tree_blob:[ubyte],
        ngram_params:[ubyte], features_version }`. tree_blob/ngram_params are
        the raw model bytes (portable JSON), ready to embed as [ubyte] vectors.
        """
        tree_blob = self.tree.dump() if self.tree is not None else b""
        ngram_params = self.ngram.dump() if self.ngram is not None else b""
        # MlKind: 0 = xgboost-tree, 1 = ngram, 2 = both
        if self.tree is not None and self.ngram is not None:
            kind = 2
        elif self.ngram is not None:
            kind = 1
        else:
            kind = 0
        return {
            "kind": kind,
            "version": self.version,
            "tree_blob": tree_blob,
            "ngram_params": ngram_params,
            "features_version": self.features_version,
        }

    def import_(self, payload: Dict[str, Any]) -> int:
        """Load a §9 MlModelUpdate wire payload (inverse of export())."""
        blob = {
            "kind": "ml-model",
            "version": int(payload.get("version", self.version + 1)),
            "features_version": payload.get("features_version", FEATURES_VERSION),
            "tree_blob": payload.get("tree_blob") or None,
            "ngram_params": payload.get("ngram_params") or None,
        }
        # normalize empty byte strings to None so _build_from skips them
        if blob["tree_blob"] in (b"", ""):
            blob["tree_blob"] = None
        if blob["ngram_params"] in (b"", ""):
            blob["ngram_params"] = None
        return self.update(blob)

    # -- convenience: assemble an engine blob from trained sub-models ------
    @staticmethod
    def make_blob(tree: Optional[XGBoostModel], ngram: Optional[NGramModel],
                  version: int = 1,
                  features_version: str = FEATURES_VERSION) -> bytes:
        obj = {
            "kind": "ml-model",
            "version": int(version),
            "features_version": features_version,
            "tree_blob": tree.dump().decode("utf-8") if tree is not None else None,
            "ngram_params": ngram.dump().decode("utf-8") if ngram is not None else None,
        }
        return json.dumps(obj).encode("utf-8")


# ===========================================================================
# Synthetic training data (deterministic)
# ===========================================================================
_EICAR = (rb"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")


def _lcg(seed: int):
    """Tiny deterministic PRNG (no dependence on random module seeding)."""
    state = seed & 0xFFFFFFFF

    def nxt() -> int:
        nonlocal state
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        return state
    return nxt


def _synthetic_dataset() -> Tuple[List[bytes], List[int]]:
    """Build a tiny labeled corpus: malware-ish (1) vs benign (0)."""
    rnd = _lcg(0xC0FFEE)
    samples: List[bytes] = []
    labels: List[int] = []

    # --- benign: plain english-ish text -----------------------------------
    words = [b"the ", b"quick ", b"brown ", b"fox ", b"jumps ", b"over ",
             b"lazy ", b"dog ", b"hello ", b"world ", b"config ", b"value ",
             b"report ", b"summary ", b"please ", b"review "]
    for k in range(12):
        buf = bytearray()
        while len(buf) < 400:
            buf += words[rnd() % len(words)]
        samples.append(bytes(buf))
        labels.append(0)

    # benign: a small structured text/CSV-ish doc
    for k in range(4):
        buf = ("name,value,notes\n" * 40).encode()
        samples.append(buf)
        labels.append(0)

    # --- malware: high-entropy packed blobs -------------------------------
    for k in range(10):
        buf = bytearray(b"MZ")
        while len(buf) < 500:
            buf.append(rnd() & 0xFF)
        samples.append(bytes(buf))
        labels.append(1)

    # malware: EICAR-string carriers (the canonical AV test signature)
    for k in range(6):
        pad = bytes((rnd() & 0xFF) for _ in range(rnd() % 60))
        samples.append(pad + _EICAR + pad)
        labels.append(1)

    return samples, labels


# ===========================================================================
# selftest
# ===========================================================================
def selftest() -> int:
    print("ffn_ml_engine selftest (xgboost=%s)" % ("yes" if HAVE_XGBOOST else "no"))

    # -- feature extraction determinism & shape ---------------------------
    f1 = extract_features(b"hello world")
    f2 = extract_features(b"hello world")
    assert len(f1) == FEATURE_LEN, len(f1)
    assert f1 == f2, "feature extraction not deterministic"
    assert 0.0 <= f1[FEAT_OFF_ENTROPY] <= 1.0
    hist_sum = sum(f1[FEAT_OFF_HIST:FEAT_OFF_HIST + 256])
    assert abs(hist_sum - 1.0) < 1e-9, hist_sum
    print("  [ok] extract_features deterministic, len=%d, %s" %
          (FEATURE_LEN, FEATURES_VERSION))

    # entropy sanity: random bytes >> english text
    ent_rand = shannon_entropy(bytes(range(256)) * 4)
    ent_text = shannon_entropy(b"aaaaaaaaaa bbbb the the the")
    assert ent_rand > ent_text, (ent_rand, ent_text)
    print("  [ok] entropy rand=%.2f > text=%.2f" % (ent_rand, ent_text))

    # -- build training set -----------------------------------------------
    samples, labels = _synthetic_dataset()
    X = [extract_features(s) for s in samples]

    # -- train XGBoostModel (xgboost if present, else python GBM) ----------
    tree = XGBoostModel().fit(X, labels, n_estimators=20, max_depth=3)
    print("  [ok] XGBoostModel trained (%s), %d trees" %
          (tree.trained_with, len(tree.trees)))

    # -- portable-table reload predicts IDENTICALLY -----------------------
    blob = tree.dump()
    tree2 = XGBoostModel.load(blob)
    for x in X:
        p1 = tree.predict(x)
        p2 = tree2.predict(x)
        assert abs(p1 - p2) < 1e-12, (p1, p2)
    print("  [ok] portable flat-table reload predicts byte-identically")

    # -- train NGramModel --------------------------------------------------
    ng = NGramModel().fit(samples, labels, epochs=250, lr=0.5)
    ng2 = NGramModel.load(ng.dump())
    for s in samples:
        assert abs(ng.predict(s) - ng2.predict(s)) < 1e-12
    print("  [ok] NGramModel trained + reload identical")

    # -- assemble engine, score canonical samples -------------------------
    eng = MlEngine()
    eng.load(MlEngine.make_blob(tree, ng, version=1))

    # EICAR carrier -> malware
    mal = eng.score(_EICAR + b"\x00\x11\x22trailing")
    print("  malware sample  -> %s" % mal)
    assert mal["verdict"] == "malware", mal

    # high-entropy packed -> malware
    rnd = _lcg(0x1234)
    packed = bytes(b"MZ") + bytes((rnd() & 0xFF) for _ in range(600))
    malp = eng.score(packed)
    print("  packed sample   -> %s" % malp)
    assert malp["verdict"] == "malware", malp

    # plain english text -> benign
    ben = eng.score(b"the quick brown fox jumps over the lazy dog. " * 12)
    print("  benign sample   -> %s" % ben)
    assert ben["verdict"] == "benign", ben

    assert mal["features_version"] == FEATURES_VERSION

    # -- atomic hot-swap via §9 wire payload round-trip -------------------
    payload = eng.export()
    assert payload["features_version"] == FEATURES_VERSION
    assert payload["kind"] == 2, payload["kind"]  # both models present
    eng2 = MlEngine()
    new_ver = eng2.import_(payload)
    assert new_ver == payload["version"]
    # scored identically after wire round-trip
    for probe, want in ((_EICAR + b"z", "malware"),
                        (b"the lazy dog sleeps quietly " * 15, "benign")):
        a = eng.score(probe)["verdict"]
        b = eng2.score(probe)["verdict"]
        assert a == b == want, (a, b, want)
    print("  [ok] §9 MlModelUpdate export/import_ round-trip, hot-swap v%d" %
          new_ver)

    # -- update() is atomic: bad blob leaves engine intact ----------------
    ver_before = eng.version
    try:
        eng.update(b"{ this is not valid json ")
        raise AssertionError("expected update() to reject malformed blob")
    except AssertionError:
        raise
    except Exception:
        pass
    assert eng.version == ver_before, "engine mutated on failed update"
    assert eng.score(_EICAR)["verdict"] == "malware"
    print("  [ok] update() atomic: malformed blob rejected, engine intact")

    # -- ngram-only and tree-only engines both score ----------------------
    eng_ng = MlEngine().load(MlEngine.make_blob(None, ng, version=3))
    assert eng_ng.export()["kind"] == 1
    _ = eng_ng.score(_EICAR)
    eng_tr = MlEngine().load(MlEngine.make_blob(tree, None, version=4))
    assert eng_tr.export()["kind"] == 0
    _ = eng_tr.score(packed)
    print("  [ok] tree-only + ngram-only engines operational")

    print("ALL OK")
    return 0


# ===========================================================================
# CLI
# ===========================================================================
def _main(argv: List[str]) -> int:
    if len(argv) >= 2 and argv[1] == "selftest":
        return selftest()
    if len(argv) >= 3 and argv[1] == "score":
        # score a file with a freshly-trained selftest model (demo only)
        samples, labels = _synthetic_dataset()
        X = [extract_features(s) for s in samples]
        tree = XGBoostModel().fit(X, labels)
        ng = NGramModel().fit(samples, labels)
        eng = MlEngine().load(MlEngine.make_blob(tree, ng, version=1))
        with open(argv[2], "rb") as fh:
            data = fh.read()
        print(json.dumps(eng.score(data)))
        return 0
    print("usage: ffn_ml_engine.py selftest | score <file>")
    return 2


if __name__ == "__main__":
    sys.exit(_main(sys.argv))
