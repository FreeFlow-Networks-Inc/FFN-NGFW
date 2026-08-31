#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
FFN NGFW — WildFire ML Model Update Agent

Reads suspicious packets punted by the FPGA BNN engine via QDMA C2H,
runs deeper analysis, collects labeled samples, retrains the BNN with
binary quantization, and DMA-loads updated weights back to the FPGA.

Workflow:
  1. Open QDMA C2H device to receive packets flagged as suspicious
     by the on-FPGA binary neural network.
  2. For each packet, run local analysis (file hash DB, heuristics).
  3. Label the sample as confirmed-malicious or benign.
  4. When enough new samples accumulate, retrain the BNN:
     - Float32 training with simple gradient descent
     - Binary quantization: weights = sign(float_weights)
     - Pack binary weights into 32-bit words
  5. Load updated weights to FPGA BNN BRAM via ioctl.
  6. Log all verdicts to syslog.

Usage:
    ffn_wildfire_agent.py [--dev /dev/ngfw0] [--qdma /dev/qdma0-c2h-0]
                          [--hashdb /var/lib/ngfw/hashes.db]
                          [--interval 300] [--min-samples 100]
                          [--debug]
"""

import argparse
import ctypes
try:
    import fcntl  # Linux-only; used solely by the FPGA ioctl path below
except ImportError:  # non-Linux (offline tests / CI) -- hardware path is unused there
    fcntl = None
import hashlib
import logging
import logging.handlers
import os
import signal
import struct
import sys
import time
from pathlib import Path

import numpy as np

# Canonical threat-intelligence store (the WildFire database). Imported softly
# so the agent still runs if it is not deployed; without it, lookups + verdict
# feedback fall back to the legacy flat-file HashDB only.
try:
    from ffn_threatdb import ThreatDB, DEFAULT_DB_PATH as THREATDB_DEFAULT
except Exception:  # missing module / import error
    ThreatDB = None
    THREATDB_DEFAULT = "/var/lib/ffn-ngfw/threatdb.sqlite"

# ============================================================
# FPGA ioctl definitions (must match ngfw_regs.h)
# ============================================================

NGFW_IOC_MAGIC = ord('N')

# _IOW(magic, nr, size) — Linux ioctl number encoding
def _IOW(magic, nr, size):
    return (1 << 30) | (size << 16) | (magic << 8) | nr

def _IOWR(magic, nr, size):
    return (3 << 30) | (size << 16) | (magic << 8) | nr


# struct ngfw_bnn_weight_load { u8 layer; u16 offset; u32 data; }
# Packed size: 1 + 2 + 4 = 7, but struct padding makes it 8
class BnnWeightLoad(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("layer",  ctypes.c_uint8),
        ("offset", ctypes.c_uint16),
        ("data",   ctypes.c_uint32),
    ]

NGFW_IOC_BNN_LOAD = _IOW(NGFW_IOC_MAGIC, 0x17, ctypes.sizeof(BnnWeightLoad))

# struct ngfw_engine_stats { u8 engine_id; u64 packets, matches, drops, errors; }
class EngineStats(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("engine_id", ctypes.c_uint8),
        ("packets",   ctypes.c_uint64),
        ("matches",   ctypes.c_uint64),
        ("drops",     ctypes.c_uint64),
        ("errors",    ctypes.c_uint64),
    ]

NGFW_IOC_ENGINE_STATS = _IOWR(NGFW_IOC_MAGIC, 0x18, ctypes.sizeof(EngineStats))

# ML inference engine table ID
NGFW_TBL_ML_INFERENCE = 0x15

# ============================================================
# BNN architecture constants
# ============================================================

# Default BNN topology: input -> hidden layers -> output
# Matches the FPGA RTL bnn_inference.v configuration.
BNN_INPUT_SIZE   = 256    # 256 features extracted from packet header
BNN_HIDDEN_SIZES = [512, 256, 128]
BNN_OUTPUT_SIZE  = 2      # [benign, malicious]
BNN_NUM_LAYERS   = len(BNN_HIDDEN_SIZES) + 1   # hidden + output
BNN_LEARNING_RATE = 0.01
BNN_BATCH_SIZE    = 32

# ============================================================
# File hash database (simple flat file of known-bad SHA256)
# ============================================================

class HashDB:
    """Simple file hash database for known malicious content."""

    def __init__(self, db_path):
        self.db_path = db_path
        self.hashes = set()
        self._load()

    def _load(self):
        if not os.path.exists(self.db_path):
            return
        try:
            with open(self.db_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.hashes.add(line.lower())
            logging.info("loaded %d hashes from %s", len(self.hashes), self.db_path)
        except OSError as e:
            logging.warning("cannot load hash DB %s: %s", self.db_path, e)

    def is_known_malicious(self, data):
        """Check if SHA256 of data matches a known-bad hash."""
        h = hashlib.sha256(data).hexdigest()
        return h in self.hashes

# ============================================================
# Packet feature extraction
# ============================================================

def extract_features(pkt_data):
    """
    Extract a fixed-size feature vector from raw packet bytes.

    Features are designed to match the FPGA's feature extraction
    pipeline in feature_extract.v:
      - Byte histogram (256 values, normalized)
      - Entropy estimate
      - Packet length statistics
      - Protocol-specific fields (IP/TCP/UDP header fields)
    """
    data = np.frombuffer(pkt_data[:1500], dtype=np.uint8)
    features = np.zeros(BNN_INPUT_SIZE, dtype=np.float32)

    pkt_len = len(data)

    # Byte frequency histogram (first 128 features)
    hist, _ = np.histogram(data, bins=128, range=(0, 256))
    if pkt_len > 0:
        features[:128] = hist.astype(np.float32) / pkt_len

    # Entropy (feature 128)
    if pkt_len > 0:
        probs = hist[hist > 0].astype(np.float32) / pkt_len
        features[128] = -np.sum(probs * np.log2(probs + 1e-10))

    # Packet length normalized (feature 129)
    features[129] = min(pkt_len / 1500.0, 1.0)

    # IP header fields (features 130-145)
    if pkt_len >= 34:   # minimum Ethernet + IP header
        ip_start = 14   # skip Ethernet header
        features[130] = data[ip_start] / 255.0       # version + IHL
        features[131] = data[ip_start + 1] / 255.0   # DSCP/ECN
        features[132] = (int(data[ip_start + 2]) << 8 | int(data[ip_start + 3])) / 65535.0  # total length
        features[133] = data[ip_start + 8] / 255.0   # TTL
        features[134] = data[ip_start + 9] / 255.0   # protocol

        # Source IP bytes
        features[135] = data[ip_start + 12] / 255.0
        features[136] = data[ip_start + 13] / 255.0
        features[137] = data[ip_start + 14] / 255.0
        features[138] = data[ip_start + 15] / 255.0

        # Dest IP bytes
        features[139] = data[ip_start + 16] / 255.0
        features[140] = data[ip_start + 17] / 255.0
        features[141] = data[ip_start + 18] / 255.0
        features[142] = data[ip_start + 19] / 255.0

    # TCP/UDP port features (features 146-149)
    if pkt_len >= 38:
        tp_start = 34
        features[146] = (int(data[tp_start]) << 8 | int(data[tp_start + 1])) / 65535.0   # src port
        features[147] = (int(data[tp_start + 2]) << 8 | int(data[tp_start + 3])) / 65535.0  # dst port

    # TCP flags (feature 150) — if TCP
    if pkt_len >= 48 and data[23] == 6:   # protocol = TCP
        features[150] = data[47] / 255.0  # TCP flags byte

    # Remaining features (151..255) are zero-padded for future use

    return features

# ============================================================
# Binary Neural Network (training + quantization)
# ============================================================

class BinaryNeuralNetwork:
    """
    Binary Neural Network for packet classification.

    Training uses float32 weights with standard backprop.
    Inference (and FPGA deployment) uses sign-binarized weights:
        w_binary = sign(w_float)
    """

    def __init__(self):
        self.layers = []
        self._init_weights()
        self.train_X = []
        self.train_y = []

    def _init_weights(self):
        """Initialize float32 weight matrices."""
        sizes = [BNN_INPUT_SIZE] + BNN_HIDDEN_SIZES + [BNN_OUTPUT_SIZE]
        self.layers = []
        rng = np.random.default_rng(42)
        for i in range(len(sizes) - 1):
            fan_in = sizes[i]
            scale = np.sqrt(2.0 / fan_in)
            W = rng.normal(0, scale, (sizes[i], sizes[i + 1])).astype(np.float32)
            b = np.zeros(sizes[i + 1], dtype=np.float32)
            self.layers.append({"W": W, "b": b})

    def _sign_activation(self, x):
        """Binary activation: +1 if x >= 0, -1 otherwise."""
        return np.where(x >= 0, 1.0, -1.0).astype(np.float32)

    def _forward(self, X):
        """Forward pass with binary activations (STE for training)."""
        activations = [X]
        z_list = []
        out = X
        for i, layer in enumerate(self.layers):
            z = out @ layer["W"] + layer["b"]
            z_list.append(z)
            if i < len(self.layers) - 1:
                out = self._sign_activation(z)
            else:
                # Output layer uses sigmoid for probability
                out = 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))
            activations.append(out)
        return activations, z_list

    def _backward(self, activations, z_list, y):
        """
        Backward pass using Straight-Through Estimator (STE).

        The STE passes gradients through the sign function unchanged
        when |z| <= 1, zero otherwise.
        """
        m = y.shape[0]
        # Output layer gradient (binary cross-entropy)
        dz = activations[-1] - y
        grads = []

        for i in range(len(self.layers) - 1, -1, -1):
            dW = activations[i].T @ dz / m
            db = np.mean(dz, axis=0)
            grads.insert(0, {"dW": dW, "db": db})

            if i > 0:
                dz = dz @ self.layers[i]["W"].T
                # STE: pass gradient through where |z| <= 1
                ste_mask = (np.abs(z_list[i - 1]) <= 1.0).astype(np.float32)
                dz = dz * ste_mask

        return grads

    def add_sample(self, features, label):
        """
        Add a labeled sample to the training buffer.

        Args:
            features: numpy array of shape (BNN_INPUT_SIZE,)
            label: 0 = benign, 1 = malicious
        """
        self.train_X.append(features)
        y = np.zeros(BNN_OUTPUT_SIZE, dtype=np.float32)
        y[label] = 1.0
        self.train_y.append(y)

    def sample_count(self):
        return len(self.train_X)

    def train(self, epochs=50):
        """Train the BNN on accumulated samples."""
        if len(self.train_X) < 2:
            logging.warning("not enough samples to train (%d)", len(self.train_X))
            return

        X = np.array(self.train_X, dtype=np.float32)
        y = np.array(self.train_y, dtype=np.float32)
        n_samples = X.shape[0]

        logging.info("training BNN: %d samples, %d epochs", n_samples, epochs)

        for epoch in range(epochs):
            # Mini-batch SGD
            indices = np.random.permutation(n_samples)
            total_loss = 0.0
            n_batches = 0

            for start in range(0, n_samples, BNN_BATCH_SIZE):
                end = min(start + BNN_BATCH_SIZE, n_samples)
                batch_idx = indices[start:end]
                X_batch = X[batch_idx]
                y_batch = y[batch_idx]

                activations, z_list = self._forward(X_batch)
                grads = self._backward(activations, z_list, y_batch)

                # Update weights
                for i, layer in enumerate(self.layers):
                    layer["W"] -= BNN_LEARNING_RATE * grads[i]["dW"]
                    layer["b"] -= BNN_LEARNING_RATE * grads[i]["db"]
                    # Clip weights to [-1, 1] for better binarization
                    layer["W"] = np.clip(layer["W"], -1.0, 1.0)

                # Cross-entropy loss
                pred = activations[-1]
                loss = -np.mean(y_batch * np.log(pred + 1e-10) +
                                (1 - y_batch) * np.log(1 - pred + 1e-10))
                total_loss += loss
                n_batches += 1

            avg_loss = total_loss / max(n_batches, 1)
            if (epoch + 1) % 10 == 0 or epoch == 0:
                logging.info("  epoch %d/%d  loss=%.4f", epoch + 1, epochs, avg_loss)

        # Clear training buffer after successful training
        self.train_X.clear()
        self.train_y.clear()
        logging.info("training complete")

    def get_binary_weights(self):
        """
        Quantize weights to binary and pack into 32-bit words.

        Returns a list of (layer_idx, offset, data_u32) tuples
        ready for FPGA programming.
        """
        weight_words = []

        for layer_idx, layer in enumerate(self.layers):
            W = layer["W"]
            # Binarize: sign(w) -> +1/-1 -> 1/0 bit
            W_bin = (np.sign(W) >= 0).astype(np.uint8)

            # Pack into 32-bit words (row-major)
            flat = W_bin.flatten()
            n_words = (len(flat) + 31) // 32

            for word_idx in range(n_words):
                start = word_idx * 32
                end = min(start + 32, len(flat))
                bits = flat[start:end]

                word = 0
                for bit_pos, bit_val in enumerate(bits):
                    word |= (int(bit_val) << bit_pos)

                if word_idx <= 0xFFFF:
                    weight_words.append((layer_idx, word_idx, word))

        logging.info("quantized %d layers -> %d weight words",
                     len(self.layers), len(weight_words))
        return weight_words

    def predict(self, features):
        """Run inference and return (class, confidence)."""
        X = features.reshape(1, -1)
        activations, _ = self._forward(X)
        probs = activations[-1][0]
        cls = int(np.argmax(probs))
        return cls, float(probs[cls])

# ============================================================
# FPGA interface
# ============================================================

class FPGAInterface:
    """Interface to the FPGA via /dev/ngfw0 ioctls."""

    def __init__(self, dev_path):
        self.dev_path = dev_path
        self.fd = None

    def open(self):
        self.fd = os.open(self.dev_path, os.O_RDWR)
        logging.info("opened %s (fd=%d)", self.dev_path, self.fd)

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def load_bnn_weight(self, layer, offset, data):
        """Write a single BNN weight word to FPGA BRAM."""
        w = BnnWeightLoad()
        w.layer = layer
        w.offset = offset & 0xFFFF
        w.data = data & 0xFFFFFFFF
        try:
            fcntl.ioctl(self.fd, NGFW_IOC_BNN_LOAD, w)
        except OSError as e:
            logging.error("BNN_LOAD failed (layer=%d off=%d): %s",
                          layer, offset, e)
            raise

    def load_all_weights(self, weight_words):
        """
        Load all binary weights to FPGA.

        Args:
            weight_words: list of (layer, offset, data_u32) from
                          BinaryNeuralNetwork.get_binary_weights()
        """
        logging.info("loading %d weight words to FPGA...", len(weight_words))
        t0 = time.monotonic()

        for layer, offset, data in weight_words:
            self.load_bnn_weight(layer, offset, data)

        elapsed = time.monotonic() - t0
        logging.info("weight load complete (%.2f s, %.0f words/s)",
                     elapsed, len(weight_words) / max(elapsed, 0.001))

    def read_engine_stats(self):
        """Read ML inference engine statistics."""
        st = EngineStats()
        st.engine_id = NGFW_TBL_ML_INFERENCE
        try:
            fcntl.ioctl(self.fd, NGFW_IOC_ENGINE_STATS, st)
            return {
                "packets": st.packets,
                "matches": st.matches,
                "drops":   st.drops,
                "errors":  st.errors,
            }
        except OSError as e:
            logging.warning("ENGINE_STATS failed: %s", e)
            return None

# ============================================================
# QDMA C2H reader (suspicious packet punt path)
# ============================================================

class QDMAReader:
    """
    Read packets from QDMA C2H channel.

    The FPGA punts packets that the BNN classified as suspicious
    (confidence below threshold) to the C2H channel for deeper
    analysis by this agent.

    Packet format on C2H:
      [0:7]   = metadata (port_id, engine_id, bnn_score, flags)
      [8:end] = raw Ethernet frame
    """

    METADATA_SIZE = 8

    def __init__(self, qdma_path):
        self.qdma_path = qdma_path
        self.fd = None

    def open(self):
        try:
            self.fd = os.open(self.qdma_path, os.O_RDONLY | os.O_NONBLOCK)
            logging.info("opened QDMA C2H: %s", self.qdma_path)
        except OSError as e:
            logging.warning("cannot open %s: %s (running without punt path)",
                            self.qdma_path, e)
            self.fd = None

    def close(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def read_packet(self):
        """
        Read one punted packet.

        Returns (metadata_dict, raw_frame) or (None, None) if no
        packet is available.
        """
        if self.fd is None:
            return None, None

        try:
            buf = os.read(self.fd, 2048)
        except BlockingIOError:
            return None, None
        except OSError as e:
            logging.error("QDMA read error: %s", e)
            return None, None

        if len(buf) < self.METADATA_SIZE + 14:
            return None, None

        # Parse metadata header
        meta_raw = buf[:self.METADATA_SIZE]
        port_id, engine_id, bnn_score, flags = struct.unpack("<BBHi", meta_raw)

        metadata = {
            "port_id":   port_id,
            "engine_id": engine_id,
            "bnn_score": bnn_score,
            "flags":     flags,
        }

        raw_frame = buf[self.METADATA_SIZE:]
        return metadata, raw_frame

# ============================================================
# Main agent
# ============================================================

class WildFireAgent:
    """Main agent coordinating packet analysis and BNN updates."""

    def __init__(self, args):
        self.fpga = FPGAInterface(args.dev)
        self.qdma = QDMAReader(args.qdma)
        self.hashdb = HashDB(args.hashdb)
        # Canonical threat DB: lookups + verdict feedback persistence.
        self.threatdb = None
        if ThreatDB is not None:
            try:
                self.threatdb = ThreatDB(getattr(args, "threatdb", THREATDB_DEFAULT))
                # One-time seed: fold the legacy flat-file hashes into the DB.
                seeded = 0
                for h in self.hashdb.hashes:
                    try:
                        self.threatdb.record_sample(h, "malware", source="hashdb-import")
                        seeded += 1
                    except ValueError:
                        pass  # not a 64-hex sha256 -- skip
                logging.info("threat DB ready: %s (seeded %d from flat file)",
                             getattr(args, "threatdb", THREATDB_DEFAULT), seeded)
            except Exception as e:
                logging.warning("threat DB unavailable (%s) -- flat-file only", e)
                self.threatdb = None
        self.bnn = BinaryNeuralNetwork()
        self.retrain_interval = args.interval
        self.min_samples = args.min_samples
        self.running = True
        self.total_analyzed = 0
        self.total_malicious = 0
        self.total_benign = 0
        self.last_retrain = time.monotonic()

    def start(self):
        self.fpga.open()
        self.qdma.open()
        logging.info("WildFire agent started")
        logging.info("  retrain interval: %d s", self.retrain_interval)
        logging.info("  min samples: %d", self.min_samples)

        # Log initial engine stats
        stats = self.fpga.read_engine_stats()
        if stats:
            logging.info("  ML engine stats: pkts=%d matches=%d drops=%d errors=%d",
                         stats["packets"], stats["matches"],
                         stats["drops"], stats["errors"])

    def stop(self):
        logging.info("WildFire agent stopping (analyzed=%d malicious=%d benign=%d)",
                     self.total_analyzed, self.total_malicious, self.total_benign)
        self.qdma.close()
        self.fpga.close()
        if self.threatdb is not None:
            self.threatdb.close()

    def analyze_packet(self, metadata, raw_frame):
        """
        Analyze a single suspicious packet.

        Steps:
          1. Extract features
          2. Check file hash DB
          3. Run local BNN prediction
          4. Determine final verdict
          5. Add labeled sample to training buffer
        """
        self.total_analyzed += 1

        features = extract_features(raw_frame)

        # Hash the frame once; consult both the legacy flat file and the
        # canonical threat DB (definitive if either says known-bad).
        frame_sha = hashlib.sha256(raw_frame).hexdigest()
        is_known_bad = self.hashdb.is_known_malicious(raw_frame)
        if not is_known_bad and self.threatdb is not None:
            is_known_bad = self.threatdb.is_malicious_hash(frame_sha)

        # Run local BNN prediction
        cls, confidence = self.bnn.predict(features)

        # Determine final label
        if is_known_bad:
            label = 1   # malicious
            verdict = "MALICIOUS (hash match)"
        elif cls == 1 and confidence > 0.8:
            label = 1   # malicious
            verdict = "MALICIOUS (BNN %.2f)" % confidence
        elif cls == 0 and confidence > 0.9:
            label = 0   # benign
            verdict = "BENIGN (BNN %.2f)" % confidence
        else:
            # Low confidence — use FPGA's original score as tiebreaker
            fpga_score = metadata.get("bnn_score", 0)
            if fpga_score > 128:
                label = 1
                verdict = "SUSPICIOUS->MALICIOUS (FPGA=%d)" % fpga_score
            else:
                label = 0
                verdict = "SUSPICIOUS->BENIGN (FPGA=%d)" % fpga_score

        if label == 1:
            self.total_malicious += 1
            # WildFire feedback loop: persist newly discovered bad content so
            # the compiler can push it to the FPGA MALWARE region and the next
            # occurrence matches in hardware (not just in this agent).
            if self.threatdb is not None and not is_known_bad:
                try:
                    self.threatdb.record_sample(
                        frame_sha, "malware",
                        threat_name="agent.heuristic", source="agent")
                except Exception as e:
                    logging.debug("threatdb record failed: %s", e)
        else:
            self.total_benign += 1

        # Log verdict
        logging.info("verdict: %s port=%d len=%d",
                     verdict, metadata.get("port_id", -1), len(raw_frame))

        # Add to training buffer
        self.bnn.add_sample(features, label)

    def maybe_retrain(self):
        """
        Check if it is time to retrain the BNN and reload weights.

        Retraining happens when:
          - Enough new samples have accumulated (>= min_samples)
          - Enough time has passed since last retrain (>= interval)
        """
        now = time.monotonic()
        elapsed = now - self.last_retrain

        if (self.bnn.sample_count() >= self.min_samples and
                elapsed >= self.retrain_interval):
            logging.info("retraining BNN (%d samples, %.0f s since last)",
                         self.bnn.sample_count(), elapsed)

            self.bnn.train(epochs=50)
            weights = self.bnn.get_binary_weights()
            self.fpga.load_all_weights(weights)
            self.last_retrain = now

            # Log updated engine stats
            stats = self.fpga.read_engine_stats()
            if stats:
                logging.info("post-retrain ML stats: pkts=%d matches=%d",
                             stats["packets"], stats["matches"])

    def run(self):
        """Main loop: read packets, analyze, retrain periodically."""
        self.start()

        while self.running:
            metadata, raw_frame = self.qdma.read_packet()

            if metadata is not None and raw_frame is not None:
                self.analyze_packet(metadata, raw_frame)
                self.maybe_retrain()
            else:
                # No packet available — sleep briefly to avoid busy-wait
                time.sleep(0.01)

                # Still check retrain timer even without new packets
                self.maybe_retrain()

        self.stop()

# ============================================================
# Signal handling
# ============================================================

agent_instance = None

def signal_handler(signum, frame):
    logging.info("received signal %d, shutting down", signum)
    if agent_instance:
        agent_instance.running = False

# ============================================================
# Entry point
# ============================================================

def main():
    global agent_instance

    parser = argparse.ArgumentParser(
        description="FFN NGFW WildFire ML Model Update Agent")
    parser.add_argument("--dev", default="/dev/ngfw0",
                        help="FPGA device path (default: /dev/ngfw0)")
    parser.add_argument("--qdma", default="/dev/qdma0-c2h-0",
                        help="QDMA C2H device for punted packets")
    parser.add_argument("--hashdb", default="/var/lib/ngfw/hashes.db",
                        help="Path to known-bad file hash database (legacy flat file)")
    parser.add_argument("--threatdb", default=THREATDB_DEFAULT,
                        help="Path to the canonical threat-intelligence DB (SQLite)")
    parser.add_argument("--interval", type=int, default=300,
                        help="Minimum seconds between retrains (default: 300)")
    parser.add_argument("--min-samples", type=int, default=100,
                        help="Minimum samples before retraining (default: 100)")
    parser.add_argument("--debug", action="store_true",
                        help="Enable debug logging")
    args = parser.parse_args()

    # Configure logging — syslog + stderr in debug mode
    log_level = logging.DEBUG if args.debug else logging.INFO
    logger = logging.getLogger()
    logger.setLevel(log_level)

    # Syslog handler
    try:
        syslog_handler = logging.handlers.SysLogHandler(
            address="/dev/log", facility=logging.handlers.SysLogHandler.LOG_DAEMON)
        syslog_handler.setFormatter(
            logging.Formatter("ffn_wildfire: %(levelname)s %(message)s"))
        logger.addHandler(syslog_handler)
    except OSError:
        # /dev/log may not exist on all systems
        pass

    # Console handler (always in debug, stderr only otherwise)
    if args.debug:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(console)

    logging.info("FFN WildFire agent starting")
    logging.info("  device:    %s", args.dev)
    logging.info("  qdma:      %s", args.qdma)
    logging.info("  hashdb:    %s", args.hashdb)
    logging.info("  interval:  %d s", args.interval)
    logging.info("  min-samp:  %d", args.min_samples)

    # Install signal handlers
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT,  signal_handler)

    # Create and run agent
    agent_instance = WildFireAgent(args)
    try:
        agent_instance.run()
    except KeyboardInterrupt:
        agent_instance.running = False
        agent_instance.stop()
    except Exception:
        logging.exception("fatal error in WildFire agent")
        if agent_instance:
            agent_instance.stop()
        sys.exit(1)

    logging.info("FFN WildFire agent exited cleanly")


if __name__ == "__main__":
    main()
