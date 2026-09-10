#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Offline end-to-end smoke test for the FFN threat-intel pipeline.

    threat feed --> ThreatDB --> BNN agent verdict --> ThreatDB
                                                              |
                                            export(MALWARE region) --> compiler input

Exercises the real code paths (ffn_threatdb.ThreatDB + ffn_bnn_agent.
BnnAgent.analyze_packet) with NO FPGA and NO network. The only stub is
the BNN prediction, pinned to low confidence so the FPGA-score tiebreaker is
the deterministic decision-maker (otherwise the randomly-initialised net makes
the verdict nondeterministic).

Run:  python ffn_pipeline_selftest.py
"""
import argparse
import hashlib
import sys


def main():
    from ffn_threatdb import NGFW_RGN_MALWARE
    import ffn_bnn_agent as bnn

    print("FFN threat-intel pipeline selftest")

    # Build the agent with NO hardware. FPGAInterface/QDMAReader are created but
    # never .open()'d, so no /dev access happens; threatdb is in-memory.
    args = argparse.Namespace(
        dev="/dev/null", qdma="/dev/null",
        hashdb="/nonexistent/hashes.db", threatdb=":memory:",
        interval=300, min_samples=100)
    agent = bnn.BnnAgent(args)
    assert agent.threatdb is not None, "ThreatDB must initialise"

    # Pin the BNN to a low-confidence benign guess so the deterministic path is
    # the FPGA-score tiebreaker (score > 128 => malicious).
    agent.bnn.predict = lambda feats: (0, 0.5)

    # 1. seed a known-bad hash through the feed path
    seeded = "d" * 64
    agent.threatdb.ingest_feed("malware_hashes", [seeded])
    assert agent.threatdb.is_malicious_hash(seeded)
    print("  [ok] feed-seeded hash is known-malicious")

    # 2. agent analyses an UNKNOWN frame the FPGA flagged (bnn_score=200)
    frame = bytes(range(256)) * 6          # 1536 deterministic bytes
    frame_sha = hashlib.sha256(frame).hexdigest()
    assert agent.threatdb.lookup_sample(frame_sha) is None, "frame must start unknown"
    meta = {"port_id": 1, "engine_id": 0x15, "bnn_score": 200, "flags": 0}
    agent.analyze_packet(meta, frame)

    # 3. the discovery is persisted as malware, attributed to the agent
    rec = agent.threatdb.lookup_sample(frame_sha)
    assert rec is not None and rec["verdict"] == "malware", "feedback not persisted: %r" % rec
    assert rec["source"] == "agent"
    assert agent.total_malicious == 1 and agent.total_analyzed == 1
    print("  [ok] agent persisted discovery %s.. as %s" % (frame_sha[:16], rec["verdict"]))

    # 4. export the MALWARE region -> contains BOTH the feed hash and the
    #    agent's discovery, ready for db_compiler -> FPGA DDR.
    exported = {v for (v, _fh, _act, _n) in agent.threatdb.export_region(NGFW_RGN_MALWARE)}
    assert seeded in exported and frame_sha in exported, "export missing entries: %r" % exported
    print("  [ok] MALWARE export has %d hashes incl. feed + discovery" % len(exported))

    # 5. the agent's lookup now short-circuits the SAME frame as known-bad
    #    (closing the loop: a second sighting is definitive, no re-analysis).
    assert agent.threatdb.is_malicious_hash(frame_sha)
    print("  [ok] second sighting of the discovery is now definitive")

    agent.stop()   # closes threatdb; fpga/qdma closes are no-ops (never opened)
    print("PIPELINE SELFTEST PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
