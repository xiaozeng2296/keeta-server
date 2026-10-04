#!/usr/bin/env python3
"""Offline a2 verification with sequence sourced independently from decrypted a5."""

import argparse
from collections import Counter
import hashlib
import hmac
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import keeta_a2 as A2
from farm.fullsign import K1, decode_a5, hmac_key, k2buf


def pass2(prefix, mask, sequence):
    """Reference recovered tail; sequence is distinct from the a10 key byte."""
    o = prefix
    b9 = mask[0] ^ o[0] ^ o[7] ^ (sequence & 255)
    b10 = o[1] ^ o[6] ^ mask[1] ^ ((sequence >> 8) & 255)
    b11 = o[2] ^ o[5] ^ mask[2] ^ ((sequence >> 16) & 255)
    b12 = o[3] ^ o[4] ^ mask[3] ^ ((sequence >> 24) & 255)
    b13 = (o[3] ^ o[4] ^ mask[4]) & 0x7e
    b14 = 0x02 | ((mask[5] ^ o[4] ^ o[5]) & 0xbd)
    b15 = 0x20 | ((mask[6] ^ o[5] ^ o[6]) & 0xdb)
    b8 = b9 ^ b10 ^ b11 ^ b12 ^ b13 ^ b14 ^ b15 ^ mask[15]
    return bytes((b8, b9, b10, b11, b12, b13, b14, b15))


def samples(data):
    if isinstance(data, dict) and "msg_hex" in data:
        yield 0, data["mtgsig"], bytes.fromhex(data["msg_hex"]), data.get("K")
        return
    if not isinstance(data, list):
        raise ValueError("expected a msg_hex object or a Charles flow array")
    for index, flow in enumerate(data):
        request = flow.get("request") or {}
        headers = (request.get("header") or {}).get("headers", [])
        by_name = {h["name"].lower(): h["value"] for h in headers}
        for header in headers:
            if header.get("name", "").lower() != "mtgsig":
                continue
            mt = json.loads(header["value"])
            if not isinstance(mt.get("a2"), str):
                continue
            payload = {key: value for key, value in mt.items() if key != "a2"}
            host = by_name.get(":authority") or by_name.get("host") or flow["host"]
            url = flow["scheme"] + "://" + host + flow["path"]
            if flow.get("query"):
                if "?" not in flow["path"]:
                    url += "?" + flow["query"]
                elif flow["path"].split("?", 1)[1] != flow["query"]:
                    raise ValueError("ambiguous captured query")
            body_data = request.get("body") or {}
            if body_data and "text" not in body_data:
                raise ValueError("explicit UTF-8 body text required; encoded bodies are not reconstructed")
            body = body_data.get("text", "")
            # Independently apply the body byte limit observed in the native
            # message copies; canonical URL and payload remain complete.
            message = (A2.canonicalString(flow["method"], url).encode("utf-8") + body.encode("utf-8")[:16200] +
                       json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            yield index, mt, message, None


def verify(path):
    raw = path.read_bytes()
    counts = Counter()
    profiles = Counter()
    a10_values = set()
    sequences = []
    failed = []
    for index, mt, message, captured_key in samples(json.loads(raw)):
        counts["samples"] += 1
        expected = bytes.fromhex(mt["a2"])
        if len(expected) != 16:
            raise ValueError("a2 must contain exactly 16 bytes")
        plain, profile = decode_a5(mt["a5"], mt["a1"], mt["a3"], mt["a4"])
        collect = json.loads(plain)
        # Crucial: no bytes of expected a2 are used to select this sequence.
        sequence = collect["b2"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("a5.b2 is not an integer sequence")
        mask = k2buf(mt["a1"], profile)
        counter = int(mt["a10"].split(",")[1])
        key = hmac_key(counter, mt["a1"])
        if captured_key is not None:
            counts["captured_hmac_key_match"] += key.hex() == captured_key
        digest = hmac.new(key, message, hashlib.sha1).digest()[:16]
        sub = A2.a2Substitute(A2.a2Mix(digest))
        prefix = bytes(((sub[i] + digest[i]) & 255) ^ K1[i] ^ mask[i] for i in range(8))
        predicted = prefix + pass2(prefix, mask, sequence)
        # Tail-only check isolates pass2 from canonical/body/prefix differences.
        counts["tail_from_captured_prefix_match"] += (
            pass2(expected[:8], mask, sequence) == expected[8:])
        counts["prefix_match"] += prefix == expected[:8]
        counts["full_a2_match"] += predicted == expected
        counts["b17_equals_b2"] += collect.get("b17") == sequence
        counts["b18_equals_b2"] += collect.get("b18") == sequence
        counts["b3_equals_b2"] += collect.get("b3") == sequence
        profiles[profile] += 1
        a10_values.add(mt["a10"])
        sequences.append(sequence)
        if predicted != expected:
            failed.append(index)
    if not sequences:
        raise ValueError("no verifiable a2 samples")
    return {"source": str(path), "sha256": hashlib.sha256(raw).hexdigest(),
            "counts": dict(counts), "profiles": dict(profiles),
            "a10_distinct": len(a10_values), "a10_values": sorted(a10_values),
            "sequence_min": min(sequences), "sequence_max": max(sequences),
            "failed_capture_indices": failed}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sources", type=Path, nargs="+")
    args = parser.parse_args()
    try:
        rows = [verify(path) for path in args.sources]
    except (ValueError, KeyError, TypeError, OSError) as exc:
        print("Input validation failed (" + type(exc).__name__ + "); no complete report produced.", file=sys.stderr)
        return 2
    print(json.dumps({"sequence_source": "decrypted a5.b2 (not extracted from expected a2)",
                      "sources": rows}, ensure_ascii=False, indent=2))
    return int(any(row["failed_capture_indices"] for row in rows))


if __name__ == "__main__":
    raise SystemExit(main())
