#!/usr/bin/env python3
"""
Proof JWT generator (EdDSA/Ed25519)

Behavior:
- Reads challenge JSON from file (payload is NOT modified)
- Challenge JSON must include "did" (base DID, e.g. did:web:... or did:key:...)
- User provides --didKey (a DID URL, typically DID#fragment) which is used as JWT header "kid"
- Signs payload using Ed25519 (alg=EdDSA)
- Optional: sanity-check that didKey's base DID matches payload "did"
"""

import argparse
import json
from typing import Dict, Tuple

import base58
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


# -------------------------
# Multibase helpers
# -------------------------

def parse_uvarint(data: bytes) -> Tuple[int, int]:
    x = 0
    s = 0
    for i, b in enumerate(data):
        x |= (b & 0x7F) << s
        if (b & 0x80) == 0:
            return x, i + 1
        s += 7
    raise ValueError("Invalid varint")


def decode_multibase_base58btc(z_value: str) -> bytes:
    if not z_value.startswith("z"):
        raise ValueError("Expected multibase base58btc string starting with 'z'")
    return base58.b58decode(z_value[1:])


def extract_ed25519_seed_from_privateKey(private_key_multibase: str) -> bytes:
    raw = decode_multibase_base58btc(private_key_multibase.strip())

    # Common encodings seen in the wild
    if len(raw) == 32:
        return raw
    if len(raw) == 33 and raw[0] == 0x00:
        return raw[1:]
    if len(raw) == 34 and raw[0] == 0x00 and raw[1] == 0x20:
        return raw[2:]

    code, n = parse_uvarint(raw)
    if code == 0x1300 and len(raw) - n == 32:
        return raw[n:]

    raise ValueError("Unrecognized privateKey encoding")


# -------------------------
# Signing
# -------------------------

def sign_payload(privateKey: str, kid: str, payload_obj: Dict) -> str:
    seed = extract_ed25519_seed_from_privateKey(privateKey)
    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    headers = {
        "typ": "JWT",
        "alg": "EdDSA",
        "kid": kid,
    }

    token = jwt.encode(
        payload=payload_obj,
        key=private_key,
        algorithm="EdDSA",
        headers=headers,
    )

    if isinstance(token, bytes):
        token = token.decode("utf-8")

    return token


# -------------------------
# CLI
# -------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description="Sign a challenge JSON file as a Proof JWT.")

    ap.add_argument(
        "--privateKey",
        required=True,
        help="Ed25519 private seed (multibase base58btc, starts with 'z')",
    )

    ap.add_argument(
        "--didKey",
        required=True,
        help='DID URL for the signing key (used as JWT header "kid"), e.g. did:web:example.edu#key-1',
    )

    ap.add_argument(
        "--challengeFile",
        required=True,
        help='Path to challenge JSON file (must include "did")',
    )

    ap.add_argument(
        "--strictDidMatch",
        action="store_true",
        help="Fail if base DID from --didKey doesn't match payload 'did' (recommended).",
    )

    ap.add_argument("--out", default=None)

    args = ap.parse_args()

    with open(args.challengeFile, "r", encoding="utf-8") as f:
        payload_obj = json.load(f)

    if not isinstance(payload_obj, dict):
        raise SystemExit("Challenge payload must be a JSON object.")

    did_value = payload_obj.get("did")
    if not isinstance(did_value, str) or not did_value.strip():
        raise SystemExit('Challenge JSON must include a non-empty string field "did".')
    did_value = did_value.strip()

    did_key = args.didKey.strip()
    base_did_from_kid = did_key.split("#", 1)[0]

    if args.strictDidMatch and base_did_from_kid != did_value:
        raise SystemExit(
            "didKey base DID does not match challenge payload 'did'.\n"
            f"payload.did = {did_value}\n"
            f"didKey base  = {base_did_from_kid}\n"
            f"didKey       = {did_key}"
        )

    # IMPORTANT: Payload is NOT modified.
    token = sign_payload(privateKey=args.privateKey, kid=did_key, payload_obj=payload_obj)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(token)
        print(f"Wrote Proof JWT to: {args.out}")
    else:
        print(token)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
