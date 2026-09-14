"""Payload obfuscation chains — evasion research utilities.

Pure functions for encoding/decoding payloads through common chains
(base64, hex, URL, ROT13, XOR). Used in the evasion-research phase to
study how security tools flag (or miss) encoded payloads against your
own lab. Nothing here touches the network.
"""

from __future__ import annotations

import base64
import codecs
import urllib.parse


def b64(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def de_b64(payload: str) -> str:
    return base64.b64decode(payload.encode()).decode("utf-8", "replace")


def hexenc(payload: str) -> str:
    return payload.encode().hex()


def de_hex(payload: str) -> str:
    return bytes.fromhex(payload.strip()).decode("utf-8", "replace")


def urlenc(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def de_url(payload: str) -> str:
    return urllib.parse.unquote(payload)


def rot13(payload: str) -> str:
    return codecs.encode(payload, "rot_13")


def xor(payload: str, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(payload.encode()))


def de_xor(data: bytes, key: bytes) -> str:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data)).decode("utf-8", "replace")


CHAINS = {
    "plain": [lambda p: p],
    "url": [urlenc],
    "double-url": [urlenc, urlenc],
    "b64": [b64],
    "url-b64": [urlenc, b64],
    "b64-url": [b64, urlenc],
    "hex": [hexenc],
    "rot13": [rot13],
}


def encode_chain(payload: str, chain: str) -> str:
    """Apply a named encoding chain. Raises KeyError on unknown chain."""
    out = payload
    for fn in CHAINS[chain]:
        out = fn(out)
    return out


def describe(chain: str) -> str:
    names = {"b64": "base64", "url": "percent", "hex": "hex", "rot13": "ROT13"}
    return " -> ".join(names.get(c, c) for c in CHAINS[chain])  # type: ignore[arg-type]
