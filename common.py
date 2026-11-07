"""Shared primitives: canonical JSON, Ed25519 keys, signing, small HTTP client."""
from __future__ import annotations

import hashlib
import json
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)


def canon(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def action_hash(action: dict) -> str:
    return hashlib.sha256(canon(action)).hexdigest()


# ---------------------------------------------------------------- keys
def new_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def pk_hex(sk: Ed25519PrivateKey) -> str:
    return sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def save_sk(sk: Ed25519PrivateKey, path: Path) -> None:
    path.write_bytes(sk.private_bytes(serialization.Encoding.Raw,
                                      serialization.PrivateFormat.Raw,
                                      serialization.NoEncryption()))


def load_sk(path: Path) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(path.read_bytes())


def sign(sk: Ed25519PrivateKey, obj) -> str:
    return sk.sign(canon(obj)).hex()


def verify(pk_hex_str: str, obj, sig_hex: str) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pk_hex_str)).verify(
            bytes.fromhex(sig_hex), canon(obj))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def pop_message(payload: dict, action: dict) -> dict:
    """What the holder signs to prove possession of the authorization."""
    return {"purpose": "apply", "nonce": payload["nonce"],
            "action_hash": action_hash(action)}


# ---------------------------------------------------------------- http
def post(url: str, body: dict, timeout: float = 2.0) -> dict:
    req = urllib.request.Request(url, data=canon(body), method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read() or b"{}")


def get(url: str, timeout: float = 2.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())
