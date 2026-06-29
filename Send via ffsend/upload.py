#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "cryptography",
# ]
# ///
from __future__ import annotations

import base64
import json
import mimetypes
import os
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SEND_SERVER = os.environ.get("SEND_SERVER", "https://send.willner.ws")
DEFAULT_DLIMIT = int(os.environ.get("SEND_DLIMIT", "3"))

NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 16
ECE_RECORD_SIZE = 65536


def hkdf_derive(ikm: bytes, info: bytes, length: int = 16) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=length,
        salt=None,
        info=info,
    )
    return hkdf.derive(ikm)


def ece_derive_key(ikm: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=16,
        salt=salt,
        info=b"Content-Encoding: aes128gcm\x00",
    )
    return hkdf.derive(ikm)


def ece_derive_nonce_base(ikm: bytes, salt: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=SHA256(),
        length=16,
        salt=salt,
        info=b"Content-Encoding: nonce\x00",
    )
    return hkdf.derive(ikm)[:NONCE_LEN]


def xor_nonce(nonce_base: bytes, seq: int) -> bytes:
    result = bytearray(nonce_base)
    m = int.from_bytes(result[-4:], "big")
    result[-4:] = (m ^ seq).to_bytes(4, "big")
    return bytes(result)


def ece_encrypt(plaintext: bytes, ikm: bytes, rs: int = ECE_RECORD_SIZE) -> bytes:
    salt = os.urandom(KEY_LEN)
    key = ece_derive_key(ikm, salt)
    nonce_base = ece_derive_nonce_base(ikm, salt)

    header = salt + struct.pack(">I", rs) + struct.pack("B", 0)

    records = []
    offset = 0
    seq = 0
    max_data = rs - TAG_LEN - 1
    while offset < len(plaintext):
        chunk = plaintext[offset : offset + max_data]
        is_last = (offset + len(chunk)) >= len(plaintext)

        if is_last:
            padded = chunk + b"\x02"
        else:
            pad_len = rs - TAG_LEN - len(chunk)
            padded = chunk + b"\x01" + b"\x00" * (pad_len - 1)

        nonce = xor_nonce(nonce_base, seq)
        aesgcm = AESGCM(key)
        encrypted = aesgcm.encrypt(nonce, padded, None)
        records.append(encrypted)
        offset += len(chunk)
        seq += 1

    return header + b"".join(records)


def encrypt_metadata(meta_key: bytes, metadata: dict) -> bytes:
    aesgcm = AESGCM(meta_key)
    iv = b"\x00" * NONCE_LEN
    plaintext = json.dumps(metadata).encode("utf-8")
    return aesgcm.encrypt(iv, plaintext, None)


def upload_file(file_path: str) -> str:
    path = Path(file_path)
    if not path.is_file():
        print(f"Error: {file_path} is not a file", file=sys.stderr)
        sys.exit(1)

    file_size = path.stat().st_size
    file_name = path.name
    mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"

    secret = os.urandom(16)

    meta_key = hkdf_derive(secret, b"metadata")
    auth_key = hkdf_derive(secret, b"authentication", length=64)

    metadata = {
        "name": file_name,
        "size": file_size,
        "type": mime_type,
        "manifest": {"files": [{"name": file_name, "size": file_size}]},
    }
    encrypted_meta = encrypt_metadata(meta_key, metadata)
    meta_b64 = base64.b64encode(encrypted_meta).decode("ascii")

    auth_key_b64 = base64.b64encode(auth_key).decode("ascii")

    plaintext = path.read_bytes()
    encrypted_data = ece_encrypt(plaintext, secret)

    req = urllib.request.Request(
        f"{SEND_SERVER}/api/upload",
        data=encrypted_data,
        headers={
            "X-File-Metadata": meta_b64,
            "Authorization": f"send-v1 {auth_key_b64}",
            "Content-Type": "application/octet-stream",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"Upload failed ({e.code}): {body}", file=sys.stderr)
        sys.exit(1)

    url = result["url"]
    owner_token = result["owner"]
    file_id = result["id"]

    params_data = json.dumps({"owner_token": owner_token, "dlimit": DEFAULT_DLIMIT}).encode(
        "utf-8"
    )
    params_req = urllib.request.Request(
        f"{SEND_SERVER}/api/params/{file_id}",
        data=params_data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(params_req, timeout=30) as resp:
            if resp.status != 200:
                print(f"Warning: Failed to set download limit", file=sys.stderr)
    except urllib.error.HTTPError:
        print(f"Warning: Failed to set download limit", file=sys.stderr)

    secret_b64 = base64.b64encode(secret).decode("ascii")
    share_url = f"{url}#{secret_b64}"
    return share_url


def main():
    if len(sys.argv) < 2:
        print("Usage: upload.py <file>", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    print(f"Uploading {file_path} to {SEND_SERVER}...", file=sys.stderr)

    t0 = time.monotonic()
    share_url = upload_file(file_path)
    elapsed = time.monotonic() - t0

    print(f"Uploaded in {elapsed:.1f}s", file=sys.stderr)
    print(share_url, end="")


if __name__ == "__main__":
    main()
