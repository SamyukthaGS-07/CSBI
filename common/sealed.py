"""
common.sealed
=============
Encrypts captured phishing HTML so it can be stored as a GitHub Actions
artifact on a public repository without republishing live phishing kits.

Hybrid encryption:
  * a fresh random Fernet key (AES-128-CBC + HMAC-SHA256) encrypts the tar.gz
  * that key is wrapped with RSA-OAEP(SHA-256) under keys/snapshots_public.pem

Only the holder of the matching private key can open an archive:

    python scripts/unseal_snapshots.py --key path/to/snapshots_private.pem archives/*.sealed

File layout:  b"CSBI1" | 2-byte len(wrapped key) | wrapped key | Fernet token
"""
from __future__ import annotations

import io
import struct
import tarfile
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

MAGIC = b"CSBI1"
_OAEP = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def seal_files(files: dict[str, bytes], public_key_pem: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    key = Fernet.generate_key()
    token = Fernet(key).encrypt(buf.getvalue())
    pub = serialization.load_pem_public_key(public_key_pem)
    wrapped = pub.encrypt(key, _OAEP)
    return MAGIC + struct.pack(">H", len(wrapped)) + wrapped + token


def unseal(blob: bytes, private_key_pem: bytes) -> dict[str, bytes]:
    if not blob.startswith(MAGIC):
        raise ValueError("not a CSBI sealed archive")
    n = struct.unpack(">H", blob[5:7])[0]
    wrapped, token = blob[7:7 + n], blob[7 + n:]
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    raw = Fernet(priv.decrypt(wrapped, _OAEP)).decrypt(token)
    out = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
        for m in tar.getmembers():
            if m.isfile():
                out[m.name] = tar.extractfile(m).read()
    return out


def public_key_path() -> Path:
    return Path(__file__).resolve().parent.parent / "keys" / "snapshots_public.pem"
