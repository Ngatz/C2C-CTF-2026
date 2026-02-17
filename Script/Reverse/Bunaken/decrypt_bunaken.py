#!/usr/bin/env python3
"""
============================================================
decrypt_bunaken.py
Dekripsi flag.txt.bunakencrypted dari CTF challenge "Bunaken"

Hasil deobfuscation:
  - Key       : "sulawesi"
  - Algoritma : AES-128-CBC
  - Key Deriv : SHA-256("sulawesi") → 16 byte pertama
  - Format    : base64( IV[16] || Ciphertext )
  - Compress  : Bun.zstdCompress() (Zstandard)

Dependency: openssl (sudah ada di Linux), python3 standard library
Jalankan  : python3 decrypt_bunaken.py
============================================================
"""

import base64
import hashlib
import subprocess
import tempfile
import os
import sys
import zlib

# ===== PARAMETER DARI DEOBFUSCATION =====
KEY_STRING     = "sulawesi"
ENCRYPTED_FILE = "flag.txt.bunakencrypted"


def derive_key(key_string: str) -> bytes:
    """
    Replika fungsi deriveKey() dari source code Bunaken.
    SHA-256(key_string) → ambil 16 byte pertama → AES-128 key
    """
    key_bytes = key_string.encode("utf-8")
    # "sulawesi" = 8 byte, bukan 16/24/32, jadi masuk ke branch SHA-256
    sha256_hash = hashlib.sha256(key_bytes).digest()
    return sha256_hash[:16]  # 16 byte = AES-128


def aes_cbc_decrypt_openssl(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    AES-128-CBC decrypt menggunakan openssl CLI.
    Tidak perlu pip install apapun.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp_in:
        tmp_in.write(ciphertext)
        tmp_in_path = tmp_in.name

    tmp_out_path = tmp_in_path + ".dec"

    try:
        cmd = [
            "openssl", "enc", "-d", "-aes-128-cbc",
            "-K", key.hex(),
            "-iv", iv.hex(),
            "-in", tmp_in_path,
            "-out", tmp_out_path,
        ]
        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            raise RuntimeError(f"openssl error: {result.stderr.decode()}")

        with open(tmp_out_path, "rb") as f:
            return f.read()
    finally:
        os.unlink(tmp_in_path)
        if os.path.exists(tmp_out_path):
            os.unlink(tmp_out_path)


def try_decompress(data: bytes) -> bytes:
    """
    Coba dekompresi. Source code menggunakan Bun.zstdCompress(),
    jadi data dikompresi dengan Zstandard.
    """
    methods = []

    # 1. Zstandard via python module (jika ada)
    try:
        import zstandard as zstd
        methods.append(("zstandard (python module)",
                        lambda d: zstd.ZstdDecompressor().decompress(d)))
    except ImportError:
        pass

    # 2. Zstandard via CLI tool
    def zstd_cli_decompress(d):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".zst") as tmp:
            tmp.write(d)
            tmp_path = tmp.name
        try:
            result = subprocess.run(
                ["zstd", "-d", tmp_path, "-o", tmp_path + ".out", "-f"],
                capture_output=True
            )
            if result.returncode != 0:
                raise RuntimeError(result.stderr.decode())
            with open(tmp_path + ".out", "rb") as f:
                return f.read()
        finally:
            for p in [tmp_path, tmp_path + ".out"]:
                if os.path.exists(p):
                    os.unlink(p)

    # Cek apakah zstd CLI tersedia
    zstd_available = subprocess.run(
        ["which", "zstd"], capture_output=True
    ).returncode == 0
    if zstd_available:
        methods.append(("zstd CLI tool", zstd_cli_decompress))

    # 3. Fallback: zlib, gzip, raw
    methods.extend([
        ("zlib decompress",        lambda d: zlib.decompress(d)),
        ("zlib raw (wbits=-15)",   lambda d: zlib.decompress(d, -15)),
        ("gzip (wbits=31)",        lambda d: zlib.decompress(d, 31)),
        ("raw (tanpa decompress)", lambda d: d),
    ])

    for name, fn in methods:
        try:
            result = fn(data)
            print(f"[+] Dekompresi berhasil: {name}")
            return result
        except Exception:
            print(f"[-] Dekompresi gagal  : {name}")

    return data


def main():
    print("=" * 55)
    print("  BUNAKEN CTF — Decryption Script (Python)")
    print("=" * 55)

    # 1. Baca file terenkripsi
    print(f"\n[*] Membaca {ENCRYPTED_FILE}...")
    try:
        with open(ENCRYPTED_FILE, "r") as f:
            raw = f.read().strip()
    except FileNotFoundError:
        print(f"[-] File '{ENCRYPTED_FILE}' tidak ditemukan!")
        print(f"    Pastikan file ada di direktori yang sama.")
        sys.exit(1)

    # 2. Base64 decode
    print("[*] Base64 decoding...")
    enc_buffer = base64.b64decode(raw)
    print(f"    Total encrypted data: {len(enc_buffer)} bytes")

    # 3. Pisahkan IV (16 byte pertama) dan ciphertext
    iv = enc_buffer[:16]
    ciphertext = enc_buffer[16:]
    print(f"    IV         (hex): {iv.hex()}")
    print(f"    Ciphertext size : {len(ciphertext)} bytes")

    # 4. Derive key: SHA-256("sulawesi") → 16 byte pertama
    print(f'\n[*] Deriving key: SHA-256("{KEY_STRING}") → 16 bytes...')
    key = derive_key(KEY_STRING)
    print(f"    Key (hex): {key.hex()}")
    print(f"    Key size : {len(key)} bytes → AES-{len(key)*8}")

    # 5. AES-128-CBC decrypt (via openssl)
    print("\n[*] AES-128-CBC decrypting (via openssl)...")
    try:
        decrypted = aes_cbc_decrypt_openssl(key, iv, ciphertext)
        print(f"    Decrypted size: {len(decrypted)} bytes")
    except Exception as e:
        print(f"[-] Dekripsi gagal: {e}")
        sys.exit(1)

    # 6. Dekompresi (Zstandard)
    print("\n[*] Mencoba dekompresi (source code pakai Bun.zstdCompress)...")
    result = try_decompress(decrypted)

    # 7. Output flag
    print("\n" + "=" * 55)
    print("  FLAG:")
    print("=" * 55)
    try:
        flag_text = result.decode("utf-8")
        print(flag_text)
    except UnicodeDecodeError:
        flag_text = result.decode("utf-8", errors="replace")
        print(flag_text)
        print("\n[!] Warning: ada byte non-UTF8, mungkin perlu")
        print("    metode dekompresi yang berbeda.")

    # 8. Simpan ke file
    with open("flag_decrypted.txt", "wb") as f:
        f.write(result)
    print(f"\n[+] Tersimpan di flag_decrypted.txt")


if __name__ == "__main__":
    main()
