#!/usr/bin/env python3
"""
============================================================
deobfuscate_bunaken.py
Ekstrak & deobfuscate source code dari binary CTF "Bunaken"
Jalankan: python3 deobfuscate_bunaken.py
============================================================
"""

import urllib.parse

# =====================
# BAGIAN 1: Replika fungsi obfuscation dari source code binary
# =====================

# Array string ter-obfuscate (copy exact dari binary)
string_array = [
    "WR0tF8oezmkl", "toString", "W603xSol", "1tlHJnY",
    "1209923ghGtmw", "text", "13820KCwBPf", "byteOffset",
    "40xRjnfn", "Cfa9", "bNaXh8oEW6OiW5FcIq", "alues",
    "lXNdTmoAgqS0pG", "D18RtemLWQhcLConW5a", "nCknW4vfbtX+",
    "WOZcIKj+WONdMq", "FCk1cCk2W7FcM8kdW4y",
    "a8oNWOjkW551fSk2sZVcNa", "yqlcTSo9xXNcIY9vW7dcS8ky", "from",
    "iSoTxCoMW6/dMSkXW7PSW4xdHaC", "c0ZcS2NdK37cM8o+mW",
    "377886jVoqYx", "417805ESwrVS", "7197AxJyfv",
    "cu7cTX/cMGtdJSowmSk4W5NdVCkl", "W7uTCqXDf0ddI8kEFW", "write",
    "encrypt", "ted", "xHxdQ0m", "byteLength", "6CCilXQ",
    "304OpHfOi", "set", "263564pSWjjv", "subtle", "945765JHdYMe",
    "SHA-256", "Bu7dQfxcU3K", "getRandomV"
]


def l(n):
    """Direct array access (offset 367)"""
    return string_array[n - 367]


def custom_base64_decode(encoded_str):
    """
    Custom base64 decoder (replika dari fungsi b() di JS)
    Menggunakan charset: a-z A-Z 0-9 + / =
    """
    charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
    result = ""
    d = 0
    o = 0
    p = 0

    while p < len(encoded_str):
        e_char = encoded_str[p]
        p += 1
        e = charset.find(e_char)
        if e == -1:
            continue
        if d % 4 != 0:
            o = o * 64 + e
        else:
            o = e
        if d % 4 != 0:
            char_code = (255 & (o >> (-2 * (d + 1) & 6)))
            result += chr(char_code)
        d += 1

    # URL encode lalu decode
    hex_str = ""
    for ch in result:
        hex_str += "%" + ("00" + format(ord(ch), 'x'))[-2:]
    return urllib.parse.unquote(hex_str)


def rc4_decrypt(data_str, key_str):
    """
    RC4 stream cipher (replika dari fungsi U() di JS)
    Digunakan untuk mendekripsi string-string ter-obfuscate
    """
    # Inisialisasi S-box
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + ord(key_str[i % len(key_str)])) % 256
        s[i], s[j] = s[j], s[i]

    # Decrypt
    i = 0
    j = 0
    result = ""
    for k in range(len(data_str)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        result += chr(ord(data_str[k]) ^ s[(s[i] + s[j]) % 256])

    return result


# Cache untuk c() results
c_cache = {}


def c(n, r):
    """
    RC4 string decoder (replika dari fungsi c() di JS)
    1. Custom base64 decode
    2. RC4 decrypt dengan key r
    """
    idx = n - 367
    cache_key = f"{idx}_{string_array[0]}"

    if cache_key in c_cache:
        return c_cache[cache_key]

    encoded = string_array[idx]
    decoded = custom_base64_decode(encoded)
    result = rc4_decrypt(decoded, r)
    c_cache[cache_key] = result
    return result


def js_parseInt(s):
    """
    Replika JavaScript parseInt().
    parseInt("1209923ghGtmw") → 1209923
    parseInt("text") → NaN (raise ValueError)
    """
    import re
    match = re.match(r'^[+-]?\d+', str(s))
    if match:
        return int(match.group())
    raise ValueError(f"Cannot parseInt: {s}")


def rotate_array():
    """
    Replika IIFE: rotate string_array sampai checksum === 105028
    Ini penting! Array HARUS dirotasi dulu sebelum decode string.
    """
    global string_array
    max_attempts = len(string_array) * 3  # safety limit

    for attempt in range(max_attempts):
        try:
            checksum = (
                js_parseInt(l(405)) / 1 * (js_parseInt(l(383)) / 2) +
                -js_parseInt(l(385)) / 3 * (js_parseInt(c(382, "9Dnx")) / 4) +
                js_parseInt(l(384)) / 5 * (-js_parseInt(l(393)) / 6) +
                js_parseInt(l(396)) / 7 * (js_parseInt(l(369)) / 8) +
                js_parseInt(c(381, "R69F")) / 9 +
                -js_parseInt(l(367)) / 10 +
                -js_parseInt(l(406)) / 11
            )
            if checksum == 105028:
                print(f"    (array dirotasi {attempt} kali)")
                return True
        except (ValueError, TypeError, IndexError):
            pass

        # Rotate: pindahkan elemen pertama ke akhir
        string_array.append(string_array.pop(0))
        # Reset cache karena array berubah
        c_cache.clear()

    return False


# =====================
# BAGIAN 2: Jalankan deobfuscation
# =====================

def main():
    print("=" * 65)
    print("  BUNAKEN CTF — Python Deobfuscation Script")
    print("=" * 65)

    # Step 1: Rotate array (WAJIB dilakukan pertama!)
    print("\n[*] Rotating string array (target checksum: 105028)...")
    if rotate_array():
        print("[+] Array rotation berhasil!")
    else:
        print("[-] GAGAL rotate array! Hasil mungkin salah.")
        return

    # Step 2: Decode semua string via l() (direct access)
    print("\n[*] Decoded strings via l() [direct array access]:\n")
    for idx in range(367, 408):
        try:
            val = l(idx)
            print(f"    l({idx}) = \"{val}\"")
        except (IndexError, Exception):
            pass

    # Step 3: Decode string via c() (RC4)
    print("\n[*] Decoded strings via c() [RC4 decrypted]:\n")
    c_calls = [
        (370, "CYgn"), (371, "kAmA"), (373, "rG]G"), (374, "CYgn"),
        (375, "dHTh"), (376, "$lpa"), (377, "R69F"), (381, "R69F"),
        (382, "9Dnx"), (387, "f]pG"), (391, "9Dnx"), (394, "R69F"),
        (398, "f]pG"), (400, "I2yl"), (402, "Fw]1"), (404, "(Y*]"),
    ]
    for idx, key in c_calls:
        try:
            val = c(idx, key)
            print(f"    c({idx}, \"{key}\") = \"{val}\"")
        except Exception as e:
            print(f"    c({idx}, \"{key}\") = [ERROR: {e}]")

    # Step 4: Ekstrak parameter enkripsi
    print("\n" + "=" * 65)
    print("  ENCRYPTION PARAMETERS")
    print("=" * 65)

    try:
        KEY_STRING = c(373, "rG]G")
        FILE_METHOD = c(391, "9Dnx")
        FILENAME = c(377, "R69F")
        COMPRESS_FN = c(387, "f]pG") + "ss"
        OUTPUT_ENC = c(376, "$lpa")
        OUTPUT_EXT = c(374, "CYgn")
        IMPORT_FMT = c(370, "CYgn")
        ALGO_NAME = c(375, "dHTh")
        DIGEST_ALGO = l(399)
        ENCRYPT_OP = l(389)
        WRITE_FN = l(388)
        TEXT_FN = l(407)

        print(f"""
  Key (hardcoded) : "{KEY_STRING}"
  Algorithm       : {ALGO_NAME}
  Key Derivation  : {DIGEST_ALGO}("{KEY_STRING}") → first 16 bytes
  IV              : 16 bytes random, prepended to ciphertext
  Output Encoding : {OUTPUT_ENC}
  Pre-processing  : Bun.{COMPRESS_FN}() sebelum enkripsi
  Input file      : {FILENAME}
  Output file     : flag.txt.{OUTPUT_EXT}{l(390)}
        """)

        # Step 5: Rekonstruksi source code readable
        print("=" * 65)
        print("  RECONSTRUCTED SOURCE CODE (Readable)")
        print("=" * 65)
        print(f"""
// ======= BUNAKEN — Deobfuscated =======

const deriveKey = async (keyInput) => {{
    let keyBytes = new Uint8Array(keyInput);
    if (keyBytes.byteLength === 16 || keyBytes.byteLength === 24 || keyBytes.byteLength === 32)
        return keyBytes;
    let hash = await crypto.subtle.digest("{DIGEST_ALGO}", keyBytes);
    return new Uint8Array(hash).subarray(0, 16);
}};

const concat = (a, b) => {{
    let result = new Uint8Array(a.byteLength + b.byteLength);
    result.set(a, 0);
    result.set(b, a.byteLength);
    return result;
}};

const encryptData = async (key, plaintext) => {{
    let iv = crypto.getRandomValues(new Uint8Array(16));
    let derivedKey = await deriveKey(key);
    let cryptoKey = await crypto.subtle.importKey(
        "{IMPORT_FMT}", derivedKey, {{ name: "{ALGO_NAME}" }}, false, ["{ENCRYPT_OP}"]
    );
    let encrypted = await crypto.subtle.encrypt(
        {{ name: "{ALGO_NAME}", iv: iv }}, cryptoKey, plaintext
    );
    return concat(iv, new Uint8Array(encrypted));
}};

// === MAIN ===
var fileHandle  = Bun.{FILE_METHOD}("{FILENAME}");
var textContent = await fileHandle.{TEXT_FN}();
var compressed  = await Bun.{COMPRESS_FN}(textContent);
var encrypted   = await encryptData(Buffer.from("{KEY_STRING}"), compressed);

Bun.{WRITE_FN}(
    "flag.txt.{OUTPUT_EXT}{l(390)}",
    Buffer.from(encrypted).toString("{OUTPUT_ENC}")
);
        """)

        # Step 6: Petunjuk dekripsi
        print("=" * 65)
        print("  LANGKAH DEKRIPSI")
        print("=" * 65)
        print(f"""
  1. {OUTPUT_ENC} decode file flag.txt.{OUTPUT_EXT}{l(390)}
  2. Split: IV = bytes[0:16], ciphertext = bytes[16:]
  3. key = {DIGEST_ALGO}("{KEY_STRING}")[0:16]
  4. plaintext = AES-CBC-decrypt(key, iv, ciphertext)
  5. result = decompress(plaintext) ← jika ada Bun.{COMPRESS_FN}

  Jalankan: python3 decrypt_bunaken.py
        """)

    except Exception as e:
        print(f"\n[-] Error saat ekstrak parameter: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
