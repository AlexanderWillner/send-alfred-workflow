import hmac
import hashlib
import struct

SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

_R = 0xE1 << 120


def _xtime(a):
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else (a << 1) & 0xFF


def _mix_column(col):
    a = list(col)
    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ _xtime(a[0] ^ a[1])
    a[1] ^= t ^ _xtime(a[1] ^ a[2])
    a[2] ^= t ^ _xtime(a[2] ^ a[3])
    a[3] ^= t ^ _xtime(a[3] ^ u)
    return a


def _key_expansion(key):
    w = []
    for i in range(4):
        w.append([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]])
    for i in range(4, 44):
        temp = list(w[i - 1])
        if i % 4 == 0:
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ temp[j] for j in range(4)])
    rks = []
    for r in range(11):
        rk = []
        for c in range(4):
            rk.extend(w[r * 4 + c])
        rks.append(rk)
    return rks


def _aes_block(block, rks):
    s = [[block[row + 4 * col] for col in range(4)] for row in range(4)]
    rk = rks[0]
    for col in range(4):
        for row in range(4):
            s[row][col] ^= rk[col * 4 + row]
    for rnd in range(1, 10):
        for row in range(4):
            for col in range(4):
                s[row][col] = SBOX[s[row][col]]
        for r in range(4):
            s[r] = s[r][r:] + s[r][:r]
        for col in range(4):
            c = [s[row][col] for row in range(4)]
            c = _mix_column(c)
            for row in range(4):
                s[row][col] = c[row]
        rk = rks[rnd]
        for col in range(4):
            for row in range(4):
                s[row][col] ^= rk[col * 4 + row]
    for row in range(4):
        for col in range(4):
            s[row][col] = SBOX[s[row][col]]
    for r in range(4):
        s[r] = s[r][r:] + s[r][:r]
    rk = rks[10]
    for col in range(4):
        for row in range(4):
            s[row][col] ^= rk[col * 4 + row]
    out = bytearray(16)
    for col in range(4):
        for row in range(4):
            out[row + 4 * col] = s[row][col]
    return bytes(out)


def _gf128_mul(x, y):
    z = 0
    v = y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        if v & 1:
            v = (v >> 1) ^ _R
        else:
            v >>= 1
    return z


def _ghash(h_int, aad, ct):
    y = 0
    padded = aad + b"\x00" * ((-len(aad)) % 16)
    for i in range(0, len(padded), 16):
        y = _gf128_mul(y ^ int.from_bytes(padded[i : i + 16], "big"), h_int)
    padded = ct + b"\x00" * ((-len(ct)) % 16)
    for i in range(0, len(padded), 16):
        y = _gf128_mul(y ^ int.from_bytes(padded[i : i + 16], "big"), h_int)
    lens = struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    y = _gf128_mul(y ^ int.from_bytes(lens, "big"), h_int)
    return y


def _inc32(block):
    c = bytearray(block)
    val = struct.unpack(">I", c[12:16])[0] + 1
    struct.pack_into(">I", c, 12, val)
    return bytes(c)


def aes_gcm_encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> bytes:
    rks = _key_expansion(key)
    h_int = int.from_bytes(_aes_block(b"\x00" * 16, rks), "big")
    ct = bytearray()
    ctr = nonce + b"\x00\x00\x00\x02"
    for i in range(0, len(plaintext), 16):
        blk = plaintext[i : i + 16]
        ks = _aes_block(ctr, rks)
        ct.extend(a ^ b for a, b in zip(blk, ks))
        ctr = _inc32(ctr)
    ct = bytes(ct)
    g = _ghash(h_int, aad, ct)
    j0 = nonce + b"\x00\x00\x00\x01"
    ek_j0 = int.from_bytes(_aes_block(j0, rks), "big")
    tag = (g ^ ek_j0).to_bytes(16, "big")
    return ct + tag


def hkdf_derive(ikm: bytes, info: bytes, length: int = 16) -> bytes:
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    t = b""
    for i in range(1, (length // 32) + 3):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        if len(okm) >= length:
            break
    return okm[:length]


def hmac_sign(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()
