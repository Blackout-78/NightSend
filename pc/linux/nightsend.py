#!/usr/bin/env python3
"""NightSend for Linux (v3 protocol: encrypted + QR pairing, keeps folders, auto-sort, pick the phone folder, auto-reconnect, two-way).

Same job and same wire protocol as the Windows app (pc/NightSend.ps1), so it pairs with the same NightSend phone app.
Both devices on the same network: the app finds the phone by itself, you pair once by scanning a QR code with the phone.
No internet, no cloud, no telemetry. The only extra package is `cryptography` (AES / HMAC / ECDH).
"""
import atexit
import hashlib
import hmac
import json
import os
import queue
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FutureTimeout

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BUILD_STAMP = "build dev"   # the build replaces this line with the real build number and commit
PORT = 47800
MAX_PLAIN = 262144
MAX_FRAME = 16 + MAX_PLAIN + 16 + 32
CHUNK = 1 << 20


# ---------------------------------------------------------------- small helpers

def config_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    d = os.path.join(base, "nightsend")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def write_crash(msg, cfgdir=None):
    """Any unexpected error goes to ~/.config/nightsend/crash.log instead of silently closing the app."""
    try:
        d = cfgdir or config_dir()
        with open(os.path.join(d, "crash.log"), "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%dT%H:%M:%S") + "  " + msg + "\n")
    except Exception:
        pass


def fmt(b):
    b = float(b)
    units = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while b >= 1024 and i < 4:
        b /= 1024
        i += 1
    return "{:,.1f} {}".format(b, units[i])


def clean_name(n):
    return re.sub(r'[<>:"|?*]', "", n).strip()


def sort_name(name):
    """'Show.Name.S02E05.mkv' -> 'Show Name/Season 2/Show.Name.S02E05.mkv'; anything else is left alone."""
    m = re.match(r"^(.+?)[ ._-]+[Ss](\d{1,2})[ ._-]?[Ee]\d{1,3}", name)
    if not m:
        m = re.match(r"^(.+?)[ ._-]+(\d{1,2})x\d{1,3}", name)
    if m:
        show = clean_name(re.sub(r"[._]", " ", m.group(1)))
        if show:
            return "{}/Season {}/{}".format(show, int(m.group(2)), name)
    return name


_BAD_CHARS = '<>:"|?*\\'


def safe_recv_path(dest, rel):
    """A file name from the phone becomes a path that must stay inside the chosen folder (bad characters become _)."""
    parts = []
    for p in re.split(r"[/\\]", rel):
        if p in ("", ".", ".."):
            return None
        c = "".join("_" if (ch in _BAD_CHARS or ord(ch) < 32) else ch for ch in p).rstrip(". ")
        if not c:
            return None
        parts.append(c)
    root = os.path.realpath(dest)
    full = os.path.realpath(os.path.join(root, *parts))
    if not full.startswith(root.rstrip(os.sep) + os.sep):
        return None
    return full


# ---------------------------------------------------------------- protocol v2: key exchange + encrypted frames
# Same as Secure.java on the phone and NsCrypto in the Windows app.

class AuthError(Exception):
    def __init__(self, reply):
        super().__init__(reply)
        self.reply = reply


class Stopped(Exception):
    pass


def _hmac(key, *parts):
    h = hmac.new(key, digestmod=hashlib.sha256)
    for p in parts:
        h.update(p)
    return h.digest()


def _is_hex(s, n):
    return s is not None and len(s) == n and all(c in "0123456789abcdef" for c in s)


def key_id(pair_key):
    return hashlib.sha256(pair_key).digest()[:8].hex()


class Conn:
    """A TCP connection. Lines in clear text until the handshake is done, then AES-256-CBC + HMAC-SHA256 frames."""

    def __init__(self, sock):
        self.sock = sock
        self.inbuf = bytearray()
        self.plain = bytearray()
        self.keys = None
        self.s_seq = 0
        self.r_seq = 0
        self.wlock = threading.Lock()

    def _fill(self):
        d = self.sock.recv(65536)
        if not d:
            raise ConnectionError("The phone closed the connection.")
        self.inbuf += d

    def raw_line(self):
        while True:
            i = self.inbuf.find(b"\n")
            if i >= 0:
                line = bytes(self.inbuf[:i]).rstrip(b"\r")
                del self.inbuf[:i + 1]
                return line.decode("utf-8", "replace")
            if len(self.inbuf) > 1024:
                raise IOError("line too long")
            self._fill()

    def raw_send_line(self, s):
        self.sock.sendall((s + "\n").encode("utf-8"))

    def enable(self, s_enc, s_mac, r_enc, r_mac):
        self.keys = (s_enc, s_mac, r_enc, r_mac)

    def write(self, data):
        s_enc, s_mac = self.keys[0], self.keys[1]
        mv = memoryview(data)
        with self.wlock:
            for off in range(0, len(mv), MAX_PLAIN):
                chunk = bytes(mv[off:off + MAX_PLAIN])
                iv = os.urandom(16)
                padder = padding.PKCS7(128).padder()
                pt = padder.update(chunk) + padder.finalize()
                enc = Cipher(algorithms.AES(s_enc), modes.CBC(iv)).encryptor()
                ct = enc.update(pt) + enc.finalize()
                mac = _hmac(s_mac, struct.pack(">Q", self.s_seq), iv, ct)
                self.s_seq += 1
                self.sock.sendall(struct.pack(">I", 16 + len(ct) + 32) + iv + ct + mac)

    def send_line(self, s):
        self.write((s + "\n").encode("utf-8"))

    def _next_frame(self):
        r_enc, r_mac = self.keys[2], self.keys[3]
        while len(self.inbuf) < 4:
            self._fill()
        n = struct.unpack(">I", bytes(self.inbuf[:4]))[0]
        if n < 64 or n > MAX_FRAME:
            raise IOError("bad frame size")
        while len(self.inbuf) < 4 + n:
            self._fill()
        f = bytes(self.inbuf[4:4 + n])
        del self.inbuf[:4 + n]
        iv, ct, mac = f[:16], f[16:-32], f[-32:]
        if not hmac.compare_digest(mac, _hmac(r_mac, struct.pack(">Q", self.r_seq), iv, ct)):
            raise IOError("bad frame signature")
        dec = Cipher(algorithms.AES(r_enc), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        unp = padding.PKCS7(128).unpadder()
        self.plain += unp.update(pt) + unp.finalize()
        self.r_seq += 1

    def read_some(self, n):
        if not self.plain:
            self._next_frame()
        k = min(n, len(self.plain))
        out = bytes(self.plain[:k])
        del self.plain[:k]
        return out

    def read_line(self):
        while True:
            i = self.plain.find(b"\n")
            if i >= 0:
                line = bytes(self.plain[:i]).rstrip(b"\r")
                del self.plain[:i + 1]
                return line.decode("utf-8", "replace")
            if len(self.plain) > (1 << 20):
                raise IOError("line too long")
            self._next_frame()

    def set_timeout(self, t):
        self.sock.settimeout(t)

    def close(self, bye=True):
        if bye and self.keys:
            try:
                self.send_line("BYE")
            except Exception:
                pass
        try:
            self.sock.close()
        except Exception:
            pass


def client_handshake(conn, code, pair_key):
    """PC side. pair_key set: use the saved key (AUTH). Otherwise use the one-time 128-bit pairing secret from the QR code (PAIR).
    Returns the pair key (new one after a PAIR)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    nums = priv.public_key().public_numbers()
    pc = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
    conn.raw_send_line("NS2 " + pc.hex())
    r = conn.raw_line()
    if not _is_hex(r, 128):
        raise AuthError("ERR version")
    ph = bytes.fromhex(r)
    try:
        peer = ec.EllipticCurvePublicNumbers(int.from_bytes(ph[:32], "big"), int.from_bytes(ph[32:], "big"), ec.SECP256R1()).public_key()
    except ValueError:
        raise IOError("bad public key")
    t = pc + ph
    zh = hashlib.sha256(priv.exchange(ec.ECDH(), peer)).digest()
    if pair_key is not None:
        key = pair_key
        conn.raw_send_line("AUTH " + key_id(pair_key) + " " + _hmac(key, b"NS2-C", t).hex())
    else:
        key = code.encode("utf-8")
        conn.raw_send_line("PAIR " + _hmac(key, b"NS2-C", t).hex())
    ok = conn.raw_line()
    if ok.startswith("ERR"):
        raise AuthError(ok)
    if not ok.startswith("OK ") or not _is_hex(ok[3:], 64):
        raise IOError("Unexpected answer from the phone.")
    if not hmac.compare_digest(bytes.fromhex(ok[3:]), _hmac(key, b"NS2-S", t)):
        raise IOError("The phone could not prove who it is. Not trusted.")
    master = _hmac(key, b"NS2-MASTER", zh, t)
    new_key = pair_key if pair_key is not None else _hmac(zh, b"NS2-PAIRKEY", t)
    conn.enable(_hmac(master, b"c2s-enc"), _hmac(master, b"c2s-mac"), _hmac(master, b"s2c-enc"), _hmac(master, b"s2c-mac"))
    return new_key


# ---------------------------------------------------------------- QR code for pairing
# Version 3, error correction M, byte mode, up to 42 bytes. Port of NsQr in the Windows app, checked by selftest.py.

QR_N, QR_DATA, QR_EC = 29, 44, 26
_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _gmul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _generator(deg):
    g = [1]
    for i in range(deg):
        ng = [0] * (len(g) + 1)
        for j in range(len(g)):
            ng[j] ^= g[j]
            ng[j + 1] ^= _gmul(g[j], _EXP[i])
        g = ng
    return g


def _remainder(data, deg):
    g = _generator(deg)
    res = list(data) + [0] * deg
    for i in range(len(data)):
        c = res[i]
        if c:
            for j in range(1, len(g)):
                res[i + j] ^= _gmul(g[j], c)
    return res[len(data):]


def _codewords(p):
    if len(p) > 42:
        raise ValueError("payload too long")
    bits = []

    def put(v, n):
        for i in range(n - 1, -1, -1):
            bits.append((v >> i) & 1)
    put(4, 4)
    put(len(p), 8)
    for b in p:
        put(b, 8)
    put(0, min(4, QR_DATA * 8 - len(bits)))
    while len(bits) % 8:
        bits.append(0)
    allw = []
    for i in range(0, len(bits), 8):
        v = 0
        for j in range(8):
            v = (v << 1) | bits[i + j]
        allw.append(v)
    k = 0
    while len(allw) < QR_DATA:
        allw.append(0xEC if k % 2 == 0 else 0x11)
        k += 1
    allw += _remainder(allw[:QR_DATA], QR_EC)
    return allw


def _blank():
    N = QR_N
    m = [[False] * N for _ in range(N)]
    f = [[False] * N for _ in range(N)]

    def setf(r, c, v):
        m[r][c] = v
        f[r][c] = True
    for co in ((0, 0), (0, N - 7), (N - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = co[0] + dr, co[1] + dc
                if 0 <= r < N and 0 <= c < N:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    dark = inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4))
                    setf(r, c, dark)
    for i in range(8, N - 8):
        setf(6, i, i % 2 == 0)
        setf(i, 6, i % 2 == 0)
    for dr in range(-2, 3):
        for dc in range(-2, 3):
            setf(22 + dr, 22 + dc, max(abs(dr), abs(dc)) != 1)
    for i in range(9):
        f[8][i] = True
        f[i][8] = True
    for i in range(8):
        f[8][N - 1 - i] = True
        f[N - 1 - i][8] = True
    setf(N - 8, 8, True)
    return m, f


def _place_data(m, f, cws):
    N = QR_N
    total = len(cws) * 8 + 7
    bits = []
    for cw in cws:
        for i in range(7, -1, -1):
            bits.append((cw >> i) & 1)
    bits += [0] * (total - len(bits))
    idx = 0
    c = N - 1
    up = True
    while c > 0:
        if c == 6:
            c -= 1
        for k in range(N):
            r = N - 1 - k if up else k
            for d in range(2):
                cc = c - d
                if not f[r][cc]:
                    m[r][cc] = idx < total and bits[idx] == 1
                    idx += 1
        up = not up
        c -= 2


def _mask_bit(mask, r, c):
    if mask == 0:
        return (r + c) % 2 == 0
    if mask == 1:
        return r % 2 == 0
    if mask == 2:
        return c % 3 == 0
    if mask == 3:
        return (r + c) % 3 == 0
    if mask == 4:
        return (r // 2 + c // 3) % 2 == 0
    if mask == 5:
        return (r * c) % 2 + (r * c) % 3 == 0
    if mask == 6:
        return ((r * c) % 2 + (r * c) % 3) % 2 == 0
    return ((r + c) % 2 + (r * c) % 3) % 2 == 0


def _format_bits(mask):
    data = mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return ((data << 10) | rem) ^ 0x5412


def _draw_format(m, mask):
    N = QR_N
    bits = _format_bits(mask)

    def fb(i):
        return ((bits >> i) & 1) != 0
    for i in range(6):
        m[i][8] = fb(i)
    m[7][8] = fb(6)
    m[8][8] = fb(7)
    m[8][7] = fb(8)
    for i in range(9, 15):
        m[8][14 - i] = fb(i)
    for i in range(8):
        m[8][N - 1 - i] = fb(i)
    for i in range(8, 15):
        m[N - 15 + i][8] = fb(i)
    m[N - 8][8] = True


_PAT1 = [True, False, True, True, True, False, True, False, False, False, False]
_PAT2 = [False, False, False, False, True, False, True, True, True, False, True]


def _penalty(m):
    N = QR_N
    s = 0
    for pas in range(2):
        for a in range(N):
            line = [m[a][b] if pas == 0 else m[b][a] for b in range(N)]
            run = 1
            for i in range(1, N):
                if line[i] == line[i - 1]:
                    run += 1
                else:
                    if run >= 5:
                        s += 3 + (run - 5)
                    run = 1
            if run >= 5:
                s += 3 + (run - 5)
            for i in range(0, N - 10):
                seg = line[i:i + 11]
                if seg == _PAT1 or seg == _PAT2:
                    s += 40
    for r in range(N - 1):
        for c in range(N - 1):
            if m[r][c] == m[r][c + 1] == m[r + 1][c] == m[r + 1][c + 1]:
                s += 3
    dark = sum(1 for r in range(N) for c in range(N) if m[r][c])
    total = N * N
    k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
    s += k * 10
    return s


def qr_encode(payload):
    """Returns the 29 x 29 module grid (True = dark). No quiet zone."""
    N = QR_N
    m, f = _blank()
    _place_data(m, f, _codewords(payload))
    best, best_p = None, 0
    for mask in range(8):
        t = [[m[r][c] ^ ((not f[r][c]) and _mask_bit(mask, r, c)) for c in range(N)] for r in range(N)]
        _draw_format(t, mask)
        p = _penalty(t)
        if best is None or p < best_p:
            best, best_p = t, p
    return best


def qr_check():
    """A fixed text must always give exactly this picture (same hash as the Windows build self-test)."""
    m = qr_encode(b"NS3:00112233445566778899aabbccddeeff")
    s = "\n".join("".join("1" if x else "0" for x in row) for row in m)
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


QR_CHECK_HASH = "ab58fb4308d7ab7a050645c269e34e918ef4a81b4a5477d5a9ac6e052257cd0a"


# ---------------------------------------------------------------- finding the phone

def _local_networks():
    """Returns (local addresses, default gateways). Skips loopback and container/VM bridges."""
    locals_, gws = [], []
    try:
        out = subprocess.run(["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4 or "inet" not in parts:
                continue
            dev = parts[1]
            if dev == "lo" or dev.startswith(("docker", "veth", "br-", "virbr")):
                continue
            addr = parts[parts.index("inet") + 1].split("/")[0]
            if not addr.startswith(("127.", "169.254.")):
                locals_.append(addr)
        out = subprocess.run(["ip", "-4", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
        for line in out.splitlines():
            parts = line.split()
            if "via" in parts:
                gw = parts[parts.index("via") + 1]
                if gw != "0.0.0.0" and gw not in gws:
                    gws.append(gw)
    except (OSError, subprocess.SubprocessError):
        pass
    if not locals_:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))   # no packet is sent; this only asks the OS which address it would use
            locals_.append(s.getsockname()[0])
            s.close()
        except OSError:
            pass
    return locals_, gws


def _probe(ip):
    try:
        s = socket.create_connection((ip, PORT), timeout=1.5)
        s.close()
        return ip
    except OSError:
        return None


def find_phone_ip(log):
    """Look for the phone: default gateways first (USB tethering / phone hotspot), then the PC hotspot range, then every local /24."""
    locals_, gws = _local_networks()
    prefixes = []
    for a in locals_:
        p = ".".join(a.split(".")[:3])
        if p not in prefixes:
            prefixes.append(p)
    prefixes.sort(key=lambda p: 0 if p == "10.42.0" else 1)   # NetworkManager hotspot range first
    cands = list(gws)
    for p in prefixes:
        for i in range(1, 255):
            ip = "{}.{}".format(p, i)
            if ip not in locals_ and ip not in cands:
                cands.append(ip)
    log("Searching {} addresses...".format(len(cands)))
    found = None
    ex = ThreadPoolExecutor(max_workers=256)
    futs = [ex.submit(_probe, ip) for ip in cands]
    try:
        for fut in as_completed(futs, timeout=3.0):
            r = fut.result()
            if r:
                found = r
                break
    except FutureTimeout:
        pass
    ex.shutdown(wait=False, cancel_futures=True)
    return found


# ---------------------------------------------------------------- keep the computer awake while a transfer runs

class KeepAwake:
    def __init__(self):
        self.p = None
        atexit.register(self.off)

    def on(self):
        if self.p:
            return
        try:
            self.p = subprocess.Popen(
                ["systemd-inhibit", "--what=sleep:idle", "--who=NightSend", "--why=File transfer running", "--mode=block", "sleep", "2147483647"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            self.p = None

    def off(self):
        if self.p:
            try:
                self.p.terminate()
                self.p.wait(timeout=3)
            except Exception:
                pass
            self.p = None


# ---------------------------------------------------------------- the app logic (no window in here, so it can be tested)

class Ui:
    """Everything the logic says to the outside. The window overrides these; the tests use this silent version."""
    def log(self, msg): pass
    def phone(self, text, kind="dim"): pass          # kind: dim / good / bad
    def status(self, text): pass
    def file(self, text): pass
    def progress(self, frac): pass                    # 0.0 - 1.0
    def confirm(self, text): return True
    def busy(self, b): pass
    def note(self, title, msg): pass
    def set_ip(self, ip): pass
    def set_dest(self, text): pass


class Core:
    def __init__(self, ui, cfgdir=None):
        self.ui = ui
        self.cfgdir = cfgdir or config_dir()
        self.key_file = os.path.join(self.cfgdir, "pairing-key.dat")
        self.strict_file = os.path.join(self.cfgdir, "strict.flag")
        self.stop = threading.Event()
        self.awake = KeepAwake()
        self.conn = None
        self.pair_key = None
        self.pair_secret = None
        self.pair_secret_at = 0.0
        self.strict = os.path.exists(self.strict_file)
        if not self.strict:
            self.pair_key = self._load_key()
        self.phone_ip = None
        self.phone_free = -1
        self.phone_path = ""
        self.phone_root = ""
        self.dest_path = ""
        self.running = False

    # ---- pairing key (kept in a file only this Linux user can read)
    def _load_key(self):
        try:
            with open(self.key_file, "rb") as f:
                k = f.read()
            return k if len(k) == 32 else None
        except OSError:
            return None

    def save_pair_key(self, key):
        self.pair_key = key
        try:
            tmp = self.key_file + ".tmp"
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
            os.replace(tmp, self.key_file)
            os.chmod(self.key_file, 0o600)
        except OSError:
            pass

    def forget_pair_key(self):
        self.pair_key = None
        try:
            os.remove(self.key_file)
        except OSError:
            pass

    def set_strict(self, on):
        self.strict = on
        try:
            if on:
                with open(self.strict_file, "w") as f:
                    f.write("1")
                self.forget_pair_key()
            elif os.path.exists(self.strict_file):
                os.remove(self.strict_file)
        except OSError:
            pass

    def new_pair_secret(self):
        self.pair_secret = secrets.token_bytes(16).hex()
        self.pair_secret_at = time.time()
        return self.pair_secret

    # ---- connection
    def close_conn(self, bye=True):
        if self.conn:
            self.conn.close(bye)
        self.conn = None

    def open_conn(self, ip):
        self.close_conn()
        s = socket.create_connection((ip, PORT), timeout=3)
        s.settimeout(30)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, CHUNK)
        except OSError:
            pass
        self.conn = Conn(s)

    def say_hello(self):
        if self.pair_secret and time.time() - self.pair_secret_at > 600:
            self.pair_secret = None
        code = self.pair_secret
        if not self.pair_key and not code:
            raise IOError("Press 'Pair with QR', scan the picture with the NightSend phone app, then press Find phone.")
        use_key = None if code else self.pair_key   # a fresh QR pairing always wins over an old saved key
        try:
            new_key = client_handshake(self.conn, code, use_key)
        except AuthError as e:
            if e.reply == "ERR auth":
                raise IOError("The phone does not know this PC (forgotten, strict mode on the phone, or not your phone). Press 'Pair with QR' and scan it on the phone.")
            if e.reply == "ERR code":
                self.pair_secret = None
                raise IOError("The phone did not accept the pairing. On the phone tap 'Scan the PC's QR code' first, then press Find phone. If it still fails press 'Pair with QR' again for a new picture.")
            raise IOError("The phone has an older NightSend. Install the newest NightSend.apk from Releases.")
        self.pair_secret = None   # the QR secret works once
        if self.strict:
            self.forget_pair_key()   # strict mode: the key is not kept, the next session needs a new QR
        elif new_key and new_key != self.pair_key:
            self.save_pair_key(new_key)
        self.conn.send_line("HELLO")
        r = self.conn.read_line()
        if not r.startswith("NIGHTSEND|"):
            raise IOError("Not a NightSend phone.")
        p = r.split("|")
        self.phone_free = int(p[2])
        root = p[5] if len(p) > 5 and p[5] else p[3]
        return {"model": p[1], "free": int(p[2]), "path": p[3], "storage_ok": p[4] == "1", "root": root}

    def connect_phone(self, ip_text=""):
        ui = self.ui
        ui.phone("Looking for the phone...", "dim")
        ip = (ip_text or "").strip()
        if not ip:
            ip = find_phone_ip(ui.log)
        if not ip:
            ui.phone("Phone not found. Open NightSend on the phone and make sure the phone and this PC are on the same Wi-Fi.", "bad")
            return False
        try:
            self.open_conn(ip)
            h = self.say_hello()
            self.phone_ip = ip
            self.phone_path = h["path"]
            self.phone_root = h["root"]
            ui.set_ip(ip)
            ui.phone("Connected: {}  -  {} free  -  saving to {}".format(h["model"], fmt(h["free"]), h["path"]), "good")
            ui.log("Connected to {} at {}.".format(h["model"], ip))
            if not h["storage_ok"]:
                ui.phone("Connected, but the phone app needs storage permission. Tap 'Allow NightSend to save files' on the phone.", "bad")
                self.close_conn()
                return False
            return True
        except Exception as e:
            ui.phone("Could not connect: " + str(e), "bad")
            self.close_conn(bye=False)
            return False

    def _use_dest(self):
        """Send into the folder picked on the phone (instead of the phone's save folder)."""
        self.conn.send_line("DEST " + self.dest_path)
        r = self.conn.read_line()
        if not r.startswith("OK"):
            raise IOError("phone answered: " + r)
        q = r.split("|")
        if len(q) > 1:
            try:
                self.phone_free = int(q[1])
            except ValueError:
                pass

    # ---- browsing the phone's folders
    def phone_dirs(self, path):
        self.conn.send_line("DIRS " + path)
        names = []
        while True:
            l = self.conn.read_line()
            if l == "END":
                break
            if l.startswith("ERR"):
                raise IOError(l)
            names.append(l)
        return names

    def phone_mkdir(self, path):
        self.conn.send_line("MKDIR " + path)
        r = self.conn.read_line()
        if r != "OK":
            raise IOError("phone answered: " + r)

    # ---- send (PC -> phone)
    def send(self, src, ip_text, make_root, auto_sort, archive_to):
        ui = self.ui
        src = src.strip()
        if len(src) > 1:
            src = src.rstrip("/")
        if not os.path.isdir(src):
            ui.log("Source folder not found.")
            return
        self.stop.clear()
        self.running = True
        ui.busy(True)
        failed, queue_, total, done_bytes = [], [], 0, 0
        try:
            if not self.connect_phone(ip_text):
                return
            if self.dest_path:
                try:
                    self._use_dest()
                except Exception as e:
                    ui.log("The phone would not use that folder ({}). If it says unknown command, update the NightSend phone app.".format(e))
                    return
            ui.status("Reading files on the PC...")
            root_name = ""
            if make_root:
                leaf = clean_name(os.path.basename(src))
                target = self.dest_path or self.phone_path
                phone_leaf = re.split(r"[/\\]", target)[-1]
                if leaf and leaf != phone_leaf:
                    root_name = leaf
            local = []
            for dp, dns, fns in os.walk(src):
                for fn in fns:
                    full = os.path.join(dp, fn)
                    try:
                        size = os.stat(full).st_size
                    except OSError:
                        continue
                    local.append((full, os.path.relpath(full, src).replace(os.sep, "/"), size))

            ui.status("Reading what is already on the phone...")
            have = {}
            try:
                self.conn.send_line("LIST")
                while True:
                    l = self.conn.read_line()
                    if l == "END":
                        break
                    i = l.find("|")
                    if i > 0:
                        have[l[i + 1:]] = int(l[:i])
            except Exception as e:
                ui.log("Could not read phone files: " + str(e))
                return

            skipped = 0
            for full, rel, size in local:
                if "\n" in rel or "\r" in rel:
                    failed.append(rel)
                    ui.log("SKIPPED (line break in the file name): " + repr(rel))
                    continue
                if auto_sort and "/" not in rel:
                    rel = sort_name(rel)
                if root_name:
                    rel = root_name + "/" + rel
                if have.get(rel) == size:
                    skipped += 1
                    continue
                queue_.append((full, rel, size))
                total += size
            ui.log("{} files on PC. {} already on phone (skipped). {} to send ({}).".format(len(local), skipped, len(queue_), fmt(total)))

            if not queue_:
                ui.status("Everything is already on the phone.")
                ui.progress(1.0)
                return
            if 0 <= self.phone_free < total:
                if not ui.confirm("Not enough space on the phone.\nNeeded: {}\nFree: {}\n\nSend as much as fits anyway?".format(fmt(total), fmt(self.phone_free))):
                    ui.status("Cancelled - not enough space.")
                    return

            self.awake.on()
            start = time.time()
            last_ui = 0.0
            retries = 0
            need_reconnect = False
            i = 0
            while i < len(queue_):
                if self.stop.is_set():
                    raise Stopped("Stopped by you.")
                full, rel, size = queue_[i]
                try:
                    if need_reconnect:
                        for _ in range(30):   # 3 seconds, but the Stop button works meanwhile
                            if self.stop.is_set():
                                raise Stopped("Stopped by you.")
                            time.sleep(0.1)
                        self.open_conn(self.phone_ip)
                        self.say_hello()
                        if self.dest_path:
                            self._use_dest()
                        ui.log("Reconnected. Continuing.")
                        need_reconnect = False
                    try:
                        st = os.stat(full)
                        f = open(full, "rb")
                    except OSError as e:
                        failed.append(rel)
                        ui.log("SKIPPED (cannot read on PC): " + rel)
                        done_bytes += size
                        i += 1
                        continue
                    with f:
                        if st.st_size != size:
                            failed.append(rel)
                            ui.log("SKIPPED (changed while sending): " + rel)
                            done_bytes += size
                            i += 1
                            continue
                        ui.file(rel)
                        self.conn.send_line("PUT {} {}".format(size, rel))
                        left, cur = size, 0
                        while left > 0:
                            if self.stop.is_set():
                                raise Stopped("Stopped by you.")
                            chunk = f.read(min(CHUNK, left))
                            if not chunk:
                                raise IOError("File got shorter while sending: " + rel)
                            self.conn.write(chunk)
                            left -= len(chunk)
                            cur += len(chunk)
                            now = time.time()
                            if now - last_ui > 0.1:
                                last_ui = now
                                self._progress(i, len(queue_), done_bytes + cur, total, start)
                    self.conn.set_timeout(120)   # the phone checks the size before it answers
                    try:
                        resp = self.conn.read_line()
                    finally:
                        self.conn.set_timeout(30)
                    if resp.startswith("ERR !"):
                        raise IOError("phone stopped answering")
                    if resp != "OK":
                        failed.append(rel)
                        ui.log("FAILED on phone: {}  ({})".format(rel, resp))
                    done_bytes += size
                    i += 1
                    retries = 0
                    self._progress(min(i, len(queue_) - 1), len(queue_), done_bytes, total, start)
                except Stopped:
                    raise
                except (OSError, IOError, ValueError, struct.error) as e:
                    write_crash("Connection lost: {}".format(e), self.cfgdir)
                    self.close_conn(bye=False)
                    if retries >= 3:
                        raise IOError("Connection lost: {} (gave up after 3 tries).".format(e))
                    retries += 1
                    ui.log("Connection lost: {}. Reconnecting ({} of 3)...".format(e, retries))
                    ui.status("Connection lost - reconnecting...")
                    need_reconnect = True

            self.close_conn()
            ui.progress(1.0)
            ui.file("")
            if not failed:
                ui.status("Done. All files sent and checked.")
                ui.log("DONE - all files sent and size-checked by the phone.")
                self._archive(src, archive_to)
            else:
                ui.status("Done with {} failed file(s). Press SEND again to retry them.".format(len(failed)))
                ui.log("Finished. {} file(s) failed - press SEND again to retry only those.".format(len(failed)))
            ui.note("NightSend", "Finished sending.")
        except Stopped as e:
            self.close_conn(bye=False)
            ui.status("Stopped. Press SEND to continue where it left off.")
            ui.log(str(e) + "  Next SEND skips finished files.")
            ui.note("NightSend stopped", "Stopped. Press SEND to continue.")
        except Exception as e:
            write_crash("send: {!r}".format(e), self.cfgdir)
            self.close_conn(bye=False)
            ui.status("Stopped. Press SEND to continue where it left off.")
            ui.log(str(e) + "  Next SEND skips finished files.")
            ui.note("NightSend stopped", str(e))
        finally:
            self.awake.off()
            self.running = False
            self.close_conn()
            ui.busy(False)

    def _progress(self, idx, count, done, total, start):
        ui = self.ui
        if total > 0:
            ui.progress(min(1.0, done / total))
        secs = time.time() - start
        speed = done / secs if secs > 1 else 0
        eta = ""
        if speed > 0:
            left = int(min(359999, max(0, (total - done) / speed)))
            eta = "  -  about {}h {}m left".format(left // 3600, (left % 3600) // 60)
        ui.status("File {} of {}  -  {} of {}  -  {}/s{}".format(min(idx + 1, count), count, fmt(done), fmt(total), fmt(speed), eta))

    def _archive(self, src, dest):
        """Optional: after a send where every file was checked by the phone, move the folder into the archive folder.
        Same disk only (a rename, so nothing is copied or deleted). Nothing is ever removed."""
        ui = self.ui
        if not dest:
            return
        try:
            dest = dest.strip()
            if not dest:
                ui.log("Archive: no archive folder chosen. Nothing moved.")
                return
            src_full = os.path.realpath(src)
            dest_full = os.path.realpath(dest)
            if src_full in ("/", os.path.realpath(os.path.expanduser("~"))):
                ui.log("Archive: will not move a whole disk or your home folder. Nothing moved.")
                return
            if dest_full == src_full or dest_full.startswith(src_full + os.sep):
                ui.log("Archive: the archive folder is inside the folder you sent. Nothing moved.")
                return
            os.makedirs(dest_full, exist_ok=True)
            if os.stat(src_full).st_dev != os.stat(dest_full).st_dev:
                ui.log("Archive: the archive folder is on a different disk, so nothing was moved. Pick a folder on the same disk as the sent folder.")
                return
            name = os.path.basename(src_full)
            target = os.path.join(dest_full, name)
            if os.path.exists(target):
                target = os.path.join(dest_full, name + "_" + time.strftime("%Y%m%d-%H%M%S"))
            os.rename(src_full, target)
            ui.log("Archived: moved {} to {}. Nothing was deleted.".format(src_full, target))
        except OSError as e:
            ui.log("Archive: could not move the folder ({}). Files may be open in another program. Nothing was deleted.".format(e))

    # ---- receive (phone -> PC)
    def receive(self, dest, ip_text):
        ui = self.ui
        dest = dest.strip()
        if len(dest) > 1:
            dest = dest.rstrip("/")
        if not dest:
            ui.status("Pick a folder on this PC to save into.")
            return
        try:
            os.makedirs(dest, exist_ok=True)
        except OSError as e:
            ui.status("Cannot use that folder: " + str(e))
            return
        self.stop.clear()
        self.running = True
        self.awake.on()
        ui.busy(True)
        ui.progress(0.0)
        ui.file("")
        try:
            ui.status("Connecting...")
            if not self.connect_phone(ip_text):
                ui.status("Not connected.")
                return
            c = self.conn
            c.send_line("OUTBOX")
            r = c.read_line()
            if r.startswith("ERR unknown"):
                raise IOError("The phone app is too old. Install the newest NightSend.apk from Releases.")
            if not r.startswith("OK|"):
                raise IOError(re.sub(r"^ERR\s*", "", r))
            ui.log("The phone is sharing: " + r[3:])

            ui.status("Reading the list from the phone...")
            c.send_line("OTREE")
            items = []
            while True:
                l = c.read_line()
                if l == "END":
                    break
                if l.startswith("ERR"):
                    raise IOError(re.sub(r"^ERR\s*", "", l))
                i = l.find("|")
                if i < 1:
                    continue
                items.append((int(l[:i]), l[i + 1:]))

            todo, skipped, failed = [], 0, 0
            for size, rel in items:
                full = safe_recv_path(dest, rel)
                if not full:
                    ui.log("Skipped (name not allowed): " + rel)
                    failed += 1
                    continue
                if os.path.isfile(full) and os.path.getsize(full) == size:
                    skipped += 1
                    continue
                todo.append((rel, size, full))
            total = sum(t[1] for t in todo)
            if not todo:
                ui.status("Nothing new. {} file(s) already here.".format(skipped))
                ui.log("Nothing new. {} file(s) already here.".format(skipped))
                return
            try:
                free = shutil.disk_usage(dest).free
                if free < total:
                    raise IOError("Not enough space on this PC: need {}, {} free.".format(fmt(total), fmt(free)))
            except OSError:
                pass
            ui.log("Receiving {} file(s), {}.".format(len(todo), fmt(total)))

            start = time.time()
            last_ui = 0.0
            got, done = 0, 0
            for idx, (rel, size0, full) in enumerate(todo, 1):
                if self.stop.is_set():
                    raise Stopped("Stopped by you.")
                ui.file(rel)
                part = full + ".nspart"
                os.makedirs(os.path.dirname(full), exist_ok=True)
                fs = open(part, "wb")   # opened before asking, so a local problem never leaves the phone mid-file
                ok = False
                try:
                    c.send_line("GET " + rel)
                    h = c.read_line()
                    if not h.startswith("OK|"):
                        ui.log("The phone refused {}: {}".format(rel, h))
                        failed += 1
                        continue
                    size = int(h[3:])
                    left = size
                    while left > 0:
                        chunk = c.read_some(min(CHUNK, left))
                        fs.write(chunk)
                        left -= len(chunk)
                        got += len(chunk)
                        now = time.time()
                        if now - last_ui > 0.15:
                            last_ui = now
                            sec = max(0.5, now - start)
                            ui.progress(min(1.0, got / max(1, total)))
                            ui.status("File {} of {}  -  {} of {}  -  {}/s".format(idx, len(todo), fmt(got), fmt(total), fmt(got / sec)))
                            if self.stop.is_set():
                                raise Stopped("Stopped by you.")
                    ok = True
                finally:
                    fs.close()
                    if not ok:
                        try:
                            os.remove(part)
                        except OSError:
                            pass
                if os.path.getsize(part) != size:
                    os.remove(part)
                    ui.log("Size check failed, not kept: " + rel)
                    failed += 1
                    continue
                os.replace(part, full)
                done += 1
            ui.progress(1.0)
            ui.file("")
            msg = "Done. {} file(s) received ({}).".format(done, fmt(got))
            if skipped:
                msg += " {} already here.".format(skipped)
            if failed:
                msg += " {} failed - press RECEIVE again to retry.".format(failed)
            ui.status(msg)
            ui.log(msg)
        except Stopped as e:
            ui.status("Stopped: " + str(e))
            ui.log("Receive stopped: {}  Press RECEIVE to continue.".format(e))
            self.close_conn(bye=False)
        except Exception as e:
            write_crash("receive: {!r}".format(e), self.cfgdir)
            ui.status("Stopped: " + str(e))
            ui.log("Receive stopped: {}  Press RECEIVE to continue.".format(e))
            self.close_conn(bye=False)
        finally:
            self.close_conn()
            self.running = False
            self.awake.off()
            ui.busy(False)
            ui.note("NightSend", "Receive finished.")


# ---------------------------------------------------------------- the window

C_BG, C_PANEL, C_TEXT, C_DIM = "#000000", "#1c1c1c", "#dcdce1", "#82828c"
C_ACCENT, C_BAD, C_GOOD, C_BAR = "#23295d", "#dc4650", "#5aaa6e", "#313a82"


def run_gui(smoke=False):
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk

    try:
        root = tk.Tk()
    except tk.TclError as e:
        print("NightSend needs a desktop session (no display found): {}".format(e), file=sys.stderr)
        return 1
    root.title("NightSend")
    root.configure(bg=C_BG)
    root.resizable(False, False)
    q = queue.Queue()
    root.report_callback_exception = lambda et, ev, tb: write_crash("UI error: {!r}".format(ev))

    settings_file = os.path.join(config_dir(), "settings.json")
    try:
        with open(settings_file, "r", encoding="utf-8") as f:
            st = json.load(f)
    except (OSError, ValueError):
        st = {}
    home = os.path.expanduser("~")

    def font(size=10, bold=False, mono=False):
        return ("DejaVu Sans Mono" if mono else "DejaVu Sans", size, "bold" if bold else "normal")

    def lab(parent, text, color=C_TEXT, f=None, **kw):
        return tk.Label(parent, text=text, bg=C_BG, fg=color, font=f or font(), anchor="w", **kw)

    def btn(parent, text, cmd, accent=False, w=None):
        return tk.Button(parent, text=text, command=cmd, bg=C_ACCENT if accent else C_PANEL, fg=C_TEXT, relief="flat", bd=0,
                         activebackground=C_ACCENT, activeforeground=C_TEXT, disabledforeground=C_DIM,
                         highlightthickness=1, highlightbackground=C_ACCENT, highlightcolor=C_ACCENT,
                         font=font(10, accent), padx=10, pady=5, width=w, cursor="hand2")

    def ent(parent, value="", readonly=False, **kw):
        e = tk.Entry(parent, bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT, relief="flat", bd=0, font=font(),
                     highlightthickness=1, highlightbackground=C_ACCENT, highlightcolor=C_ACCENT,
                     readonlybackground=C_PANEL, disabledbackground=C_PANEL, disabledforeground=C_DIM, **kw)
        e.insert(0, value)
        if readonly:
            e.configure(state="readonly")
        return e

    def chk(parent, text, var, cmd=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=cmd, bg=C_BG, fg=C_TEXT, selectcolor=C_PANEL,
                              activebackground=C_BG, activeforeground=C_TEXT, highlightthickness=0, bd=0, font=font(), anchor="w")

    pad = {"padx": 20}
    lab(root, "NIGHTSEND", f=font(24, True)).pack(anchor="w", padx=20, pady=(12, 0))
    lab(root, "Pair once with a QR code  -  no cloud, no internet", C_DIM).pack(anchor="w", padx=22)
    tk.Frame(root, bg=C_ACCENT, height=2).pack(fill="x", padx=20, pady=(8, 8))

    # 1 PHONE
    lab(root, "1  PHONE", C_DIM, font(10, True)).pack(anchor="w", **pad)
    r1 = tk.Frame(root, bg=C_BG)
    r1.pack(fill="x", padx=20, pady=4)
    btn_find = btn(r1, "Find phone", lambda: on_find(), w=12)
    btn_find.pack(side="left")
    lab(r1, "Address (auto):", C_DIM).pack(side="left", padx=(12, 4))
    txt_ip = ent(r1, "", width=15)
    txt_ip.pack(side="left", ipady=4)
    btn_pair = btn(r1, "Pair with QR", lambda: show_pair_qr(), w=12)
    btn_pair.pack(side="left", padx=(12, 6))
    lab(r1, "(once per phone)", C_DIM).pack(side="left")
    lbl_phone = lab(root, "Not connected.", C_DIM, wraplength=680, justify="left")
    lbl_phone.pack(anchor="w", padx=20, pady=2)
    var_strict = tk.BooleanVar(value=False)
    chk_strict = chk(root, "Strict: new QR for every session", var_strict, lambda: core.set_strict(var_strict.get()))
    chk_strict.pack(anchor="w", padx=20)

    # 2 SEND
    lab(root, "2  SEND FROM (this PC)", C_DIM, font(10, True)).pack(anchor="w", padx=20, pady=(10, 0))
    r2 = tk.Frame(root, bg=C_BG)
    r2.pack(fill="x", padx=20, pady=4)
    txt_src = ent(r2, st.get("src", home))
    txt_src.pack(side="left", fill="x", expand=True, ipady=4)
    btn_browse = btn(r2, "Browse", lambda: pick_dir(txt_src), w=10)
    btn_browse.pack(side="left", padx=(10, 0))
    r3 = tk.Frame(root, bg=C_BG)
    r3.pack(fill="x", padx=20, pady=4)
    lab(r3, "Put it in (phone):", C_DIM).pack(side="left")
    txt_dest = ent(r3, "(the phone's save folder)", readonly=True)
    txt_dest.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
    btn_pick = btn(r3, "Pick on phone", lambda: on_pick(), w=12)
    btn_pick.pack(side="left")
    r4 = tk.Frame(root, bg=C_BG)
    r4.pack(fill="x", padx=20)
    var_root = tk.BooleanVar(value=st.get("root", True))
    var_sort = tk.BooleanVar(value=st.get("sort", True))
    chk_root = chk(r4, "Make a folder with its name", var_root)
    chk_root.pack(side="left")
    chk_sort = chk(r4, "Auto-sort loose files by name (Show / Season)", var_sort)
    chk_sort.pack(side="left", padx=(16, 0))
    r5 = tk.Frame(root, bg=C_BG)
    r5.pack(fill="x", padx=20, pady=2)
    var_arch = tk.BooleanVar(value=st.get("archive_on", False))
    chk_arch = chk(r5, "After a clean send, archive the folder to:", var_arch)
    chk_arch.pack(side="left")
    txt_arch = ent(r5, st.get("archive", os.path.join(home, "Sent to phone")))
    txt_arch.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
    btn_arch = btn(r5, "Browse", lambda: pick_dir(txt_arch), w=10)
    btn_arch.pack(side="left")
    r6 = tk.Frame(root, bg=C_BG)
    r6.pack(fill="x", padx=20, pady=6)
    btn_send = btn(r6, "SEND", lambda: on_send(), accent=True, w=14)
    btn_send.pack(side="left")
    btn_stop = btn(r6, "Stop", lambda: core.stop.set(), w=10)
    btn_stop.pack(side="left", padx=10)
    btn_stop.configure(state="disabled")

    # 3 RECEIVE
    lab(root, "3  RECEIVE FROM PHONE (the folder the phone chose to send)", C_DIM, font(10, True)).pack(anchor="w", padx=20, pady=(8, 0))
    r7 = tk.Frame(root, bg=C_BG)
    r7.pack(fill="x", padx=20, pady=4)
    lab(r7, "Save on this PC:", C_DIM).pack(side="left")
    txt_recv = ent(r7, st.get("recv", os.path.join(home, "Downloads", "From phone")))
    txt_recv.pack(side="left", fill="x", expand=True, padx=8, ipady=4)
    btn_recv_browse = btn(r7, "Browse", lambda: pick_dir(txt_recv), w=10)
    btn_recv_browse.pack(side="left")
    btn_recv = btn(root, "RECEIVE", lambda: on_recv(), accent=True, w=14)
    btn_recv.pack(anchor="w", padx=20, pady=4)

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("Night.Horizontal.TProgressbar", troughcolor=C_PANEL, background=C_BAR, bordercolor=C_ACCENT, lightcolor=C_BAR, darkcolor=C_BAR)
    bar = ttk.Progressbar(root, style="Night.Horizontal.TProgressbar", maximum=1000, mode="determinate")
    bar.pack(fill="x", padx=20, pady=(8, 2))
    lbl_status = lab(root, "Ready.", C_TEXT, wraplength=680, justify="left")
    lbl_status.pack(anchor="w", padx=20)
    lbl_file = lab(root, "", C_DIM, wraplength=680, justify="left")
    lbl_file.pack(anchor="w", padx=20)
    txt_log = tk.Text(root, height=7, bg=C_PANEL, fg=C_DIM, relief="flat", bd=0, font=font(9, mono=True), wrap="word",
                      highlightthickness=1, highlightbackground=C_ACCENT, state="disabled")
    txt_log.pack(fill="x", padx=20, pady=(6, 4))
    foot = tk.Frame(root, bg=C_BG)
    foot.pack(fill="x", padx=20, pady=(0, 8))
    lab(foot, "NightSend " + BUILD_STAMP, C_DIM, font(8)).pack(side="left")   # version/build tag, bottom-left
    # Updates: the browser opens the Releases page. The app itself stays offline.
    btn(foot, "Open GitHub Releases", lambda: webbrowser.open("https://github.com/Blackout-78/NightSend/releases"), w=20).pack(side="right")

    kinds = {"dim": C_DIM, "good": C_GOOD, "bad": C_BAD}

    class GuiUi(Ui):
        """Called from worker threads: everything is queued and shown by the window's own thread."""
        def _post(self, fn):
            q.put(fn)

        def log(self, msg):
            def f():
                txt_log.configure(state="normal")
                txt_log.insert("end", time.strftime("%H:%M:%S") + "  " + msg + "\n")
                txt_log.see("end")
                txt_log.configure(state="disabled")
            self._post(f)

        def phone(self, text, kind="dim"):
            self._post(lambda: lbl_phone.configure(text=text, fg=kinds.get(kind, C_DIM)))

        def status(self, text):
            self._post(lambda: lbl_status.configure(text=text))

        def file(self, text):
            self._post(lambda: lbl_file.configure(text=text))

        def progress(self, frac):
            self._post(lambda: bar.configure(value=int(frac * 1000)))

        def confirm(self, text):
            ev, res = threading.Event(), []

            def f():
                res.append(messagebox.askyesno("NightSend", text, icon="warning", parent=root))
                ev.set()
            self._post(f)
            ev.wait()
            return bool(res and res[0])

        def busy(self, b):
            def f():
                s = "disabled" if b else "normal"
                for w in (btn_send, btn_find, btn_browse, btn_pick, btn_recv, btn_recv_browse, chk_root, chk_sort):
                    w.configure(state=s)
                btn_stop.configure(state="normal" if b else "disabled")
            self._post(f)

        def note(self, title, msg):
            def f():
                if root.state() == "iconic":
                    try:
                        subprocess.Popen(["notify-send", "-a", "NightSend", title, msg], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    except OSError:
                        pass
            self._post(f)

        def set_ip(self, ip):
            def f():
                txt_ip.delete(0, "end")
                txt_ip.insert(0, ip)
            self._post(f)

        def set_dest(self, text):
            def f():
                txt_dest.configure(state="normal")
                txt_dest.delete(0, "end")
                txt_dest.insert(0, text)
                txt_dest.configure(state="readonly")
            self._post(f)

    ui = GuiUi()
    core = Core(ui)
    var_strict.set(core.strict)

    def pump():
        try:
            while True:
                q.get_nowait()()
        except queue.Empty:
            pass
        root.after(40, pump)

    def save_settings():
        try:
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump({"src": txt_src.get(), "recv": txt_recv.get(), "archive": txt_arch.get(), "archive_on": var_arch.get(),
                           "root": var_root.get(), "sort": var_sort.get()}, f)
        except OSError:
            pass

    def bg(fn, *args):
        def run():
            try:
                fn(*args)
            except Exception as e:
                write_crash("worker: {!r}".format(e))
                ui.status("Stopped: " + str(e))
                ui.busy(False)
        threading.Thread(target=run, daemon=True).start()

    def pick_dir(entry):
        d = filedialog.askdirectory(initialdir=entry.get() if os.path.isdir(entry.get()) else home, parent=root)
        if d:
            entry.delete(0, "end")
            entry.insert(0, d)

    def find_job():
        ui.busy(True)
        ui.status("Ready.")
        core.connect_phone(txt_ip.get())
        core.close_conn()
        ui.busy(False)

    def on_find():
        bg(find_job)

    def on_send():
        save_settings()
        a = (txt_src.get(), txt_ip.get(), var_root.get(), var_sort.get(), txt_arch.get() if var_arch.get() else None)
        bg(core.send, *a)

    def on_recv():
        save_settings()
        bg(core.receive, txt_recv.get(), txt_ip.get())

    def show_pair_qr():
        secret = core.new_pair_secret()
        mods = qr_encode(("NS3:" + secret).encode("utf-8"))
        scale, quiet, n = 9, 4, QR_N
        px = (n + 2 * quiet) * scale
        dlg = tk.Toplevel(root)
        dlg.title("Pair with the phone")
        dlg.configure(bg=C_BG)
        dlg.resizable(False, False)
        dlg.transient(root)
        cv = tk.Canvas(dlg, width=px, height=px, bg="white", highlightthickness=0)
        cv.pack(padx=20, pady=(14, 8))
        for r in range(n):
            for c in range(n):
                if mods[r][c]:
                    cv.create_rectangle((c + quiet) * scale, (r + quiet) * scale, (c + quiet + 1) * scale, (r + quiet + 1) * scale, fill="black", outline="black")
        lab(dlg, "On the phone open NightSend and tap 'Scan the PC's QR code', then point the camera at this picture. "
                 "Then come back and press Find phone. This picture works once.", wraplength=px, justify="left").pack(padx=20, anchor="w")
        grp = re.sub(r"(.{4})(?=.)", r"\1 ", secret)
        lab(dlg, "No camera? On the phone choose 'Type the code instead':\n" + grp, C_DIM, font(9, mono=True), wraplength=px, justify="left").pack(padx=20, pady=6, anchor="w")
        btn(dlg, "Done", dlg.destroy, w=10).pack(pady=(2, 14))
        dlg.grab_set()

    def pick_job():
        ui.busy(True)
        q.put(lambda: btn_stop.configure(state="disabled"))
        if not core.connect_phone(txt_ip.get()):
            ui.busy(False)
            return
        q.put(open_picker)

    def on_pick():
        bg(pick_job)

    def open_picker():
        root_dir = core.phone_root.rstrip("/")
        state = {"path": core.dest_path or core.phone_path, "choice": None}
        dlg = tk.Toplevel(root)
        dlg.title("Pick the folder on the phone")
        dlg.configure(bg=C_BG)
        dlg.resizable(False, False)
        dlg.transient(root)
        lbl = lab(dlg, "", C_DIM, wraplength=520, justify="left")
        lbl.pack(anchor="w", padx=16, pady=(12, 4))
        lb = tk.Listbox(dlg, width=64, height=16, bg=C_PANEL, fg=C_TEXT, relief="flat", bd=0, font=font(),
                        selectbackground=C_ACCENT, selectforeground=C_TEXT, highlightthickness=1, highlightbackground=C_ACCENT, activestyle="none")
        lb.pack(padx=16, pady=4)

        def refresh():
            try:
                try:
                    names = core.phone_dirs(state["path"])
                except (OSError, IOError):
                    # the phone may have dropped the idle connection while the window was open: reconnect once
                    if not core.connect_phone(txt_ip.get()):
                        raise IOError("phone not reachable")
                    names = core.phone_dirs(state["path"])
                lb.delete(0, "end")
                for nme in names:
                    lb.insert("end", nme)
                lbl.configure(text=state["path"], fg=C_DIM)
                if not names:
                    lb.insert("end", "(no folders here - press Use this folder, or New folder)")
            except Exception as e:
                lbl.configure(text="Could not read that folder: {}   (If it says unknown command, update the phone app.)".format(e), fg=C_BAD)

        def open_sel(_=None):
            s = lb.curselection()
            if s:
                nme = lb.get(s[0])
                if not nme.startswith("(no folders"):
                    state["path"] = state["path"].rstrip("/") + "/" + nme
                    refresh()

        def up():
            p = state["path"].rstrip("/")
            if len(p) > len(root_dir):
                state["path"] = p[:p.rfind("/")]
                if len(state["path"]) < len(root_dir):
                    state["path"] = root_dir
                refresh()

        def new_folder():
            win = tk.Toplevel(dlg)
            win.title("Name of the new folder")
            win.configure(bg=C_BG)
            win.transient(dlg)
            e = ent(win, "", width=40)
            e.pack(padx=16, pady=(14, 6), ipady=4)
            e.focus_set()

            def ok(_=None):
                nme = clean_name(e.get())
                nme = re.sub(r"[/\\]", " ", nme).strip()
                win.destroy()
                if nme:
                    np_ = state["path"].rstrip("/") + "/" + nme
                    try:
                        core.phone_mkdir(np_)
                        state["path"] = np_
                    except Exception as ex:
                        lbl.configure(text="Could not make the folder: " + str(ex), fg=C_BAD)
                        return
                    refresh()
            e.bind("<Return>", ok)
            btn(win, "OK", ok, accent=True, w=10).pack(pady=(0, 12))
            win.grab_set()
            win.wait_window()

        def finish(choice):
            state["choice"] = choice
            dlg.destroy()

        lb.bind("<Double-Button-1>", open_sel)
        b1 = tk.Frame(dlg, bg=C_BG)
        b1.pack(fill="x", padx=16, pady=4)
        btn(b1, "Up", up, w=8).pack(side="left")
        btn(b1, "Open", open_sel, w=8).pack(side="left", padx=8)
        btn(b1, "New folder", new_folder, w=12).pack(side="left")
        b2 = tk.Frame(dlg, bg=C_BG)
        b2.pack(fill="x", padx=16, pady=(4, 14))
        btn(b2, "Use this folder", lambda: finish(state["path"]), accent=True, w=14).pack(side="left")
        btn(b2, "Phone's save folder", lambda: finish(""), w=18).pack(side="left", padx=8)
        btn(b2, "Cancel", lambda: finish(None), w=8).pack(side="left")
        refresh()
        dlg.grab_set()
        dlg.wait_window()
        ch = state["choice"]
        if ch is not None:
            if ch == core.phone_path:
                ch = ""
            core.dest_path = ch
            ui.set_dest(ch if ch else "(the phone's save folder)")
        core.close_conn()
        ui.busy(False)

    def on_close():
        if core.running:
            # X while sending: keep sending in the background instead of stopping (use Stop to cancel).
            root.iconify()
            ui.log("Still working in the background. Use the taskbar to bring the window back.")
            return
        save_settings()
        core.awake.off()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    ui.log("NightSend ready. First time: press Pair with QR, scan the picture with the NightSend phone app, then press Find phone.")
    if core.pair_key:
        bg(find_job)
    root.after(40, pump)
    if smoke:
        root.after(1500, root.destroy)
    root.mainloop()
    return 0


def main(argv):
    if "--version" in argv:
        print("NightSend " + BUILD_STAMP)
        return 0
    return run_gui(smoke="--smoke" in argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
