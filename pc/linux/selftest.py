#!/usr/bin/env python3
"""NightSend for Linux self-test. Run by the build; if it fails nothing is published.

  1. the QR picture is exactly what the Windows app makes
  2. the encrypted handshake and frames work against the REAL Secure.java from the phone app (needs java; --require-java makes it a must)
  3. send / receive / reconnect / archive / folder picking, against a fake phone on loopback

Usage: python3 -I pc/linux/selftest.py [--require-java]
"""
import hashlib
import hmac
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import nightsend as N   # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec   # noqa: E402

PASSED = []


def ok(name):
    PASSED.append(name)
    print("ok   " + name)


def fail(msg):
    print("FAIL " + msg)
    sys.exit(1)


def check(cond, msg):
    if not cond:
        fail(msg)


# ---------------------------------------------------------------- 1 QR
def test_qr():
    check(N.qr_check() == N.QR_CHECK_HASH, "QR code picture is not what the Windows reference makes")
    ok("QR picture matches the Windows reference")


# ---------------------------------------------------------------- 2 real phone crypto
def test_java(require):
    java, javac = shutil.which("java"), shutil.which("javac")
    if not java or not javac:
        if require:
            fail("java is required for the interop test but was not found")
        print("skip interop against Secure.java (no java here)")
        return
    root = HERE.parents[1]
    tmp = tempfile.mkdtemp(prefix="nsinterop-")
    try:
        subprocess.run([javac, "-d", tmp, str(root / "app/src/main/java/com/blackout/nightsend/Secure.java"),
                        str(HERE / "interop/com/blackout/nightsend/InteropServer.java")], check=True, capture_output=True)
        p = subprocess.Popen([java, "-cp", tmp, "com.blackout.nightsend.InteropServer"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        port = int(p.stdout.readline())
        code = "0123456789abcdef0123456789abcdef"
        data = os.urandom(1000000)

        def connect():
            s = socket.create_connection(("127.0.0.1", port), timeout=20)
            return N.Conn(s)

        # 1: wrong code is refused
        c = connect()
        try:
            N.client_handshake(c, "0" * 32, None)
            fail("wrong pairing code was accepted by the real phone code")
        except N.AuthError as e:
            check(e.reply == "ERR code", "wrong code gave " + e.reply)
        c.close(bye=False)
        # 2: pair, send 1 MB, the phone saw the same bytes
        c = connect()
        key = N.client_handshake(c, code, None)
        c.send_line("HELLO")
        c.write(data)
        check(c.read_line() == "ECHO HELLO " + hashlib.sha256(data).hexdigest(), "pair round: data mismatch")
        c.close(bye=False)
        # 3: come back with the saved key only
        c = connect()
        N.client_handshake(c, "", key)
        c.send_line("AGAIN")
        c.write(data)
        check(c.read_line() == "ECHO AGAIN " + hashlib.sha256(data).hexdigest(), "key round: data mismatch")
        c.close(bye=False)
        p.wait(timeout=20)
        ok("encrypted handshake and frames work with the real phone crypto (Secure.java)")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------- 3 fake phone
class FakePhone:
    """Speaks the phone's side of the protocol on loopback. Storage is a temp folder."""
    CODE = "ffeeddccbbaa99887766554433221100"

    def __init__(self, base, free=10 ** 12):
        self.base = Path(base)
        (self.base / "NightSend").mkdir(parents=True, exist_ok=True)
        (self.base / "Outbox").mkdir(exist_ok=True)
        self.free = free
        self.stored = [None]
        self.drop_next_put = False
        self.puts = 0
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.t = threading.Thread(target=self.loop, daemon=True)
        self.t.start()

    def loop(self):
        while True:
            try:
                s, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(s,), daemon=True).start()

    def path(self, p):
        p = p.lstrip("/")
        if p.startswith("store/"):
            p = p[6:]
        return self.base / p

    def serve(self, s):
        s.settimeout(30)
        c = N.Conn(s)
        dest = "/store/NightSend"
        try:
            first = c.raw_line()
            pc = bytes.fromhex(first[4:])
            priv = ec.generate_private_key(ec.SECP256R1())
            nums = priv.public_key().public_numbers()
            ph = nums.x.to_bytes(32, "big") + nums.y.to_bytes(32, "big")
            peer = ec.EllipticCurvePublicNumbers(int.from_bytes(pc[:32], "big"), int.from_bytes(pc[32:], "big"), ec.SECP256R1()).public_key()
            zh = hashlib.sha256(priv.exchange(ec.ECDH(), peer)).digest()
            c.raw_send_line(ph.hex())
            w = c.raw_line().split(" ")
            t = pc + ph
            pairing = w[0] == "PAIR"
            key = self.CODE.encode() if pairing else self.stored[0]
            proof = w[1] if pairing else w[2]
            if key is None or not hmac.compare_digest(bytes.fromhex(proof), N._hmac(key, b"NS2-C", t)):
                c.raw_send_line("ERR code" if pairing else "ERR auth")
                s.close()
                return
            c.raw_send_line("OK " + N._hmac(key, b"NS2-S", t).hex())
            if pairing:
                self.stored[0] = N._hmac(zh, b"NS2-PAIRKEY", t)
            m = N._hmac(key, b"NS2-MASTER", zh, t)
            c.enable(N._hmac(m, b"s2c-enc"), N._hmac(m, b"s2c-mac"), N._hmac(m, b"c2s-enc"), N._hmac(m, b"c2s-mac"))
            while True:
                line = c.read_line()
                cmd, _, arg = line.partition(" ")
                if cmd == "BYE":
                    break
                elif cmd == "HELLO":
                    c.send_line("NIGHTSEND|TestPhone|{}|/store/NightSend|1|/store".format(self.free))
                elif cmd == "DEST":
                    dest = arg
                    self.path(dest).mkdir(parents=True, exist_ok=True)
                    c.send_line("OK|{}".format(self.free))
                elif cmd == "LIST":
                    root = self.path(dest)
                    for f in sorted(root.rglob("*")):
                        if f.is_file():
                            c.send_line("{}|{}".format(f.stat().st_size, f.relative_to(root).as_posix()))
                    c.send_line("END")
                elif cmd == "PUT":
                    size, _, rel = arg.partition(" ")
                    size = int(size)
                    self.puts += 1
                    out = self.path(dest) / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    got = 0
                    with open(out, "wb") as f:
                        while got < size:
                            d = c.read_some(min(65536, size - got))
                            f.write(d)
                            got += len(d)
                            if self.drop_next_put and got > size // 3:
                                self.drop_next_put = False
                                f.close()
                                out.unlink()
                                s.close()
                                return
                    c.send_line("OK")
                elif cmd == "DIRS":
                    d = self.path(arg)
                    for x in sorted(d.iterdir()):
                        if x.is_dir():
                            c.send_line(x.name)
                    c.send_line("END")
                elif cmd == "MKDIR":
                    self.path(arg).mkdir(parents=True, exist_ok=True)
                    c.send_line("OK")
                elif cmd == "OUTBOX":
                    c.send_line("OK|Outbox (test)")
                elif cmd == "OTREE":
                    for f in sorted((self.base / "Outbox").rglob("*")):
                        if f.is_file():
                            c.send_line("{}|{}".format(f.stat().st_size, f.relative_to(self.base / "Outbox").as_posix()))
                    # a name that tries to climb out of the save folder must be refused by the PC
                    c.send_line("5|../evil.txt")
                    c.send_line("END")
                elif cmd == "GET":
                    f = self.base / "Outbox" / arg
                    b = f.read_bytes()
                    c.send_line("OK|{}".format(len(b)))
                    c.write(b)
                else:
                    c.send_line("ERR unknown")
        except Exception:
            pass
        finally:
            try:
                s.close()
            except OSError:
                pass


class TUi(N.Ui):
    def __init__(self):
        self.logs, self.statuses, self.phones, self.answer = [], [], [], True

    def log(self, m): self.logs.append(m)
    def status(self, t): self.statuses.append(t)
    def phone(self, t, kind="dim"): self.phones.append((t, kind))
    def confirm(self, t): self.logs.append("CONFIRM: " + t); return self.answer


def sha(p):
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def test_flows():
    tmp = Path(tempfile.mkdtemp(prefix="nsflow-"))
    try:
        phone = FakePhone(tmp / "phone")
        N.PORT = phone.port
        ui = TUi()
        core = N.Core(ui, cfgdir=str(tmp / "cfg"))
        os.makedirs(tmp / "cfg", exist_ok=True)

        # -- name helpers
        check(N.sort_name("Show.Name.S02E05.mkv") == "Show Name/Season 2/Show.Name.S02E05.mkv", "sort_name SxxExx")
        check(N.sort_name("Big Show 3x07 title.mkv") == "Big Show/Season 3/Big Show 3x07 title.mkv", "sort_name NxNN")
        check(N.sort_name("holiday.jpg") == "holiday.jpg", "sort_name leaves other files alone")
        check(N.safe_recv_path(str(tmp), "../x") is None and N.safe_recv_path(str(tmp), "a/../../x") is None, "path climb not refused")
        check(N.safe_recv_path(str(tmp), "a/b:c?.txt").endswith("a/b_c_.txt"), "bad characters not replaced")
        ok("name sorting and safe receive paths")

        # -- pairing: nothing paired yet
        check(not core.connect_phone("127.0.0.1"), "connected without any pairing")
        check("Pair with QR" in ui.phones[-1][0], "no-pairing message")
        # wrong code
        core.pair_secret, core.pair_secret_at = "0" * 32, N.time.time()
        check(not core.connect_phone("127.0.0.1"), "wrong code accepted")
        check("did not accept the pairing" in ui.phones[-1][0] and core.pair_secret is None, "wrong code message / secret not cleared")
        # right code
        core.pair_secret, core.pair_secret_at = FakePhone.CODE, N.time.time()
        check(core.connect_phone("127.0.0.1"), "pairing with the right code failed: " + str(ui.phones[-1]))
        check(core.pair_secret is None, "QR secret must work only once")
        core.close_conn()
        kf = tmp / "cfg" / "pairing-key.dat"
        check(kf.exists() and stat.S_IMODE(kf.stat().st_mode) == 0o600, "pairing key not saved with 0600")
        check(core.connect_phone("127.0.0.1"), "reconnect with the saved key failed")
        core.close_conn()
        core2 = N.Core(TUi(), cfgdir=str(tmp / "cfg"))
        check(core2.pair_key == core.pair_key, "saved key not loaded by a fresh start")
        ok("pairing (wrong code, right code, saved key, key file mode 0600)")

        # -- send
        src = tmp / "MyShow"
        (src / "sub").mkdir(parents=True)
        (src / "Show.Name.S02E05.mkv").write_bytes(os.urandom(3_000_000))
        (src / "sub" / "a.txt").write_bytes(b"hello")
        (src / "empty.bin").write_bytes(b"")
        (src / "odd\nname.txt").write_bytes(b"x")
        core.send(str(src), "127.0.0.1", True, True, None)
        dest = tmp / "phone/NightSend/MyShow"
        check(sha(dest / "Show Name/Season 2/Show.Name.S02E05.mkv") == sha(src / "Show.Name.S02E05.mkv"), "big file differs on the phone")
        check((dest / "sub/a.txt").read_bytes() == b"hello", "sub folder not kept")
        check((dest / "empty.bin").exists(), "empty file not sent")
        check(any("line break" in l for l in ui.logs), "file name with a line break must be skipped")
        check(any("Done with 1 failed" in s for s in ui.statuses), "status should report the skipped file")
        ok("send: folders kept, auto-sort, empty file, unsafe name skipped")

        # -- send again: everything already there
        before = phone.puts
        ui.statuses.clear()
        core.send(str(src), "127.0.0.1", True, True, None)
        check(phone.puts == before and "Everything is already on the phone." in ui.statuses, "second send should skip everything")
        ok("send again skips what is already on the phone")

        # -- reconnect in the middle of a file
        src2 = tmp / "Second"
        src2.mkdir()
        (src2 / "big.bin").write_bytes(os.urandom(2_000_000))
        phone.drop_next_put = True
        N.time.sleep(0.01)
        core.send(str(src2), "127.0.0.1", True, False, None)
        check(any("Reconnecting (1 of 3)" in l for l in ui.logs), "no reconnect after the drop")
        check(sha(tmp / "phone/NightSend/Second/big.bin") == sha(src2 / "big.bin"), "file wrong after reconnect")
        ok("connection dropped mid-file: reconnects and finishes")

        # -- archive after a clean send
        src3 = tmp / "Third"
        src3.mkdir()
        (src3 / "f.txt").write_bytes(b"z")
        arch = tmp / "archive"
        core.send(str(src3), "127.0.0.1", True, False, str(arch))
        check((arch / "Third/f.txt").exists() and not src3.exists(), "folder not archived")
        core.send(str(arch / "Third"), "127.0.0.1", True, False, str(arch / "Third" / "inner"))
        check((arch / "Third").exists(), "archive inside the sent folder must not move anything")
        ok("archive moves a clean folder, refuses inside itself")

        # -- not enough space asks, and "no" stops
        small = FakePhone(tmp / "small", free=10)
        N.PORT = small.port
        ui_s = TUi()
        ui_s.answer = False
        cs = N.Core(ui_s, cfgdir=str(tmp / "cfg_s"))
        os.makedirs(tmp / "cfg_s", exist_ok=True)
        cs.pair_secret, cs.pair_secret_at = FakePhone.CODE, N.time.time()
        src4 = tmp / "Fourth"
        src4.mkdir()
        (src4 / "f.txt").write_bytes(b"0123456789abcdef")
        cs.send(str(src4), "127.0.0.1", True, False, None)
        check(any("CONFIRM: Not enough space" in l for l in ui_s.logs) and small.puts == 0, "space check")
        ok("not enough space on the phone asks first")
        N.PORT = phone.port

        # -- browse the phone's folders
        check(core.connect_phone("127.0.0.1"), "reconnect for browse")
        names = core.phone_dirs("/store/NightSend")
        check("MyShow" in names and "Second" in names, "DIRS: " + str(names))
        core.phone_mkdir("/store/NightSend/New")
        check((tmp / "phone/NightSend/New").is_dir(), "MKDIR")
        core.close_conn()
        core.dest_path = "/store/NightSend/New"
        src5 = tmp / "Fifth"
        src5.mkdir()
        (src5 / "g.txt").write_bytes(b"g")
        core.send(str(src5), "127.0.0.1", True, False, None)
        check((tmp / "phone/NightSend/New/Fifth/g.txt").exists(), "send into the picked phone folder")
        core.dest_path = ""
        ok("browse phone folders, make folder, send into the picked folder")

        # -- receive
        (tmp / "phone/Outbox/Pics").mkdir()
        (tmp / "phone/Outbox/Pics/a.jpg").write_bytes(os.urandom(700_000))
        (tmp / "phone/Outbox/b: odd?.txt").write_bytes(b"bbb")
        out = tmp / "got"
        core.receive(str(out), "127.0.0.1")
        check(sha(out / "Pics/a.jpg") == sha(tmp / "phone/Outbox/Pics/a.jpg"), "received file differs")
        check((out / "b_ odd_.txt").read_bytes() == b"bbb", "received name not made safe")
        check(not (tmp / "evil.txt").exists() and not (out.parent / "evil.txt").exists(), "a name climbing out was written")
        check(any("name not allowed" in l for l in ui.logs), "climbing name should be logged")
        check(not list(out.rglob("*.nspart")), "leftover .nspart file")
        ui.statuses.clear()
        core.receive(str(out), "127.0.0.1")
        check(any(s.startswith("Nothing new") for s in ui.statuses), "second receive should find nothing new")
        ok("receive: files kept, names made safe, climbing name refused, resumes by size")

        # -- strict mode keeps no key
        core.set_strict(True)
        check(core.pair_key is None and not kf.exists(), "strict mode must forget the key")
        core.pair_secret, core.pair_secret_at = FakePhone.CODE, N.time.time()
        check(core.connect_phone("127.0.0.1") and not kf.exists() and core.pair_key is None, "strict: nothing may be kept")
        core.close_conn()
        check(not core.connect_phone("127.0.0.1"), "strict: second session needs a new QR")
        core.set_strict(False)
        ok("strict mode remembers nothing")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    test_qr()
    test_java("--require-java" in sys.argv)
    test_flows()
    print("\nALL OK ({} groups)".format(len(PASSED)))


if __name__ == "__main__":
    main()
