# NightSend PC (v3.0 - encrypted + QR pairing + tray + keeps folders / auto-sort / pick the phone folder + no freezing + auto-reconnect)
# Sends a whole folder from this PC to the NightSend phone app.
# Both devices on the same Wi-Fi: the PC finds the phone by itself, you pair once by scanning a QR code with the phone. No internet, no cloud, no extra downloads.
# Skips files already on the phone, re-sends unfinished ones, phone checks every file's size.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()
# Any unexpected error is written to %APPDATA%\NightSend\crash.log instead of silently closing the app.
[System.Windows.Forms.Application]::SetUnhandledExceptionMode([System.Windows.Forms.UnhandledExceptionMode]::CatchException)
function Write-Crash([string]$m) {
    try {
        $d = Join-Path $env:APPDATA "NightSend"
        [void](New-Item -ItemType Directory -Force -Path $d)
        [IO.File]::AppendAllText((Join-Path $d "crash.log"), ((Get-Date -Format s) + "  " + $m + "`r`n"))
    } catch {}
}
[System.Windows.Forms.Application]::add_ThreadException({ param($s, $e) Write-Crash ("UI error: " + $e.Exception.ToString()) })

# Keeps Windows from sleeping while a transfer runs.
try {
    Add-Type -Namespace NS -Name Power -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint f);'
} catch {}
function Keep-Awake([bool]$on) {
    try { if ($on) { [void][NS.Power]::SetThreadExecutionState([uint32]2147483649) } else { [void][NS.Power]::SetThreadExecutionState([uint32]2147483648) } } catch {}
}

# ---------- NightSend protocol v2: key exchange + encrypted frames (same as Secure.java on the phone) ----------
Add-Type -AssemblyName System.Security
$NsCryptoSource = @'
//CS-BEGIN
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public class NsAuthException : Exception {
    public string Reply;
    public NsAuthException(string reply) : base(reply) { Reply = reply; }
}

public static class NsCrypto {
    public const int MaxPlain = 262144;
    public const int MaxFrame = 16 + 262144 + 16 + 32;

    public static byte[] Cat(params byte[][] parts) {
        int n = 0; foreach (byte[] p in parts) n += p.Length;
        byte[] r = new byte[n]; int o = 0;
        foreach (byte[] p in parts) { Buffer.BlockCopy(p, 0, r, o, p.Length); o += p.Length; }
        return r;
    }
    public static byte[] Utf8(string s) { return new UTF8Encoding(false).GetBytes(s); }
    public static byte[] Hmac(byte[] key, params byte[][] parts) {
        using (HMACSHA256 h = new HMACSHA256(key)) { return h.ComputeHash(Cat(parts)); }
    }
    public static byte[] Sha256(byte[] b) { using (SHA256 h = SHA256.Create()) { return h.ComputeHash(b); } }
    public static string Hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        foreach (byte x in b) sb.Append(x.ToString("x2"));
        return sb.ToString();
    }
    public static bool IsHex(string s, int len) {
        if (s == null || s.Length != len) return false;
        foreach (char c in s) { if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false; }
        return true;
    }
    public static byte[] FromHex(string s) {
        byte[] r = new byte[s.Length / 2];
        for (int i = 0; i < r.Length; i++) r[i] = Convert.ToByte(s.Substring(i * 2, 2), 16);
        return r;
    }
    public static bool Equal(byte[] a, byte[] b) {
        if (a.Length != b.Length) return false;
        int d = 0; for (int i = 0; i < a.Length; i++) d |= a[i] ^ b[i];
        return d == 0;
    }
    public static byte[] Seq(ulong n) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte)(n & 0xFF); n >>= 8; }
        return b;
    }
    public static string KeyId(byte[] pairKey) {
        byte[] h = Sha256(pairKey); byte[] r = new byte[8]; Buffer.BlockCopy(h, 0, r, 0, 8); return Hex(r);
    }

    public static ECDiffieHellmanCng NewKey() {
        ECDiffieHellmanCng k = new ECDiffieHellmanCng(256);
        k.KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash;
        k.HashAlgorithm = CngAlgorithm.Sha256;
        return k;
    }
    // 64 raw bytes: X then Y (the Windows blob has an 8 byte header in front)
    public static byte[] PubRaw(ECDiffieHellmanCng k) {
        byte[] blob = k.Key.Export(CngKeyBlobFormat.EccPublicBlob);
        byte[] raw = new byte[64]; Buffer.BlockCopy(blob, 8, raw, 0, 64); return raw;
    }
    // SHA-256 of the shared secret, the same value the phone derives
    public static byte[] Shared(ECDiffieHellmanCng k, byte[] peerRaw) {
        if (peerRaw.Length != 64) throw new IOException("bad public key");
        byte[] blob = new byte[72];
        blob[0] = 0x45; blob[1] = 0x43; blob[2] = 0x4B; blob[3] = 0x31; blob[4] = 0x20;   // "ECK1", 32 byte coordinates
        Buffer.BlockCopy(peerRaw, 0, blob, 8, 64);
        using (CngKey pk = CngKey.Import(blob, CngKeyBlobFormat.EccPublicBlob)) { return k.DeriveKeyMaterial(pk); }
    }

    public static string ReadLine(Stream s) {
        StringBuilder sb = new StringBuilder();
        byte[] one = new byte[1];
        while (true) {
            int n = s.Read(one, 0, 1);
            if (n <= 0) { if (sb.Length == 0) return null; break; }
            if (one[0] == 10) break;
            if (one[0] != 13) sb.Append((char)one[0]);
            if (sb.Length > 1024) throw new IOException("line too long");
        }
        return sb.ToString();
    }
    public static void WriteLine(Stream s, string line) {
        byte[] b = Utf8(line + "\n"); s.Write(b, 0, b.Length); s.Flush();
    }

    // PC side. pairKey != null: use the saved key (AUTH). Otherwise use the one-time 128-bit pairing secret from the QR code (PAIR).
    public static SecureStream ClientHandshake(Stream raw, string code, byte[] pairKey, out byte[] newPairKey) {
        newPairKey = null;
        ECDiffieHellmanCng k = NewKey();
        byte[] pc = PubRaw(k);
        WriteLine(raw, "NS2 " + Hex(pc));
        string r = ReadLine(raw);
        if (r == null) throw new IOException("The phone closed the connection.");
        if (!IsHex(r, 128)) throw new NsAuthException("ERR version");
        byte[] ph = FromHex(r);
        byte[] t = Cat(pc, ph);
        byte[] zh = Shared(k, ph);
        byte[] key;
        if (pairKey != null) {
            key = pairKey;
            WriteLine(raw, "AUTH " + KeyId(pairKey) + " " + Hex(Hmac(key, Utf8("NS2-C"), t)));
        } else {
            key = Utf8(code);
            WriteLine(raw, "PAIR " + Hex(Hmac(key, Utf8("NS2-C"), t)));
        }
        string ok = ReadLine(raw);
        if (ok == null) throw new IOException("The phone closed the connection.");
        if (ok.StartsWith("ERR")) throw new NsAuthException(ok);
        if (!ok.StartsWith("OK ") || !IsHex(ok.Substring(3), 64)) throw new IOException("Unexpected answer from the phone.");
        if (!Equal(FromHex(ok.Substring(3)), Hmac(key, Utf8("NS2-S"), t))) throw new IOException("The phone could not prove who it is. Not trusted.");
        byte[] master = Hmac(key, Utf8("NS2-MASTER"), zh, t);
        newPairKey = pairKey != null ? pairKey : Hmac(zh, Utf8("NS2-PAIRKEY"), t);
        return new SecureStream(raw,
            Hmac(master, Utf8("c2s-enc")), Hmac(master, Utf8("c2s-mac")),
            Hmac(master, Utf8("s2c-enc")), Hmac(master, Utf8("s2c-mac")));
    }

    // ---- self test (used by the build, never by the app): plays the phone over loopback ----
    static void ServerRound(TcpClient c, string code, ref byte[] stored) {
        NetworkStream raw = c.GetStream();
        string first = ReadLine(raw);
        byte[] pc = FromHex(first.Substring(4));
        ECDiffieHellmanCng k = NewKey();
        byte[] ph = PubRaw(k); byte[] zh = Shared(k, pc);
        WriteLine(raw, Hex(ph));
        string[] w = ReadLine(raw).Split(' ');
        byte[] t = Cat(pc, ph);
        bool pairing = w[0] == "PAIR";
        byte[] key = pairing ? Utf8(code) : stored;
        string proof = pairing ? w[1] : w[2];
        if (key == null || !Equal(FromHex(proof), Hmac(key, Utf8("NS2-C"), t))) { WriteLine(raw, pairing ? "ERR code" : "ERR auth"); return; }
        WriteLine(raw, "OK " + Hex(Hmac(key, Utf8("NS2-S"), t)));
        if (pairing) stored = Hmac(zh, Utf8("NS2-PAIRKEY"), t);
        byte[] master = Hmac(key, Utf8("NS2-MASTER"), zh, t);
        SecureStream s = new SecureStream(raw,
            Hmac(master, Utf8("s2c-enc")), Hmac(master, Utf8("s2c-mac")),
            Hmac(master, Utf8("c2s-enc")), Hmac(master, Utf8("c2s-mac")));
        string cmd = ReadLine(s);
        byte[] buf = new byte[1000000]; int got = 0;
        while (got < buf.Length) { int n = s.Read(buf, got, buf.Length - got); if (n <= 0) throw new IOException("eof"); got += n; }
        WriteLine(s, "ECHO " + cmd + " " + Hex(Sha256(buf)));
    }

    public static string SelfTest() {
        if (NsQr.Check() != "ab58fb4308d7ab7a050645c269e34e918ef4a81b4a5477d5a9ac6e052257cd0a") return "FAIL: QR code picture is not what the reference makes";
        TcpListener l = new TcpListener(IPAddress.Loopback, 0); l.Start();
        int port = ((IPEndPoint)l.LocalEndpoint).Port;
        string error = null; byte[] stored = null;
        Thread th = new Thread(delegate() {
            try { for (int i = 0; i < 3; i++) { using (TcpClient c = l.AcceptTcpClient()) { ServerRound(c, "0123456789abcdef0123456789abcdef", ref stored); } } }
            catch (Exception e) { error = "server: " + e.ToString(); }
        });
        th.Start();
        try {
            byte[] np;
            // 1: wrong code is refused
            using (TcpClient c = new TcpClient("127.0.0.1", port)) {
                try { ClientHandshake(c.GetStream(), "00000000000000000000000000000000", null, out np); return "FAIL: wrong code was accepted"; }
                catch (NsAuthException e) { if (e.Reply != "ERR code") return "FAIL: " + e.Reply; }
            }
            // 2: pair with the code, send 1 MB, check the phone saw the same bytes
            byte[] key = null; byte[] data = new byte[1000000]; new Random(7).NextBytes(data);
            using (TcpClient c = new TcpClient("127.0.0.1", port)) {
                SecureStream s = ClientHandshake(c.GetStream(), "0123456789abcdef0123456789abcdef", null, out key);
                WriteLine(s, "HELLO"); s.Write(data, 0, data.Length); s.Flush();
                if (ReadLine(s) != "ECHO HELLO " + Hex(Sha256(data))) return "FAIL: pair round data mismatch";
            }
            // 3: come back with the saved key only
            using (TcpClient c = new TcpClient("127.0.0.1", port)) {
                SecureStream s = ClientHandshake(c.GetStream(), "", key, out np);
                WriteLine(s, "AGAIN"); s.Write(data, 0, data.Length); s.Flush();
                if (ReadLine(s) != "ECHO AGAIN " + Hex(Sha256(data))) return "FAIL: key round data mismatch";
            }
        } catch (Exception e) { return "FAIL: " + e.ToString(); }
        th.Join(10000); l.Stop();
        return error == null ? "OK" : "FAIL: " + error;
    }
}

public class SecureStream : Stream {
    Stream inner; byte[] sEnc, sMac, rEnc, rMac;
    ulong sSeq = 0, rSeq = 0;
    byte[] rbuf = new byte[0]; int rpos = 0;
    object wlock = new object();
    static RandomNumberGenerator rng = RandomNumberGenerator.Create();

    public SecureStream(Stream inner, byte[] sEnc, byte[] sMac, byte[] rEnc, byte[] rMac) {
        this.inner = inner; this.sEnc = sEnc; this.sMac = sMac; this.rEnc = rEnc; this.rMac = rMac;
    }
    public bool DataAvailable {
        get {
            if (rpos < rbuf.Length) return true;
            NetworkStream ns = inner as NetworkStream;
            return ns != null && ns.DataAvailable;
        }
    }
    public override bool CanRead { get { return true; } }
    public override bool CanWrite { get { return true; } }
    public override bool CanSeek { get { return false; } }
    public override long Length { get { throw new NotSupportedException(); } }
    public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
    public override long Seek(long o, SeekOrigin so) { throw new NotSupportedException(); }
    public override void SetLength(long v) { throw new NotSupportedException(); }
    public override void Flush() { inner.Flush(); }

    public override void Write(byte[] buffer, int offset, int count) {
        lock (wlock) {
            while (count > 0) {
                int n = Math.Min(count, NsCrypto.MaxPlain);
                byte[] iv = new byte[16]; rng.GetBytes(iv);
                byte[] ct;
                using (Aes aes = Aes.Create()) {
                    aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    using (ICryptoTransform t = aes.CreateEncryptor(sEnc, iv)) { ct = t.TransformFinalBlock(buffer, offset, n); }
                }
                byte[] mac = NsCrypto.Hmac(sMac, NsCrypto.Seq(sSeq), iv, ct); sSeq++;
                int len = 16 + ct.Length + 32;
                byte[] f = new byte[4 + len];
                f[0] = (byte)(len >> 24); f[1] = (byte)(len >> 16); f[2] = (byte)(len >> 8); f[3] = (byte)len;
                Buffer.BlockCopy(iv, 0, f, 4, 16);
                Buffer.BlockCopy(ct, 0, f, 20, ct.Length);
                Buffer.BlockCopy(mac, 0, f, 20 + ct.Length, 32);
                inner.Write(f, 0, f.Length);
                offset += n; count -= n;
            }
        }
    }

    public override int Read(byte[] buffer, int offset, int count) {
        if (count == 0) return 0;
        if (rpos >= rbuf.Length) { if (!NextFrame()) return 0; }
        int n = Math.Min(count, rbuf.Length - rpos);
        Buffer.BlockCopy(rbuf, rpos, buffer, offset, n);
        rpos += n;
        return n;
    }

    byte[] ReadExact(int len, int have, byte[] f) {
        while (have < len) {
            int m = inner.Read(f, have, len - have);
            if (m <= 0) throw new IOException("connection closed");
            have += m;
        }
        return f;
    }

    bool NextFrame() {
        byte[] h = new byte[4];
        int g = inner.Read(h, 0, 4);
        if (g <= 0) return false;
        ReadExact(4, g, h);
        int len = (h[0] << 24) | (h[1] << 16) | (h[2] << 8) | h[3];
        if (len < 64 || len > NsCrypto.MaxFrame) throw new IOException("bad frame size");
        byte[] f = ReadExact(len, 0, new byte[len]);
        byte[] iv = new byte[16]; Buffer.BlockCopy(f, 0, iv, 0, 16);
        byte[] ct = new byte[len - 48]; Buffer.BlockCopy(f, 16, ct, 0, ct.Length);
        byte[] mac = new byte[32]; Buffer.BlockCopy(f, len - 32, mac, 0, 32);
        if (!NsCrypto.Equal(mac, NsCrypto.Hmac(rMac, NsCrypto.Seq(rSeq), iv, ct))) throw new IOException("bad frame signature");
        using (Aes aes = Aes.Create()) {
            aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
            using (ICryptoTransform t = aes.CreateDecryptor(rEnc, iv)) { rbuf = t.TransformFinalBlock(ct, 0, ct.Length); }
        }
        rpos = 0; rSeq++;
        return true;
    }
}
// QR code for pairing: version 3, error correction M, byte mode, up to 42 bytes. Checked at build time.
public static class NsQr {
    const int N = 29, DATA = 44, EC = 26;
    static int[] EXP = new int[512];
    static int[] LOG = new int[256];
    static NsQr() {
        int x = 1;
        for (int i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if ((x & 0x100) != 0) x ^= 0x11D; }
        for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    }
    static int GMul(int a, int b) { if (a == 0 || b == 0) return 0; return EXP[LOG[a] + LOG[b]]; }
    static int[] Generator(int deg) {
        int[] g = new int[] { 1 };
        for (int i = 0; i < deg; i++) {
            int[] ng = new int[g.Length + 1];
            for (int j = 0; j < g.Length; j++) { ng[j] ^= g[j]; ng[j + 1] ^= GMul(g[j], EXP[i]); }
            g = ng;
        }
        return g;
    }
    static int[] Remainder(int[] data, int deg) {
        int[] g = Generator(deg);
        int[] res = new int[data.Length + deg];
        Array.Copy(data, 0, res, 0, data.Length);
        for (int i = 0; i < data.Length; i++) {
            int c = res[i];
            if (c != 0) for (int j = 1; j < g.Length; j++) res[i + j] ^= GMul(g[j], c);
        }
        int[] r = new int[deg];
        Array.Copy(res, data.Length, r, 0, deg);
        return r;
    }
    static void Put(System.Collections.Generic.List<int> bits, int v, int n) { for (int i = n - 1; i >= 0; i--) bits.Add((v >> i) & 1); }
    static int[] Codewords(byte[] p) {
        if (p.Length > 42) throw new ArgumentException("payload too long");
        System.Collections.Generic.List<int> bits = new System.Collections.Generic.List<int>();
        Put(bits, 4, 4);
        Put(bits, p.Length, 8);
        for (int i = 0; i < p.Length; i++) Put(bits, p[i], 8);
        int cap = DATA * 8;
        Put(bits, 0, Math.Min(4, cap - bits.Count));
        while (bits.Count % 8 != 0) bits.Add(0);
        int[] all = new int[DATA + EC];
        int n = 0;
        for (int i = 0; i < bits.Count; i += 8) {
            int v = 0;
            for (int j = 0; j < 8; j++) v = (v << 1) | bits[i + j];
            all[n++] = v;
        }
        int k = 0;
        while (n < DATA) { all[n++] = (k % 2 == 0) ? 0xEC : 0x11; k++; }
        int[] data = new int[DATA];
        Array.Copy(all, 0, data, 0, DATA);
        int[] ec = Remainder(data, EC);
        Array.Copy(ec, 0, all, DATA, EC);
        return all;
    }
    static void SetF(bool[,] m, bool[,] f, int r, int c, bool v) { m[r, c] = v; f[r, c] = true; }
    static void Blank(bool[,] m, bool[,] f) {
        int[][] corners = new int[][] { new int[] { 0, 0 }, new int[] { 0, N - 7 }, new int[] { N - 7, 0 } };
        foreach (int[] co in corners) {
            for (int dr = -1; dr <= 7; dr++) for (int dc = -1; dc <= 7; dc++) {
                int r = co[0] + dr, c = co[1] + dc;
                if (r >= 0 && r < N && c >= 0 && c < N) {
                    bool inside = dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6;
                    bool dark = inside && (dr == 0 || dr == 6 || dc == 0 || dc == 6 || (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4));
                    SetF(m, f, r, c, dark);
                }
            }
        }
        for (int i = 8; i < N - 8; i++) { SetF(m, f, 6, i, i % 2 == 0); SetF(m, f, i, 6, i % 2 == 0); }
        for (int dr = -2; dr <= 2; dr++) for (int dc = -2; dc <= 2; dc++)
            SetF(m, f, 22 + dr, 22 + dc, Math.Max(Math.Abs(dr), Math.Abs(dc)) != 1);
        for (int i = 0; i < 9; i++) { f[8, i] = true; f[i, 8] = true; }
        for (int i = 0; i < 8; i++) { f[8, N - 1 - i] = true; f[N - 1 - i, 8] = true; }
        SetF(m, f, N - 8, 8, true);
    }
    static void PlaceData(bool[,] m, bool[,] f, int[] cws) {
        int total = cws.Length * 8 + 7;
        int[] bits = new int[total];
        int n = 0;
        foreach (int cw in cws) for (int i = 7; i >= 0; i--) bits[n++] = (cw >> i) & 1;
        int idx = 0;
        int c = N - 1;
        bool up = true;
        while (c > 0) {
            if (c == 6) c--;
            for (int k = 0; k < N; k++) {
                int r = up ? N - 1 - k : k;
                for (int d = 0; d < 2; d++) {
                    int cc = c - d;
                    if (!f[r, cc]) { m[r, cc] = idx < total && bits[idx] == 1; idx++; }
                }
            }
            up = !up;
            c -= 2;
        }
    }
    static bool MaskBit(int mask, int r, int c) {
        switch (mask) {
            case 0: return (r + c) % 2 == 0;
            case 1: return r % 2 == 0;
            case 2: return c % 3 == 0;
            case 3: return (r + c) % 3 == 0;
            case 4: return (r / 2 + c / 3) % 2 == 0;
            case 5: return (r * c) % 2 + (r * c) % 3 == 0;
            case 6: return ((r * c) % 2 + (r * c) % 3) % 2 == 0;
            default: return ((r + c) % 2 + (r * c) % 3) % 2 == 0;
        }
    }
    static bool[,] ApplyMask(bool[,] m, bool[,] f, int mask) {
        bool[,] o = new bool[N, N];
        for (int r = 0; r < N; r++) for (int c = 0; c < N; c++) {
            o[r, c] = m[r, c];
            if (!f[r, c] && MaskBit(mask, r, c)) o[r, c] = !o[r, c];
        }
        return o;
    }
    static int FormatBits(int mask) {
        int data = mask;
        int rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        return ((data << 10) | rem) ^ 0x5412;
    }
    static bool FBit(int bits, int i) { return ((bits >> i) & 1) != 0; }
    static void DrawFormat(bool[,] m, int mask) {
        int bits = FormatBits(mask);
        for (int i = 0; i < 6; i++) m[i, 8] = FBit(bits, i);
        m[7, 8] = FBit(bits, 6); m[8, 8] = FBit(bits, 7); m[8, 7] = FBit(bits, 8);
        for (int i = 9; i < 15; i++) m[8, 14 - i] = FBit(bits, i);
        for (int i = 0; i < 8; i++) m[8, N - 1 - i] = FBit(bits, i);
        for (int i = 8; i < 15; i++) m[N - 15 + i, 8] = FBit(bits, i);
        m[N - 8, 8] = true;
    }
    static bool[] PAT1 = new bool[] { true, false, true, true, true, false, true, false, false, false, false };
    static bool[] PAT2 = new bool[] { false, false, false, false, true, false, true, true, true, false, true };
    static int Penalty(bool[,] m) {
        int s = 0;
        for (int pass = 0; pass < 2; pass++) {
            for (int a = 0; a < N; a++) {
                bool[] line = new bool[N];
                for (int b = 0; b < N; b++) line[b] = pass == 0 ? m[a, b] : m[b, a];
                int run = 1;
                for (int i = 1; i < N; i++) {
                    if (line[i] == line[i - 1]) run++;
                    else { if (run >= 5) s += 3 + (run - 5); run = 1; }
                }
                if (run >= 5) s += 3 + (run - 5);
                for (int i = 0; i + 11 <= N; i++) {
                    bool e1 = true, e2 = true;
                    for (int j = 0; j < 11; j++) { if (line[i + j] != PAT1[j]) e1 = false; if (line[i + j] != PAT2[j]) e2 = false; }
                    if (e1 || e2) s += 40;
                }
            }
        }
        for (int r = 0; r < N - 1; r++) for (int c = 0; c < N - 1; c++)
            if (m[r, c] == m[r, c + 1] && m[r, c] == m[r + 1, c] && m[r, c] == m[r + 1, c + 1]) s += 3;
        int dark = 0;
        for (int r = 0; r < N; r++) for (int c = 0; c < N; c++) if (m[r, c]) dark++;
        int total = N * N;
        int k = (Math.Abs(dark * 20 - total * 10) + total - 1) / total - 1;
        s += k * 10;
        return s;
    }
    // Returns the 29 x 29 module grid (true = dark). No quiet zone.
    public static bool[,] Encode(byte[] payload) {
        bool[,] m = new bool[N, N];
        bool[,] f = new bool[N, N];
        Blank(m, f);
        PlaceData(m, f, Codewords(payload));
        bool[,] best = null; int bestP = 0;
        for (int mask = 0; mask < 8; mask++) {
            bool[,] t = ApplyMask(m, f, mask);
            DrawFormat(t, mask);
            int p = Penalty(t);
            if (best == null || p < bestP) { best = t; bestP = p; }
        }
        return best;
    }
    // Used by the build self-test: a fixed text must always give exactly this picture.
    public static string Check() {
        bool[,] m = Encode(Encoding.UTF8.GetBytes("NS3:00112233445566778899aabbccddeeff"));
        StringBuilder sb = new StringBuilder();
        for (int r = 0; r < N; r++) {
            if (r > 0) sb.Append('\n');
            for (int c = 0; c < N; c++) sb.Append(m[r, c] ? '1' : '0');
        }
        using (SHA256 h = SHA256.Create()) {
            byte[] d = h.ComputeHash(Encoding.UTF8.GetBytes(sb.ToString()));
            StringBuilder o = new StringBuilder();
            foreach (byte b in d) o.Append(b.ToString("x2"));
            return o.ToString();
        }
    }
}
//CS-END
'@
Add-Type -ReferencedAssemblies System.Core -TypeDefinition $NsCryptoSource
$script:Quit = $false

$Port = 47800
# After the first pairing the PC keeps a secret key (locked to this Windows user) instead of the code.
$CodeDir = Join-Path $env:APPDATA "NightSend"
$KeyFile = Join-Path $CodeDir "pairing-key.dat"
try { [void](New-Item -ItemType Directory -Force -Path $CodeDir) } catch {}
$script:PairKey = $null
try {
    if (Test-Path -LiteralPath $KeyFile) {
        $script:PairKey = [Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($KeyFile), $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)
    }
} catch { $script:PairKey = $null }
function Save-PairKey($key) {
    $script:PairKey = $key
    try { [IO.File]::WriteAllBytes($KeyFile, [Security.Cryptography.ProtectedData]::Protect($key, $null, [Security.Cryptography.DataProtectionScope]::CurrentUser)) } catch {}
}
$script:PairSecret = $null; $script:PairSecretAt = $null
function New-PairSecret {
    $b = New-Object byte[] 16
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $rng.GetBytes($b); $rng.Dispose()
    (($b | ForEach-Object { $_.ToString("x2") }) -join "")
}
$StrictFile = Join-Path $CodeDir "strict.flag"
$script:Strict = $false
try { $script:Strict = Test-Path -LiteralPath $StrictFile } catch {}
if ($script:Strict) { $script:PairKey = $null }   # strict: nothing is remembered between sessions
function Forget-PairKey { $script:PairKey = $null; try { Remove-Item -LiteralPath $KeyFile -Force -ErrorAction SilentlyContinue } catch {} }
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Tcp = $null; $script:Ns = $null; $script:Rd = $null
$script:PhoneIp = $null; $script:PhoneFree = -1; $script:PhonePath = ""; $script:PhoneRoot = ""; $script:DestPath = ""
$script:Queue = New-Object System.Collections.ArrayList
$script:Failed = New-Object System.Collections.ArrayList
$script:Index = 0; $script:Fs = $null; $script:Left = [int64]0
$script:TotalBytes = [int64]0; $script:DoneBytes = [int64]0; $script:CurBytes = [int64]0
$script:StartTime = $null; $script:Running = $false
$script:Pend = $null; $script:PendN = 0; $script:AwaitOk = $false; $script:OkSince = $null
$script:Retries = 0; $script:RetryAt = $null; $script:LastProgress = Get-Date
$script:Buf = New-Object byte[] (1MB)

# ---------- colours ----------
$cBg     = [Drawing.Color]::FromArgb(0,0,0)
$cPanel  = [Drawing.Color]::FromArgb(28,28,28)
$cText   = [Drawing.Color]::FromArgb(220,220,225)
$cDim    = [Drawing.Color]::FromArgb(130,130,140)
$cAccent = [Drawing.Color]::FromArgb(35,41,93)
$cBad    = [Drawing.Color]::FromArgb(220,70,80)
$cGood   = [Drawing.Color]::FromArgb(90,170,110)
$fUi     = New-Object Drawing.Font("Segoe UI", 10)
$fBold   = New-Object Drawing.Font("Segoe UI Semibold", 10)

# ---------- helpers ----------
function Log([string]$msg) { $txtLog.AppendText((Get-Date -Format "HH:mm:ss") + "  " + $msg + "`r`n") }

function Fmt([double]$b) {
    $u = "B","KB","MB","GB","TB"; $i = 0
    while ($b -ge 1024 -and $i -lt 4) { $b /= 1024; $i++ }
    "{0:N1} {1}" -f $b, $u[$i]
}

function Send-Line([string]$s) {
    $bytes = $Utf8.GetBytes($s + "`n")
    $script:Ns.Write($bytes, 0, $bytes.Length)
    $script:Ns.Flush()
}

function Close-Conn {
    try { if ($script:Ns) { Send-Line "BYE" } } catch {}
    try { if ($script:Tcp) { $script:Tcp.Close() } } catch {}
    $script:Tcp = $null; $script:Ns = $null; $script:Rd = $null
}

function Open-Conn([string]$ip) {
    Close-Conn
    $t = New-Object Net.Sockets.TcpClient
    $t.SendBufferSize = 1MB
    $t.ReceiveTimeout = 30000
    $t.SendTimeout = 30000
    $ar = $t.BeginConnect($ip, $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(3000)) { $t.Close(); throw "Phone did not answer at $ip" }
    $t.EndConnect($ar)
    $script:Tcp = $t
    $script:Ns = $t.GetStream()
    $script:Rd = New-Object IO.StreamReader($script:Ns, $Utf8)
}

function Say-Hello {
    if ($script:PairSecret -and ((Get-Date) - $script:PairSecretAt).TotalMinutes -gt 10) { $script:PairSecret = $null }
    $code = $script:PairSecret
    if (-not $script:PairKey -and -not $code) { throw "Press 'Pair with QR', scan the picture with the NightSend phone app, then press Find phone." }
    $useKey = $script:PairKey
    if ($code) { $useKey = $null }   # a fresh QR pairing always wins over an old saved key
    $newKey = $null
    try {
        $sec = [NsCrypto]::ClientHandshake($script:Ns, $code, $useKey, [ref]$newKey)
    } catch {
        $e = $_.Exception
        while ($e.InnerException) { $e = $e.InnerException }
        if ($e -is [NsAuthException]) {
            if ($e.Reply -eq "ERR auth") { throw "The phone does not know this PC (forgotten, strict mode on the phone, or not your phone). Press 'Pair with QR' and scan it on the phone." }
            if ($e.Reply -eq "ERR code") { $script:PairSecret = $null; throw "The phone did not accept the pairing. On the phone tap 'Scan the PC's QR code' first, then press Find phone. If it still fails press 'Pair with QR' again for a new picture." }
            throw "The phone has an older NightSend. Install the newest NightSend.apk from Releases."
        }
        throw $e.Message
    }
    $script:Ns = $sec
    $script:Rd = New-Object IO.StreamReader($sec, $Utf8)
    $script:PairSecret = $null   # the QR secret works once
    # strict mode: the key is not kept, the next session needs a new QR
    if ($script:Strict) { Forget-PairKey } elseif ($newKey -and (-not $script:PairKey -or -not [NsCrypto]::Equal([byte[]]$newKey, [byte[]]$script:PairKey))) { Save-PairKey $newKey }
    Send-Line "HELLO"
    $r = $script:Rd.ReadLine()
    if (-not $r -or -not $r.StartsWith("NIGHTSEND|")) { throw "Not a NightSend phone." }
    $p = $r.Split("|")
    $script:PhoneFree = [int64]$p[2]
    $root = $p[3]; if ($p.Length -gt 5 -and $p[5]) { $root = $p[5] }
    return @{ Model = $p[1]; Free = [int64]$p[2]; Path = $p[3]; StorageOk = ($p[4] -eq "1"); Root = $root }
}

# Look for the phone: USB-tethering gateways first, then the PC hotspot range, then every local /24.
function Find-PhoneIp {
    $cands = New-Object System.Collections.ArrayList
    try {
        Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($g in $_.IPv4DefaultGateway) { if ($g.NextHop -and $g.NextHop -ne "0.0.0.0") { [void]$cands.Add($g.NextHop) } }
        }
    } catch {}
    $locals = @()
    try {
        $locals = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -ExpandProperty IPAddress
    } catch {}
    $prefixes = @($locals | ForEach-Object { ($_ -split "\.")[0..2] -join "." } | Sort-Object -Unique)
    $prefixes = @($prefixes | Sort-Object { if ($_ -eq "192.168.137") { 0 } else { 1 } })
    foreach ($pre in $prefixes) {
        for ($i = 1; $i -le 254; $i++) {
            $ip = "$pre.$i"
            if ($locals -notcontains $ip -and $cands -notcontains $ip) { [void]$cands.Add($ip) }
        }
    }
    Log ("Searching {0} addresses..." -f $cands.Count)
    $tries = @()
    foreach ($ip in $cands) {
        $c = New-Object Net.Sockets.TcpClient
        $tries += @{ Ip = $ip; Client = $c; Ar = $c.BeginConnect($ip, $Port, $null, $null) }
    }
    $deadline = (Get-Date).AddMilliseconds(2500)
    $found = $null
    while (-not $found -and (Get-Date) -lt $deadline) {
        foreach ($t in $tries) {
            if ($t.Ar.IsCompleted) {
                try { $t.Client.EndConnect($t.Ar); if ($t.Client.Connected) { $found = $t.Ip; break } } catch {}
            }
        }
        Start-Sleep -Milliseconds 100
        [Windows.Forms.Application]::DoEvents()
    }
    foreach ($t in $tries) { try { $t.Client.Close() } catch {} }
    return $found
}

function Set-Busy([bool]$busy) {
    $btnSend.Enabled = -not $busy; $btnFind.Enabled = -not $busy
    $btnBrowse.Enabled = -not $busy; $btnStop.Enabled = $busy; $btnPick.Enabled = -not $busy
    $chkRoot.Enabled = -not $busy; $chkSort.Enabled = -not $busy
    $btnRecv.Enabled = -not $busy; $btnRecvBrowse.Enabled = -not $busy
}

# ---------- connect ----------
function Connect-Phone {
    $lblPhone.Text = "Looking for the phone..."; $lblPhone.ForeColor = $cDim
    [Windows.Forms.Application]::DoEvents()
    $ip = $txtIp.Text.Trim()
    if (-not $ip) { $ip = Find-PhoneIp }
    if (-not $ip) {
        $lblPhone.Text = "Phone not found. Open NightSend on the phone and make sure the phone and this PC are on the same Wi-Fi."
        $lblPhone.ForeColor = $cBad
        return $false
    }
    try {
        Open-Conn $ip
        $h = Say-Hello
        $script:PhoneIp = $ip
        $script:PhonePath = $h.Path
        $script:PhoneRoot = $h.Root
        $txtIp.Text = $ip
        $lblPhone.Text = "Connected: {0}  -  {1} free  -  saving to {2}" -f $h.Model, (Fmt $h.Free), $h.Path
        $lblPhone.ForeColor = $cGood
        Log "Connected to $($h.Model) at $ip."
        if (-not $h.StorageOk) {
            $lblPhone.Text = "Connected, but the phone app needs storage permission. Tap 'Allow NightSend to save files' on the phone."
            $lblPhone.ForeColor = $cBad
            Close-Conn
            return $false
        }
        return $true
    } catch {
        $lblPhone.Text = "Could not connect: " + $_.Exception.Message
        $lblPhone.ForeColor = $cBad
        Close-Conn
        return $false
    }
}

# ---------- folder layout ----------
function Clean-Name([string]$n) { ($n -replace '[<>:"|?*]', '').Trim() }

# "Show.Name.S02E05.mkv" -> "Show Name/Season 2/Show.Name.S02E05.mkv"; anything else is left alone.
function Sort-Name([string]$name) {
    $m = [regex]::Match($name, '^(.+?)[ ._-]+[Ss](\d{1,2})[ ._-]?[Ee]\d{1,3}')
    if (-not $m.Success) { $m = [regex]::Match($name, '^(.+?)[ ._-]+(\d{1,2})x\d{1,3}') }
    if ($m.Success) {
        $show = Clean-Name ($m.Groups[1].Value -replace '[._]', ' ')
        if ($show) { return ("{0}/Season {1}/{2}" -f $show, [int]$m.Groups[2].Value, $name) }
    }
    return $name
}

# ---------- send ----------
function Start-Send {
    $src = $txtSrc.Text.Trim().TrimEnd("\")
    if (-not (Test-Path -LiteralPath $src -PathType Container)) { Log "Source folder not found."; return }
    $script:SendSrc = $src
    Set-Busy $true
    if (-not (Connect-Phone)) { Set-Busy $false; return }

    # Send into the folder picked on the phone (instead of the phone's save folder).
    if ($script:DestPath) {
        try {
            Send-Line ("DEST " + $script:DestPath)
            $r = $script:Rd.ReadLine()
            if (-not $r -or -not $r.StartsWith("OK")) { throw ("phone answered: " + $r) }
            $q = $r.Split("|"); if ($q.Length -gt 1) { $script:PhoneFree = [int64]$q[1] }
        } catch {
            Log ("The phone would not use that folder (" + $_.Exception.Message + "). If it says unknown command, update the NightSend phone app.")
            Close-Conn; Set-Busy $false; return
        }
    }

    $lblStatus.Text = "Reading files on the PC..."; [Windows.Forms.Application]::DoEvents()
    # Keep the chosen folder's own name (e.g. the show folder) unless the phone already saves into a folder of that name.
    $rootName = ""
    if ($chkRoot.Checked) {
        $leaf = Clean-Name (Split-Path $src -Leaf)
        $target = $script:PhonePath; if ($script:DestPath) { $target = $script:DestPath }
        $phoneLeaf = ($target -split "[/\\]")[-1]
        if ($leaf -and -not $leaf.EndsWith(":") -and $leaf -ne $phoneLeaf) { $rootName = $leaf }
    }
    $local = @(Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction SilentlyContinue)

    $lblStatus.Text = "Reading what is already on the phone..."; [Windows.Forms.Application]::DoEvents()
    $have = @{}
    try {
        Send-Line "LIST"
        while ($true) {
            $l = $script:Rd.ReadLine()
            if ($l -eq $null -or $l -eq "END") { break }
            $i = $l.IndexOf("|")
            if ($i -gt 0) { $have[$l.Substring($i + 1)] = [int64]$l.Substring(0, $i) }
        }
    } catch { Log ("Could not read phone files: " + $_.Exception.Message); Close-Conn; Set-Busy $false; return }

    $script:Queue.Clear(); $script:Failed.Clear()
    $script:TotalBytes = 0; $skipped = 0
    foreach ($f in $local) {
        $rel = $f.FullName.Substring($src.Length).TrimStart("\").Replace("\", "/")
        if ($chkSort.Checked -and $rel -notlike "*/*") { $rel = Sort-Name $rel }
        if ($rootName) { $rel = $rootName + "/" + $rel }
        if ($have.ContainsKey($rel) -and $have[$rel] -eq $f.Length) { $skipped++; continue }
        [void]$script:Queue.Add(@{ Local = $f.FullName; Rel = $rel; Size = [int64]$f.Length })
        $script:TotalBytes += $f.Length
    }
    Log ("{0} files on PC. {1} already on phone (skipped). {2} to send ({3})." -f $local.Count, $skipped, $script:Queue.Count, (Fmt $script:TotalBytes))

    if ($script:Queue.Count -eq 0) {
        $lblStatus.Text = "Everything is already on the phone."; $bar.Value = 1000
        Close-Conn; Set-Busy $false; return
    }
    if ($script:PhoneFree -ge 0 -and $script:PhoneFree -lt $script:TotalBytes) {
        $ans = [Windows.Forms.MessageBox]::Show(
            ("Not enough space on the phone.`r`nNeeded: {0}`r`nFree: {1}`r`n`r`nSend as much as fits anyway?" -f (Fmt $script:TotalBytes), (Fmt $script:PhoneFree)),
            "NightSend", "YesNo", "Warning")
        if ($ans -ne "Yes") { $lblStatus.Text = "Cancelled - not enough space."; Close-Conn; Set-Busy $false; return }
    }

    $script:Index = 0; $script:DoneBytes = 0; $script:CurBytes = 0
    $script:Pend = $null; $script:AwaitOk = $false; $script:Retries = 0; $script:RetryAt = $null; $script:LastProgress = Get-Date
    $script:StartTime = Get-Date; $script:Running = $true
    Keep-Awake $true
    Start-Next
    $timer.Start()
}

function Start-Next {
    while ($script:Index -lt $script:Queue.Count) {
        $item = $script:Queue[$script:Index]
        try {
            $script:Fs = [IO.File]::Open($item.Local, "Open", "Read", "Read")
            $lblFile.Text = $item.Rel
            Send-Line ("PUT {0} {1}" -f $item.Size, $item.Rel)
            $script:Left = $item.Size; $script:CurBytes = 0
            $script:LastProgress = Get-Date
            return
        } catch {
            if ($script:Fs) { try { $script:Fs.Close() } catch {}; $script:Fs = $null }
            if (-not $script:Tcp -or -not $script:Tcp.Connected) { Lost $_.Exception.Message; return }
            [void]$script:Failed.Add($item.Rel); Log ("SKIPPED (cannot read on PC): " + $item.Rel)
            $script:DoneBytes += $item.Size; $script:Index++
        }
    }
    Finish-Send
}

# The connection dropped or stalled: reconnect and carry on with the same file (up to 3 times in a row).
function Lost([string]$why) {
    $script:Pend = $null; $script:AwaitOk = $false
    if ($script:Fs) { try { $script:Fs.Close() } catch {}; $script:Fs = $null }
    $script:CurBytes = 0
    Write-Crash ("Connection lost: " + $why)
    if ($script:Retries -ge 3) { Abort-Send ("Connection lost: " + $why + " (gave up after 3 tries)."); return }
    $script:Retries++
    Log ("Connection lost: {0}. Reconnecting ({1} of 3)..." -f $why, $script:Retries)
    $lblStatus.Text = "Connection lost - reconnecting..."
    Close-Conn
    $script:RetryAt = (Get-Date).AddSeconds(3)
}

function Resume-Send {
    try {
        Open-Conn $script:PhoneIp
        [void](Say-Hello)
        if ($script:DestPath) {
            Send-Line ("DEST " + $script:DestPath)
            $r = $script:Rd.ReadLine()
            if (-not $r -or -not $r.StartsWith("OK")) { throw "phone refused the folder" }
        }
    } catch { Lost $_.Exception.Message; return }
    Log "Reconnected. Continuing."
    Start-Next
}

# Never blocks the window: writes are asynchronous and each tick returns quickly.
function On-Tick {
    if (-not $script:Running) { return }
    if ($script:RetryAt) {
        if ((Get-Date) -lt $script:RetryAt) { return }
        $script:RetryAt = $null
        Resume-Send
        return
    }
    if (-not $script:Fs -and -not $script:AwaitOk) { return }
    $item = $script:Queue[$script:Index]
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($sw.ElapsedMilliseconds -lt 100) {
            if ($script:Pend) {
                if (-not $script:Pend.IsCompleted) {
                    if (((Get-Date) - $script:LastProgress).TotalSeconds -gt 20) { throw "no progress for 20 seconds" }
                    break
                }
                $script:Ns.EndWrite($script:Pend); $script:Pend = $null
                $script:Left -= $script:PendN; $script:CurBytes += $script:PendN
                $script:LastProgress = Get-Date
                continue
            }
            if ($script:AwaitOk) {
                if ($script:Ns.DataAvailable) {
                    $resp = $script:Rd.ReadLine()
                    $script:AwaitOk = $false
                    if ($resp -eq $null -or $resp.StartsWith("ERR !")) { Lost "phone stopped answering"; return }
                    if ($resp -ne "OK") { [void]$script:Failed.Add($item.Rel); Log ("FAILED on phone: {0}  ({1})" -f $item.Rel, $resp) }
                    $script:DoneBytes += $item.Size; $script:CurBytes = 0; $script:Index++
                    $script:Retries = 0; $script:LastProgress = Get-Date
                    Update-Progress
                    Start-Next
                    return
                }
                if (((Get-Date) - $script:OkSince).TotalSeconds -gt 120) { throw "phone did not confirm the file" }
                break
            }
            if ($script:Left -le 0) {
                $script:Fs.Close(); $script:Fs = $null
                $script:AwaitOk = $true; $script:OkSince = Get-Date
                continue
            }
            $want = [int][Math]::Min([int64]$script:Buf.Length, [int64]$script:Left)
            $n = $script:Fs.Read($script:Buf, 0, $want)
            if ($n -le 0) { throw "File got shorter while sending: $($item.Rel)" }
            $script:PendN = $n
            $script:Pend = $script:Ns.BeginWrite($script:Buf, 0, $n, $null, $null)
            [void]$script:Pend.AsyncWaitHandle.WaitOne(40)
        }
        Update-Progress
    } catch {
        Lost $_.Exception.Message
    }
}

function Update-Progress {
    $done = $script:DoneBytes + $script:CurBytes
    if ($script:TotalBytes -gt 0) { $bar.Value = [int][Math]::Min(1000, ($done * 1000 / $script:TotalBytes)) }
    $secs = ((Get-Date) - $script:StartTime).TotalSeconds
    $speed = 0; if ($secs -gt 1) { $speed = $done / $secs }
    $eta = ""
    if ($speed -gt 0) {
        $left = [TimeSpan]::FromSeconds([Math]::Min(359999, [Math]::Max(0, ($script:TotalBytes - $done) / $speed)))
        $eta = "  -  about {0}h {1}m left" -f [int][Math]::Floor($left.TotalHours), $left.Minutes
    }
    $lblStatus.Text = ("File {0} of {1}  -  {2} of {3}  -  {4}/s{5}" -f
        [Math]::Min($script:Index + 1, $script:Queue.Count), $script:Queue.Count,
        (Fmt $done), (Fmt $script:TotalBytes), (Fmt $speed), $eta)
}

# Optional: after a send where every file was checked by the phone, move the folder into the archive folder.
# Same drive only (a rename, so nothing is copied or deleted). Nothing is ever removed.
$script:SendSrc = $null
function Archive-Source {
    $src = $script:SendSrc
    if (-not $chkArchive.Checked -or -not $src) { return }
    try {
        $dest = $txtArchive.Text.Trim().TrimEnd("\")
        if (-not $dest) { Log "Archive: no archive folder chosen. Nothing moved."; return }
        $srcFull = [IO.Path]::GetFullPath($src).TrimEnd("\")
        $destFull = [IO.Path]::GetFullPath($dest).TrimEnd("\")
        if ($srcFull.Length -le 3) { Log "Archive: will not move a whole drive. Nothing moved."; return }
        if ($destFull -eq $srcFull -or $destFull.StartsWith($srcFull + "\", [StringComparison]::OrdinalIgnoreCase)) { Log "Archive: the archive folder is inside the folder you sent. Nothing moved."; return }
        if ([IO.Path]::GetPathRoot($srcFull) -ne [IO.Path]::GetPathRoot($destFull)) { Log "Archive: the archive folder is on a different drive, so nothing was moved. Pick a folder on the same drive as the sent folder."; return }
        [void](New-Item -ItemType Directory -Force -Path $destFull)
        $name = Split-Path $srcFull -Leaf
        $target = Join-Path $destFull $name
        if (Test-Path -LiteralPath $target) { $target = Join-Path $destFull ($name + "_" + (Get-Date -Format "yyyyMMdd-HHmmss")) }
        [IO.Directory]::Move($srcFull, $target)
        Log ("Archived: moved " + $srcFull + " to " + $target + ". Nothing was deleted.")
        $script:SendSrc = $null
    } catch {
        Log ("Archive: could not move the folder (" + $_.Exception.Message + "). Files may be open in another program. Nothing was deleted.")
    }
}

function Finish-Send {
    $timer.Stop(); $script:Running = $false; Keep-Awake $false
    Close-Conn
    $bar.Value = 1000; $lblFile.Text = ""
    if ($script:Failed.Count -eq 0) {
        $lblStatus.Text = "Done. All files sent and checked."
        Log "DONE - all files sent and size-checked by the phone."
        Archive-Source
    } else {
        $lblStatus.Text = "Done with $($script:Failed.Count) failed file(s). Press SEND again to retry them."
        Log "Finished. $($script:Failed.Count) file(s) failed - press SEND again to retry only those."
    }
    Set-Busy $false
    Tray-Note "NightSend" $lblStatus.Text
}

function Abort-Send([string]$why) {
    $script:RecvStop = $true
    $timer.Stop(); $script:Running = $false; Keep-Awake $false
    $script:Pend = $null; $script:AwaitOk = $false; $script:RetryAt = $null
    if ($script:Fs) { try { $script:Fs.Close() } catch {}; $script:Fs = $null }
    Close-Conn
    $lblStatus.Text = "Stopped. Press SEND to continue where it left off."
    Log ($why + "  Next SEND skips finished files.")
    Set-Busy $false
    Tray-Note "NightSend stopped" $lblStatus.Text
}

# ---------- pick the folder on the phone ----------
function Get-PhoneDirs([string]$path) {
    Send-Line ("DIRS " + $path)
    $names = New-Object System.Collections.ArrayList
    while ($true) {
        $l = $script:Rd.ReadLine()
        if ($l -eq $null -or $l -eq "END") { break }
        if ($l.StartsWith("ERR")) { throw $l }
        [void]$names.Add($l)
    }
    return ,$names
}

function Ask-Text([string]$title) {
    $f = New-Object Windows.Forms.Form
    $f.Text = $title; $f.ClientSize = New-Object Drawing.Size(360, 90); $f.StartPosition = "CenterParent"
    $f.FormBorderStyle = "FixedDialog"; $f.MaximizeBox = $false; $f.MinimizeBox = $false
    $f.BackColor = $cBg; $f.ForeColor = $cText; $f.Font = $fUi
    $t = New-Object Windows.Forms.TextBox; $t.Location = New-Object Drawing.Point(16, 14); $t.Size = New-Object Drawing.Size(328, 28)
    $t.BackColor = $cPanel; $t.ForeColor = $cText; $t.BorderStyle = "FixedSingle"; $f.Controls.Add($t)
    $ok = New-Object Windows.Forms.Button; $ok.Text = "OK"; $ok.Location = New-Object Drawing.Point(16, 50); $ok.Size = New-Object Drawing.Size(110, 30)
    $ok.FlatStyle = "Flat"; $ok.BackColor = $cAccent; $ok.ForeColor = $cText; $ok.DialogResult = "OK"; $f.Controls.Add($ok)
    $f.AcceptButton = $ok
    $res = $null
    if ($f.ShowDialog($form) -eq "OK") { $res = $t.Text.Trim() }
    $f.Dispose()
    return $res
}

function Pick-PhoneFolder {
    Set-Busy $true; $btnStop.Enabled = $false
    try {
        if (-not (Connect-Phone)) { return }
        $root = $script:PhoneRoot.TrimEnd("/")
        $script:DlgPath = $script:PhonePath
        if ($script:DestPath) { $script:DlgPath = $script:DestPath }
        $script:DlgChoice = $null

        $dlg = New-Object Windows.Forms.Form
        $dlg.Text = "Pick the folder on the phone"; $dlg.ClientSize = New-Object Drawing.Size(560, 490)
        $dlg.BackColor = $cBg; $dlg.ForeColor = $cText; $dlg.Font = $fUi; $dlg.StartPosition = "CenterParent"
        $dlg.FormBorderStyle = "FixedDialog"; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
        $lblP = New-Object Windows.Forms.Label
        $lblP.Location = New-Object Drawing.Point(16, 12); $lblP.Size = New-Object Drawing.Size(528, 44); $lblP.ForeColor = $cDim
        $dlg.Controls.Add($lblP)
        $list = New-Object Windows.Forms.ListBox
        $list.Location = New-Object Drawing.Point(16, 60); $list.Size = New-Object Drawing.Size(528, 330)
        $list.BackColor = $cPanel; $list.ForeColor = $cText; $list.BorderStyle = "FixedSingle"
        $dlg.Controls.Add($list)
        $mk = {
            param($t, $x, $y, $w)
            $b = New-Object Windows.Forms.Button
            $b.Text = $t; $b.Location = New-Object Drawing.Point($x, $y); $b.Size = New-Object Drawing.Size($w, 32)
            $b.FlatStyle = "Flat"; $b.BackColor = $cPanel; $b.ForeColor = $cText; $b.FlatAppearance.BorderColor = $cAccent
            $dlg.Controls.Add($b); $b
        }
        $bUp = & $mk "Up" 16 400 90
        $bOpen = & $mk "Open" 112 400 90
        $bNew = & $mk "New folder" 208 400 130
        $bUse = & $mk "Use this folder" 16 442 170
        $bUse.BackColor = $cAccent
        $bDef = & $mk "Phone's save folder" 192 442 190
        $bCancel = & $mk "Cancel" 388 442 156

        $refresh = {
            try {
                # The phone may have dropped the idle connection while the window was open: reconnect once.
                if (-not $script:Tcp -or -not $script:Tcp.Connected) { if (-not (Connect-Phone)) { throw "phone not reachable" } }
                $names = Get-PhoneDirs $script:DlgPath
                $list.Items.Clear(); foreach ($n in $names) { [void]$list.Items.Add($n) }
                $lblP.Text = $script:DlgPath; $lblP.ForeColor = $cDim
                if ($list.Items.Count -eq 0) { [void]$list.Items.Add("(no folders here - press Use this folder, or New folder)") }
            } catch {
                $lblP.Text = "Could not read that folder: " + $_.Exception.Message + "   (If it says unknown command, update the phone app.)"
                $lblP.ForeColor = $cBad
            }
        }
        $open = {
            $n = $list.SelectedItem
            if ($n -and -not $n.StartsWith("(no folders")) { $script:DlgPath = $script:DlgPath.TrimEnd("/") + "/" + $n; & $refresh }
        }
        $bUp.Add_Click({
            $p = $script:DlgPath.TrimEnd("/")
            if ($p.Length -gt $root.Length) {
                $script:DlgPath = $p.Substring(0, $p.LastIndexOf("/"))
                if ($script:DlgPath.Length -lt $root.Length) { $script:DlgPath = $root }
                & $refresh
            }
        })
        $bOpen.Add_Click({ & $open })
        $list.Add_DoubleClick({ & $open })
        $bNew.Add_Click({
            $n = Ask-Text "Name of the new folder"
            if ($n) {
                $n = (Clean-Name $n) -replace "[/\\]", " "
                if ($n) {
                    $np = $script:DlgPath.TrimEnd("/") + "/" + $n
                    try {
                        Send-Line ("MKDIR " + $np)
                        $r = $script:Rd.ReadLine()
                        if ($r -eq "OK") { $script:DlgPath = $np } else { throw ("phone answered: " + $r) }
                    } catch { $lblP.Text = "Could not make the folder: " + $_.Exception.Message; $lblP.ForeColor = $cBad; return }
                    & $refresh
                }
            }
        })
        $bUse.Add_Click({ $script:DlgChoice = $script:DlgPath; $dlg.DialogResult = "OK" })
        $bDef.Add_Click({ $script:DlgChoice = ""; $dlg.DialogResult = "OK" })
        $bCancel.Add_Click({ $dlg.DialogResult = "Cancel" })
        & $refresh
        [void]$dlg.ShowDialog($form)
        $dlg.Dispose()
        if ($script:DlgChoice -ne $null) {
            if ($script:DlgChoice -eq $script:PhonePath) { $script:DlgChoice = "" }
            $script:DestPath = $script:DlgChoice
            if ($script:DestPath) { $txtDest.Text = $script:DestPath } else { $txtDest.Text = "(the phone's save folder)" }
        }
    } catch {
        Log ("Could not browse the phone: " + $_.Exception.Message)
    } finally {
        Close-Conn; Set-Busy $false
    }
}

# ---------- pairing QR ----------
function Show-PairQr {
    $script:PairSecret = New-PairSecret
    $script:PairSecretAt = Get-Date
    $mods = [NsQr]::Encode($Utf8.GetBytes("NS3:" + $script:PairSecret))
    $scale = 9; $quiet = 4; $n = 29
    $px = ($n + 2 * $quiet) * $scale
    $bmp = New-Object Drawing.Bitmap($px, $px)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.Clear([Drawing.Color]::White)
    $black = New-Object Drawing.SolidBrush([Drawing.Color]::Black)
    for ($r = 0; $r -lt $n; $r++) { for ($c = 0; $c -lt $n; $c++) {
        if ($mods[$r, $c]) { $g.FillRectangle($black, ($c + $quiet) * $scale, ($r + $quiet) * $scale, $scale, $scale) }
    } }
    $black.Dispose(); $g.Dispose()
    $dlg = New-Object Windows.Forms.Form
    $dlg.Text = "Pair with the phone"; $dlg.ClientSize = New-Object Drawing.Size(380, ($px + 150))
    $dlg.BackColor = $cBg; $dlg.ForeColor = $cText; $dlg.Font = $fUi
    $dlg.FormBorderStyle = "FixedDialog"; $dlg.MaximizeBox = $false; $dlg.MinimizeBox = $false
    $dlg.StartPosition = "CenterParent"
    $pb = New-Object Windows.Forms.PictureBox
    $pb.Image = $bmp; $pb.SizeMode = "Zoom"
    $pb.Location = New-Object Drawing.Point(([int]((380 - $px) / 2)), 12); $pb.Size = New-Object Drawing.Size($px, $px)
    $dlg.Controls.Add($pb)
    $help = New-Object Windows.Forms.Label
    $help.Text = "On the phone open NightSend and tap 'Scan the PC's QR code', then point the camera at this picture. Then come back and press Find phone. This picture works once."
    $help.Location = New-Object Drawing.Point(16, ($px + 20)); $help.Size = New-Object Drawing.Size(348, 60); $help.ForeColor = $cText
    $dlg.Controls.Add($help)
    $grp = ($script:PairSecret -replace "(.{4})(?=.)", '$1 ')
    $txt = New-Object Windows.Forms.Label
    $txt.Text = "No camera? On the phone choose 'Type the code instead':`n" + $grp
    $txt.Location = New-Object Drawing.Point(16, ($px + 84)); $txt.Size = New-Object Drawing.Size(348, 44); $txt.ForeColor = $cDim
    $txt.Font = New-Object Drawing.Font("Consolas", 9)
    $dlg.Controls.Add($txt)
    $ok = New-Object Windows.Forms.Button
    $ok.Text = "Done"; $ok.Location = New-Object Drawing.Point(140, ($px + 112)); $ok.Size = New-Object Drawing.Size(100, 28)
    $ok.FlatStyle = "Flat"; $ok.BackColor = $cPanel; $ok.ForeColor = $cText; $ok.FlatAppearance.BorderColor = $cAccent
    $ok.DialogResult = "OK"; $dlg.AcceptButton = $ok; $dlg.Controls.Add($ok)
    try { [void]$dlg.ShowDialog($form) } finally { $pb.Image = $null; $bmp.Dispose(); $dlg.Dispose() }
}

# ---------- receive from the phone ----------
$script:Receiving = $false; $script:RecvStop = $false

# A file name from the phone becomes a path that must stay inside the chosen PC folder (bad characters become _).
function Safe-RecvPath([string]$dest, [string]$rel) {
    $bad = [IO.Path]::GetInvalidFileNameChars()
    $parts = New-Object System.Collections.ArrayList
    foreach ($p in ($rel -split "[/\\]")) {
        if (-not $p -or $p -eq "." -or $p -eq "..") { return $null }
        $c = $p
        foreach ($ch in $bad) { $c = $c.Replace([string]$ch, "_") }
        $c = $c.TrimEnd(".", " ")
        if (-not $c) { return $null }
        [void]$parts.Add($c)
    }
    try {
        $full = [IO.Path]::GetFullPath((Join-Path $dest ($parts -join "\")))
        $root = [IO.Path]::GetFullPath($dest).TrimEnd("\") + "\"
    } catch { return $null }
    if (-not $full.StartsWith($root, [StringComparison]::OrdinalIgnoreCase)) { return $null }
    return $full
}

# Pulls every file from the folder the phone chose to send ("SEND TO PC" on the phone) into the PC folder.
# Files already here with the same size are skipped, so pressing RECEIVE again continues where it stopped.
function Start-Receive {
    $dest = $txtRecv.Text.Trim().TrimEnd("\")
    if (-not $dest) { $lblStatus.Text = "Pick a folder on this PC to save into."; return }
    try { [void][IO.Directory]::CreateDirectory($dest) } catch { $lblStatus.Text = "Cannot use that folder: " + $_.Exception.Message; return }
    $script:Receiving = $true; $script:RecvStop = $false; $script:Running = $true; Keep-Awake $true
    Set-Busy $true
    $bar.Value = 0; $lblFile.Text = ""
    try {
        $lblStatus.Text = "Connecting..."; [Windows.Forms.Application]::DoEvents()
        if (-not (Connect-Phone)) { $lblStatus.Text = "Not connected."; return }
        # Everything below reads straight from the encrypted stream (one line, or exact file bytes), never through the line reader.
        Send-Line "OUTBOX"
        $r = [NsCrypto]::ReadLine($script:Ns)
        if (-not $r) { throw "The phone did not answer." }
        if ($r.StartsWith("ERR unknown")) { throw "The phone app is too old. Install the newest NightSend.apk from Releases." }
        if (-not $r.StartsWith("OK|")) { throw ($r -replace "^ERR\s*", "") }
        Log ("The phone is sharing: " + $r.Substring(3))

        $lblStatus.Text = "Reading the list from the phone..."; [Windows.Forms.Application]::DoEvents()
        Send-Line "OTREE"
        $items = New-Object System.Collections.ArrayList
        while ($true) {
            $l = [NsCrypto]::ReadLine($script:Ns)
            if ($l -eq $null) { throw "The phone closed the connection." }
            if ($l -eq "END") { break }
            if ($l.StartsWith("ERR")) { throw ($l -replace "^ERR\s*", "") }
            $i = $l.IndexOf("|")
            if ($i -lt 1) { continue }
            [void]$items.Add(@{ Size = [int64]$l.Substring(0, $i); Rel = $l.Substring($i + 1) })
        }

        $todo = New-Object System.Collections.ArrayList
        $skipped = 0; $failed = 0
        foreach ($it in $items) {
            $full = Safe-RecvPath $dest $it.Rel
            if (-not $full) { Log ("Skipped (name not allowed): " + $it.Rel); $failed++; continue }
            if ((Test-Path -LiteralPath $full -PathType Leaf) -and ((Get-Item -LiteralPath $full -Force).Length -eq $it.Size)) { $skipped++; continue }
            [void]$todo.Add(@{ Rel = $it.Rel; Size = $it.Size; Full = $full })
        }
        $total = [int64]0
        foreach ($t in $todo) { $total += $t.Size }
        if ($todo.Count -eq 0) {
            $lblStatus.Text = "Nothing new. {0} file(s) already here." -f $skipped
            Log $lblStatus.Text
            return
        }
        $free = -1
        try { $free = (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($dest)))).AvailableFreeSpace } catch {}
        if ($free -ge 0 -and $free -lt $total) { throw ("Not enough space on this PC: need {0}, {1} free." -f (Fmt $total), (Fmt $free)) }
        Log ("Receiving {0} file(s), {1}." -f $todo.Count, (Fmt $total))

        $start = Get-Date; $lastUi = Get-Date
        $got = [int64]0; $done = 0; $idx = 0
        $buf = $script:Buf
        foreach ($t in $todo) {
            if ($script:RecvStop) { throw "Stopped by you." }
            $idx++
            $lblFile.Text = $t.Rel
            Send-Line ("GET " + $t.Rel)
            $h = [NsCrypto]::ReadLine($script:Ns)
            if ($h -eq $null) { throw "The phone closed the connection." }
            if (-not $h.StartsWith("OK|")) { Log ("The phone refused " + $t.Rel + ": " + $h); $failed++; continue }
            $size = [int64]$h.Substring(3)
            $part = $t.Full + ".nspart"
            [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($t.Full))
            $fs = $null; $ok = $false
            try {
                $fs = New-Object IO.FileStream($part, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None, 1048576)
                $left = $size
                while ($left -gt 0) {
                    $n = $script:Ns.Read($buf, 0, [int][Math]::Min($buf.Length, $left))
                    if ($n -le 0) { throw "The phone closed the connection." }
                    $fs.Write($buf, 0, $n); $left -= $n; $got += $n
                    if (((Get-Date) - $lastUi).TotalMilliseconds -gt 150) {
                        $lastUi = Get-Date
                        $sec = [Math]::Max(0.5, ((Get-Date) - $start).TotalSeconds)
                        $bar.Value = [int][Math]::Min(1000, 1000 * $got / [Math]::Max(1, $total))
                        $lblStatus.Text = "File {0} of {1}  -  {2} of {3}  -  {4}/s" -f $idx, $todo.Count, (Fmt $got), (Fmt $total), (Fmt ($got / $sec))
                        [Windows.Forms.Application]::DoEvents()
                        if ($script:RecvStop) { throw "Stopped by you." }
                    }
                }
                $ok = $true
            } finally {
                if ($fs) { $fs.Close() }
                if (-not $ok) { Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue }
            }
            if ((New-Object IO.FileInfo($part)).Length -ne $size) {
                Remove-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue
                Log ("Size check failed, not kept: " + $t.Rel); $failed++; continue
            }
            if (Test-Path -LiteralPath $t.Full) { Remove-Item -LiteralPath $t.Full -Force }
            [IO.File]::Move($part, $t.Full)
            $done++
        }
        $bar.Value = 1000; $lblFile.Text = ""
        $msg = "Done. {0} file(s) received ({1})." -f $done, (Fmt $got)
        if ($skipped) { $msg += " $skipped already here." }
        if ($failed) { $msg += " $failed failed - press RECEIVE again to retry." }
        $lblStatus.Text = $msg
        Log $msg
    } catch {
        $lblStatus.Text = "Stopped: " + $_.Exception.Message
        Log ("Receive stopped: " + $_.Exception.Message + "  Press RECEIVE to continue.")
    } finally {
        Close-Conn
        $script:Receiving = $false; $script:Running = $false; Keep-Awake $false
        Set-Busy $false
        Tray-Note "NightSend" $lblStatus.Text
    }
}

# ---------- UI ----------
$BuildStamp = "build dev"   # the build replaces this line with the real build number and commit
$form = New-Object Windows.Forms.Form
$form.Text = "NightSend"
$form.ClientSize = New-Object Drawing.Size(720, 764)
$form.BackColor = $cBg; $form.ForeColor = $cText; $form.Font = $fUi
$form.FormBorderStyle = "FixedSingle"; $form.MaximizeBox = $false
$form.StartPosition = "CenterScreen"

function L($text, $x, $y, $w, $h, $font, $color) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.Location = New-Object Drawing.Point($x, $y); $l.Size = New-Object Drawing.Size($w, $h)
    if ($font) { $l.Font = $font }; if ($color) { $l.ForeColor = $color }
    $form.Controls.Add($l); $l
}
function B($text, $x, $y, $w) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object Drawing.Point($x, $y); $b.Size = New-Object Drawing.Size($w, 32)
    $b.FlatStyle = "Flat"; $b.BackColor = $cPanel; $b.ForeColor = $cText
    $b.FlatAppearance.BorderColor = $cAccent
    $form.Controls.Add($b); $b
}
function T($text, $x, $y, $w) {
    $t = New-Object Windows.Forms.TextBox
    $t.Text = $text; $t.Location = New-Object Drawing.Point($x, $y); $t.Size = New-Object Drawing.Size($w, 28)
    $t.BackColor = $cPanel; $t.ForeColor = $cText; $t.BorderStyle = "FixedSingle"
    $form.Controls.Add($t); $t
}

[void](L "NIGHTSEND" 20 14 400 44 (New-Object Drawing.Font("Segoe UI Black", 24)) $cText)
[void](L "Pair once with a QR code  -  no cloud, no internet" 22 58 660 22 $null $cDim)
$line = New-Object Windows.Forms.Panel; $line.BackColor = $cAccent
$line.Location = New-Object Drawing.Point(20, 86); $line.Size = New-Object Drawing.Size(680, 2); $form.Controls.Add($line)

[void](L "1  PHONE" 20 102 200 22 $fBold $cDim)
$btnFind = B "Find phone" 20 126 150
[void](L "Address (auto):" 182 132 64 22 $null $cDim)
$txtIp = T "" 248 129 150
$btnPair = B "Pair with QR" 410 126 150
[void](L "(once per phone)" 568 132 130 22 $null $cDim)
$lblPhone = L "Not connected." 20 164 380 40 $null $cDim
$chkStrict = New-Object Windows.Forms.CheckBox
$chkStrict.Text = "Strict: new QR for every session"; $chkStrict.Checked = $script:Strict
$chkStrict.Location = New-Object Drawing.Point(410, 166); $chkStrict.Size = New-Object Drawing.Size(290, 26); $chkStrict.ForeColor = $cText
$form.Controls.Add($chkStrict)
$chkStrict.Add_CheckedChanged({
    $script:Strict = $chkStrict.Checked
    try {
        if ($script:Strict) { [IO.File]::WriteAllText($StrictFile, "1"); Forget-PairKey }
        else { Remove-Item -LiteralPath $StrictFile -Force -ErrorAction SilentlyContinue }
    } catch {}
})

[void](L "2  SEND FROM (this PC)" 20 210 300 22 $fBold $cDim)
$txtSrc = T "D:\BnM\TV & Movie\TV" 20 234 560
$btnBrowse = B "Browse" 590 231 110
[void](L "Put it in (phone):" 20 268 126 22 $null $cDim)
$txtDest = T "(the phone's save folder)" 148 264 426
$txtDest.ReadOnly = $true
$btnPick = B "Pick on phone" 584 261 116
$chkRoot = New-Object Windows.Forms.CheckBox
$chkRoot.Text = "Make a folder with its name"; $chkRoot.Checked = $true
$chkRoot.Location = New-Object Drawing.Point(20, 298); $chkRoot.Size = New-Object Drawing.Size(240, 26); $chkRoot.ForeColor = $cText
$form.Controls.Add($chkRoot)
$chkSort = New-Object Windows.Forms.CheckBox
$chkSort.Text = "Auto-sort loose files by name (Show / Season)"; $chkSort.Checked = $true
$chkSort.Location = New-Object Drawing.Point(270, 298); $chkSort.Size = New-Object Drawing.Size(430, 26); $chkSort.ForeColor = $cText
$form.Controls.Add($chkSort)

$chkArchive = New-Object Windows.Forms.CheckBox
$chkArchive.Text = "After a clean send, archive the folder to:"; $chkArchive.Checked = $false
$chkArchive.Location = New-Object Drawing.Point(20, 332); $chkArchive.Size = New-Object Drawing.Size(290, 26); $chkArchive.ForeColor = $cText
$form.Controls.Add($chkArchive)
$txtArchive = T "D:\BnM\Sent to phone" 312 330 268
$btnArchiveBrowse = B "Browse" 590 327 110

$btnSend = B "SEND" 20 368 150
$btnSend.BackColor = $cAccent; $btnSend.Font = $fBold
$btnStop = B "Stop" 180 368 110; $btnStop.Enabled = $false

[void](L "3  RECEIVE FROM PHONE (the folder the phone chose to send)" 20 410 600 22 $fBold $cDim)
[void](L "Save on this PC:" 20 442 126 22 $null $cDim)
$txtRecv = T (Join-Path ([Environment]::GetFolderPath("UserProfile")) "Downloads\From phone") 148 438 426
$btnRecvBrowse = B "Browse" 584 435 116
$btnRecv = B "RECEIVE" 20 474 150
$btnRecv.BackColor = $cAccent; $btnRecv.Font = $fBold

$bar = New-Object Windows.Forms.ProgressBar
$bar.Location = New-Object Drawing.Point(20, 522); $bar.Size = New-Object Drawing.Size(680, 18); $bar.Maximum = 1000
$form.Controls.Add($bar)
$lblStatus = L "Ready." 20 546 680 22 $null $cText
$lblFile = L "" 20 568 680 22 $null $cDim

$txtLog = New-Object Windows.Forms.TextBox
$txtLog.Multiline = $true; $txtLog.ScrollBars = "Vertical"; $txtLog.ReadOnly = $true
$txtLog.Location = New-Object Drawing.Point(20, 598); $txtLog.Size = New-Object Drawing.Size(680, 128)
$txtLog.BackColor = $cPanel; $txtLog.ForeColor = $cDim; $txtLog.BorderStyle = "FixedSingle"
$txtLog.Font = New-Object Drawing.Font("Consolas", 9)
$form.Controls.Add($txtLog)
$lblBuild = L ("NightSend " + $BuildStamp) 20 734 680 18 $null $cDim

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 20
$timer.Add_Tick({ On-Tick })

$btnFind.Add_Click({ Set-Busy $true; $btnStop.Enabled = $false; [void](Connect-Phone); Close-Conn; Set-Busy $false })
$btnPair.Add_Click({ Show-PairQr })
$btnArchiveBrowse.Add_Click({
    $d = New-Object Windows.Forms.FolderBrowserDialog
    $d.SelectedPath = $txtArchive.Text
    if ($d.ShowDialog() -eq "OK") { $txtArchive.Text = $d.SelectedPath }
})
$btnSend.Add_Click({ Start-Send })
$btnPick.Add_Click({ Pick-PhoneFolder })
$btnStop.Add_Click({ if ($script:Receiving) { $script:RecvStop = $true; $btnStop.Enabled = $false } else { Abort-Send "Stopped by you." } })
$btnRecv.Add_Click({ Start-Receive })
$btnRecvBrowse.Add_Click({
    $d = New-Object Windows.Forms.FolderBrowserDialog
    $d.SelectedPath = $txtRecv.Text
    if ($d.ShowDialog() -eq "OK") { $txtRecv.Text = $d.SelectedPath }
})
$btnBrowse.Add_Click({
    $d = New-Object Windows.Forms.FolderBrowserDialog
    $d.SelectedPath = $txtSrc.Text
    if ($d.ShowDialog() -eq "OK") { $txtSrc.Text = $d.SelectedPath }
})
# ---------- background (system tray) ----------
$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = [Drawing.SystemIcons]::Application
$tray.Text = "NightSend"
$tray.Visible = $true
$menu = New-Object Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add("Open NightSend", $null, { Show-Window })
[void]$menu.Items.Add("Exit", $null, { $script:Quit = $true; if ($script:Running) { Show-Window }; $form.Close() })
$tray.ContextMenuStrip = $menu

function Show-Window { $form.Show(); $form.WindowState = "Normal"; [void]$form.Activate() }
function Hide-Window {
    $form.Hide()
    if ($script:Running) { $tray.BalloonTipTitle = "NightSend"; $tray.BalloonTipText = "Still sending in the background. Click the tray icon to open."; $tray.ShowBalloonTip(3000) }
}
function Tray-Note([string]$title, [string]$msg) {
    if (-not $form.Visible) { $tray.BalloonTipTitle = $title; $tray.BalloonTipText = $msg; $tray.ShowBalloonTip(5000) }
}
$tray.Add_DoubleClick({ Show-Window })
$tray.Add_MouseClick({ if ($_.Button -eq "Left") { Show-Window } })
# Minimizing sends it to the tray, and keeps any transfer running.
$form.Add_Resize({ if ($form.WindowState -eq "Minimized") { Hide-Window } })
$form.Add_FormClosing({
    if ($script:Running -and -not $script:Quit) {
        # X while sending: keep sending in the background instead of stopping.
        $_.Cancel = $true; Hide-Window; return
    }
    if ($script:Running) {
        $a = [Windows.Forms.MessageBox]::Show("A transfer is running. Stop it and exit?", "NightSend", "YesNo", "Warning")
        if ($a -ne "Yes") { $script:Quit = $false; $_.Cancel = $true; return }
        Abort-Send "Closed."
    }
    $tray.Visible = $false; $tray.Dispose()
})
$form.Add_Shown({ Log "NightSend ready. First time: press Pair with QR, scan the picture with the NightSend phone app, then press Find phone."
    if ($script:PairKey) { Set-Busy $true; $btnStop.Enabled = $false; [void](Connect-Phone); Close-Conn; Set-Busy $false }
})

# Application.Run (not ShowDialog): hiding the window to the tray must never end the program.
try { [System.Windows.Forms.Application]::Run($form) } catch { Write-Crash ("Fatal: " + $_.Exception.ToString()) }
try { $tray.Visible = $false; $tray.Dispose() } catch {}
