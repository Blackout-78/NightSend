package com.blackout.nightsend;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * NightSend protocol v2: key exchange and encrypted frames. Nothing here touches the internet.
 *
 * Handshake (lines, hex, UTF-8):
 *   PC    -> NS2 pcPub                 pcPub = 64 raw bytes (P-256 X||Y), fresh for every connection
 *   phone -> phonePub                  fresh for every connection
 *   PC    -> AUTH keyId proof          paired before: proof = HMAC(pairKey, "NS2-C" || T)
 *         or PAIR proof                first time:    proof = HMAC(code,    "NS2-C" || T)
 *   phone -> OK proof | ERR ...        phone proves it knows the same key: HMAC(K, "NS2-S" || T)
 *   T = pcPub || phonePub
 *   zh = SHA-256(ECDH shared X)
 *   master = HMAC(K, "NS2-MASTER" || zh || T)
 *   per direction: enc = HMAC(master, "c2s-enc"|"s2c-enc"), mac = HMAC(master, "c2s-mac"|"s2c-mac")
 *   pairKey (made on PAIR, kept by both) = HMAC(zh, "NS2-PAIRKEY" || T)
 *
 * Frame: len(4, big endian) | iv(16) | AES-256-CBC ciphertext | mac(32)
 *   len = 16 + ciphertext + 32; mac = HMAC(macKey, seq(8, big endian) || iv || ciphertext)
 */
final class Secure {
    private Secure() { }

    static final int MAX_PLAIN = 262144;
    static final int MAX_FRAME = 16 + MAX_PLAIN + 16 + 32;
    static final SecureRandom RNG = new SecureRandom();

    // ---------------------------------------------------------------- small helpers

    static byte[] cat(byte[]... parts) {
        int n = 0;
        for (byte[] p : parts) n += p.length;
        byte[] r = new byte[n];
        int o = 0;
        for (byte[] p : parts) { System.arraycopy(p, 0, r, o, p.length); o += p.length; }
        return r;
    }

    static byte[] utf8(String s) {
        return s.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    }

    static byte[] hmac(byte[] key, byte[]... parts) {
        try {
            Mac m = Mac.getInstance("HmacSHA256");
            m.init(new SecretKeySpec(key, "HmacSHA256"));
            for (byte[] p : parts) m.update(p);
            return m.doFinal();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] b) {
        char[] d = "0123456789abcdef".toCharArray();
        char[] c = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) { c[i * 2] = d[(b[i] >> 4) & 15]; c[i * 2 + 1] = d[b[i] & 15]; }
        return new String(c);
    }

    static boolean isHex(String s, int len) {
        if (s == null || s.length() != len) return false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
        }
        return true;
    }

    static byte[] unhex(String s) {
        byte[] r = new byte[s.length() / 2];
        for (int i = 0; i < r.length; i++) r[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        return r;
    }

    // ---------------------------------------------------------------- key exchange

    static KeyPair newKeyPair() throws GeneralSecurityException {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec("secp256r1"));
        return g.generateKeyPair();
    }

    static byte[] fixed32(BigInteger v) {
        byte[] b = v.toByteArray();
        byte[] r = new byte[32];
        if (b.length >= 32) System.arraycopy(b, b.length - 32, r, 0, 32);
        else System.arraycopy(b, 0, r, 32 - b.length, b.length);
        return r;
    }

    static byte[] pubRaw(KeyPair kp) {
        ECPoint w = ((ECPublicKey) kp.getPublic()).getW();
        return cat(fixed32(w.getAffineX()), fixed32(w.getAffineY()));
    }

    static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);

    /** True when the point is really on the P-256 curve (blocks invalid-point tricks). */
    static boolean onCurve(BigInteger x, BigInteger y) {
        if (x.signum() < 0 || y.signum() < 0 || x.compareTo(P) >= 0 || y.compareTo(P) >= 0) return false;
        BigInteger left = y.multiply(y).mod(P);
        BigInteger right = x.multiply(x).mod(P).multiply(x).subtract(x.multiply(BigInteger.valueOf(3))).add(B).mod(P);
        return left.equals(right);
    }

    /** SHA-256 of the ECDH shared secret, the same value the PC derives. */
    static byte[] sharedHash(KeyPair mine, byte[] peerRaw) throws GeneralSecurityException {
        if (peerRaw.length != 64) throw new GeneralSecurityException("bad public key");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(peerRaw, 0, 32));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(peerRaw, 32, 64));
        if (!onCurve(x, y)) throw new GeneralSecurityException("point not on curve");
        ECParameterSpec params = ((ECPublicKey) mine.getPublic()).getParams();
        PublicKey pk = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(new ECPoint(x, y), params));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(mine.getPrivate());
        ka.doPhase(pk, true);
        return sha256(ka.generateSecret());
    }

    /** The four keys of one session, from the master secret. */
    static final class Keys {
        final byte[] c2sEnc, c2sMac, s2cEnc, s2cMac;
        Keys(byte[] master) {
            c2sEnc = hmac(master, utf8("c2s-enc"));
            c2sMac = hmac(master, utf8("c2s-mac"));
            s2cEnc = hmac(master, utf8("s2c-enc"));
            s2cMac = hmac(master, utf8("s2c-mac"));
        }
    }

    static String keyId(byte[] pairKey) {
        return hex(Arrays.copyOf(sha256(pairKey), 8));
    }

    // ---------------------------------------------------------------- frames

    static byte[] seqBytes(long seq) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) { b[i] = (byte) seq; seq >>>= 8; }
        return b;
    }

    /** Reads decrypted bytes from the other side. */
    static final class In extends InputStream {
        private final InputStream in;
        private final SecretKeySpec enc;
        private final byte[] macKey;
        private long seq = 0;
        private byte[] buf = new byte[0];
        private int pos = 0;

        In(InputStream in, byte[] encKey, byte[] macKey) {
            this.in = in;
            this.enc = new SecretKeySpec(encKey, "AES");
            this.macKey = macKey;
        }

        @Override public int read() throws IOException {
            byte[] one = new byte[1];
            int n = read(one, 0, 1);
            return n < 0 ? -1 : (one[0] & 255);
        }

        @Override public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (pos >= buf.length && !nextFrame()) return -1;
            int n = Math.min(len, buf.length - pos);
            System.arraycopy(buf, pos, b, off, n);
            pos += n;
            return n;
        }

        @Override public int available() { return buf.length - pos; }

        private boolean nextFrame() throws IOException {
            int b0 = in.read();
            if (b0 < 0) return false;
            int len = (b0 << 24) | (readByte() << 16) | (readByte() << 8) | readByte();
            if (len < 16 + 16 + 32 || len > MAX_FRAME) throw new IOException("bad frame size");
            byte[] f = new byte[len];
            int got = 0;
            while (got < len) {
                int n = in.read(f, got, len - got);
                if (n < 0) throw new IOException("connection closed");
                got += n;
            }
            byte[] iv = Arrays.copyOfRange(f, 0, 16);
            byte[] ct = Arrays.copyOfRange(f, 16, len - 32);
            byte[] mac = Arrays.copyOfRange(f, len - 32, len);
            byte[] want = hmac(macKey, seqBytes(seq), iv, ct);
            if (!MessageDigest.isEqual(mac, want)) throw new IOException("bad frame signature");
            try {
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.DECRYPT_MODE, enc, new IvParameterSpec(iv));
                buf = c.doFinal(ct);
            } catch (GeneralSecurityException e) {
                throw new IOException("bad frame");
            }
            pos = 0;
            seq++;
            return true;
        }

        private int readByte() throws IOException {
            int c = in.read();
            if (c < 0) throw new IOException("connection closed");
            return c;
        }
    }

    /** Writes encrypted frames. Whatever was written goes out on flush(). */
    static final class Out extends OutputStream {
        private final OutputStream out;
        private final SecretKeySpec enc;
        private final byte[] macKey;
        private long seq = 0;
        private final ByteArrayOutputStream pend = new ByteArrayOutputStream();

        Out(OutputStream out, byte[] encKey, byte[] macKey) {
            this.out = out;
            this.enc = new SecretKeySpec(encKey, "AES");
            this.macKey = macKey;
        }

        @Override public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override public void write(byte[] b, int off, int len) throws IOException {
            while (len > 0) {
                int n = Math.min(len, MAX_PLAIN - pend.size());
                pend.write(b, off, n);
                off += n; len -= n;
                if (pend.size() >= MAX_PLAIN) frame();
            }
        }

        @Override public void flush() throws IOException {
            if (pend.size() > 0) frame();
            out.flush();
        }

        private void frame() throws IOException {
            byte[] plain = pend.toByteArray();
            pend.reset();
            byte[] iv = new byte[16];
            RNG.nextBytes(iv);
            byte[] ct;
            try {
                Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
                c.init(Cipher.ENCRYPT_MODE, enc, new IvParameterSpec(iv));
                ct = c.doFinal(plain);
            } catch (GeneralSecurityException e) {
                throw new IOException("encrypt failed");
            }
            byte[] mac = hmac(macKey, seqBytes(seq), iv, ct);
            seq++;
            int len = 16 + ct.length + 32;
            byte[] head = { (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len };
            out.write(cat(head, iv, ct, mac));
        }
    }
}
