package com.blackout.nightsend;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.MessageDigest;

/**
 * Test only (never shipped). Plays the phone with the REAL Secure.java from the app, so the Linux app is tested against
 * the same crypto code the phone runs. Prints its port, then serves 3 rounds on loopback:
 *   1: wrong pairing code is refused   2: pair with the code, echo SHA-256 of 1 MB   3: come back with the saved key only
 */
public final class InteropServer {
    static final String CODE = "0123456789abcdef0123456789abcdef";

    static String readLine(InputStream in) throws IOException {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int c = in.read();
            if (c < 0) { if (sb.length() == 0) return null; break; }
            if (c == '\n') break;
            if (c != '\r') sb.append((char) c);
            if (sb.length() > 4096) throw new IOException("line too long");
        }
        return sb.toString();
    }

    static void writeLine(OutputStream out, String s) throws IOException {
        out.write(Secure.utf8(s + "\n"));
        out.flush();
    }

    static void round(Socket s, byte[][] stored) throws Exception {
        InputStream in = s.getInputStream();
        OutputStream out = s.getOutputStream();
        String first = readLine(in);
        byte[] pc = Secure.unhex(first.substring(4));
        KeyPair kp = Secure.newKeyPair();
        byte[] ph = Secure.pubRaw(kp);
        byte[] zh = Secure.sharedHash(kp, pc);
        writeLine(out, Secure.hex(ph));
        String[] w = readLine(in).split(" ");
        byte[] t = Secure.cat(pc, ph);
        boolean pairing = w[0].equals("PAIR");
        byte[] key = pairing ? Secure.utf8(CODE) : stored[0];
        String proof = pairing ? w[1] : w[2];
        if (!pairing && (key == null || !w[1].equals(Secure.keyId(key)))) { writeLine(out, "ERR auth"); return; }
        if (key == null || !MessageDigest.isEqual(Secure.unhex(proof), Secure.hmac(key, Secure.utf8("NS2-C"), t))) {
            writeLine(out, pairing ? "ERR code" : "ERR auth");
            return;
        }
        writeLine(out, "OK " + Secure.hex(Secure.hmac(key, Secure.utf8("NS2-S"), t)));
        if (pairing) stored[0] = Secure.hmac(zh, Secure.utf8("NS2-PAIRKEY"), t);
        Secure.Keys k = new Secure.Keys(Secure.hmac(key, Secure.utf8("NS2-MASTER"), zh, t));
        Secure.In sin = new Secure.In(in, k.c2sEnc, k.c2sMac);
        Secure.Out sout = new Secure.Out(out, k.s2cEnc, k.s2cMac);
        String cmd = readLine(sin);
        byte[] buf = new byte[1000000];
        int got = 0;
        while (got < buf.length) {
            int n = sin.read(buf, got, buf.length - got);
            if (n <= 0) throw new IOException("eof");
            got += n;
        }
        writeLine(sout, "ECHO " + cmd + " " + Secure.hex(Secure.sha256(buf)));
    }

    public static void main(String[] args) throws Exception {
        try (ServerSocket ss = new ServerSocket(0, 5, InetAddress.getLoopbackAddress())) {
            System.out.println(ss.getLocalPort());
            System.out.flush();
            byte[][] stored = new byte[1][];
            for (int i = 0; i < 3; i++) {
                try (Socket s = ss.accept()) { round(s, stored); }
            }
        }
    }
}
