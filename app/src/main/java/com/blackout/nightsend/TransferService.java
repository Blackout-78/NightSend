package com.blackout.nightsend;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.os.PowerManager;
import android.os.StatFs;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * NightSend receiver service. Runs in the foreground so it keeps receiving with the
 * screen off and the app closed. Listens on port 47800 for the NightSend PC app on the
 * same Wi-Fi. No internet, no cloud.
 *
 * Protocol v2: a key exchange (see Secure.java) first, then everything is encrypted. After it,
 * one line commands, UTF-8, ending in \n:
 *   HELLO            -> NIGHTSEND|model|freeBytes|destPath|storageOk(1/0)
 *   DIRS [path]      -> folder names inside path (default: save folder), then END
 *   DEST path        -> OK|freeBytes: this session saves into path instead of the save folder
 *   MKDIR path       -> OK or ERR reason
 *   LIST             -> size|relativePath lines, then END
 *   PUT size relPath -> (then exactly size bytes) -> OK or ERR reason
 *   BYE
 */
public class TransferService extends Service {

    static final int PORT = 47800;
    static final int MAX_WRONG = 5;        // wrong codes in a row before a new code is made
    static final int MAX_LINE = 8192;      // longest command line accepted
    static final String CHANNEL = "nightsend";
    static final int NOTE_ID = 47800;

    // State shared with the screen (MainActivity only reads it).
    static volatile String pairCode;
    static volatile int wrongTries = 0;
    static volatile String status = "Starting...";
    static volatile String currentFile = "";
    static volatile long curDone = 0, curSize = 0, sessionBytes = 0, sessionFiles = 0;
    static volatile boolean connected = false;
    static volatile boolean running = false;

    static final SecureRandom RNG = new SecureRandom();

    // Connection limits: a stranger on the network must not be able to lock the real PC out.
    static final int MAX_CONNECTIONS = 4;               // at most this many sockets open at once
    static final long HANDSHAKE_MS = 8000;               // the whole login must finish within this time
    static final Semaphore SLOTS = new Semaphore(MAX_CONNECTIONS);
    static final ReentrantLock SESSION = new ReentrantLock();   // only one logged-in PC at a time
    static final ScheduledExecutorService WATCH = Executors.newSingleThreadScheduledExecutor();

    SharedPreferences prefs;
    ServerSocket server;
    Thread thread;
    PowerManager.WakeLock wakeLock;
    WifiManager.WifiLock wifiLock;
    final Handler ui = new Handler(Looper.getMainLooper());
    String lastNote = "";

    // ---------------------------------------------------------------- shared helpers

    static SharedPreferences prefs(Context c) {
        return c.getSharedPreferences("nightsend", Context.MODE_PRIVATE);
    }

    /** Loads the saved pairing code, making one the first time. */
    static void ensureCode(Context c) {
        if (pairCode != null) return;
        String saved = prefs(c).getString("code", null);
        if (saved == null) newCode(c); else pairCode = saved;
    }

    static void newCode(Context c) {
        pairCode = String.format(Locale.US, "%06d", RNG.nextInt(1000000));
        wrongTries = 0;
        prefs(c).edit().putString("code", pairCode).apply();
    }

    static final int MAX_PCS = 8;

    /** Paired PCs are kept as "keyId:keyHex;..." in the app's private storage. */
    static synchronized byte[] findKey(Context c, String id) {
        String all = prefs(c).getString("keys", "");
        for (String e : all.split(";")) {
            String[] p = e.split(":");
            if (p.length == 2 && p[0].equals(id) && Secure.isHex(p[1], 64)) return Secure.unhex(p[1]);
        }
        return null;
    }

    static synchronized void addKey(Context c, byte[] key) {
        String id = Secure.keyId(key);
        StringBuilder sb = new StringBuilder();
        int n = 0;
        for (String e : prefs(c).getString("keys", "").split(";")) {
            if (e.isEmpty() || e.startsWith(id + ":")) continue;
            if (++n >= MAX_PCS) break;    // oldest ones fall off
            sb.append(e).append(';');
        }
        sb.append(id).append(':').append(Secure.hex(key));
        prefs(c).edit().putString("keys", sb.toString()).apply();
    }

    /** Locks out every PC: forgets all pairings and makes a new code. */
    static synchronized void forgetAll(Context c) {
        prefs(c).edit().remove("keys").apply();
        newCode(c);
    }

    /** The folder on the phone where received files go. */
    static File destFolder(Context c) {
        String p = prefs(c).getString("dest", null);
        if (p != null && !p.isEmpty()) return new File(p);
        return new File(Environment.getExternalStorageDirectory(), "Movies/TV");
    }

    static long freeBytes(File f) {
        try {
            File p = f;
            while (p != null && !p.exists()) p = p.getParentFile();
            if (p == null) return -1;
            return new StatFs(p.getPath()).getAvailableBytes();
        } catch (Exception e) { return -1; }
    }

    static String fmt(long b) {
        String[] u = {"B", "KB", "MB", "GB", "TB"};
        double d = b; int i = 0;
        while (d >= 1024 && i < 4) { d /= 1024; i++; }
        return String.format(Locale.US, "%.1f %s", d, u[i]);
    }

    /** Only folders on the phone's own storage may be browsed or written to, never "..". */
    static boolean allowed(String p) {
        if (p.isEmpty() || !p.startsWith("/")) return false;
        for (String part : p.split("/")) if (part.equals("..")) return false;
        if (p.indexOf('\0') >= 0) return false;
        String ext = Environment.getExternalStorageDirectory().getPath();
        return p.startsWith("/storage/") || p.equals(ext) || p.startsWith(ext + "/");
    }

    /** Only phone-network addresses (home Wi-Fi, hotspot, USB tether, Wi-Fi Direct) may connect, never the internet. */
    static boolean localPeer(InetAddress a) {
        if (a == null) return false;
        if (a.isLoopbackAddress() || a.isSiteLocalAddress() || a.isLinkLocalAddress()) return true;
        if (a instanceof Inet6Address) return (a.getAddress()[0] & 0xFE) == 0xFC;   // fc00::/7 private range
        return false;
    }

    /** Top of the storage volume a folder is on (phone storage or an SD card). */
    static String rootOf(File dest) {
        String ext = Environment.getExternalStorageDirectory().getPath();
        String p = dest.getPath();
        if (p.startsWith(ext)) return ext;
        if (p.startsWith("/storage/")) { int i = p.indexOf('/', 9); return i < 0 ? p : p.substring(0, i); }
        return ext;
    }

    static boolean hasStorage(Context c) {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return c.checkSelfPermission(android.Manifest.permission.WRITE_EXTERNAL_STORAGE)
                == android.content.pm.PackageManager.PERMISSION_GRANTED;
    }

    // ---------------------------------------------------------------- service

    @Override
    public void onCreate() {
        super.onCreate();
        prefs = prefs(this);
        ensureCode(this);

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "nightsend:transfer");
        wakeLock.setReferenceCounted(false);
        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "nightsend:wifi");
            wifiLock.setReferenceCounted(false);
        }

        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        NotificationChannel ch = new NotificationChannel(CHANNEL, "NightSend", NotificationManager.IMPORTANCE_LOW);
        ch.setShowBadge(false);
        nm.createNotificationChannel(ch);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification n = buildNote("Waiting for PC...");
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTE_ID, n);
            }
        } catch (Exception e) {
            // Android refused to run it in the background; the app screen will start it again.
            status = "Could not start in background: " + e.getMessage();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (thread == null) {
            running = true;
            thread = new Thread(this::serverLoop, "nightsend-server");
            thread.start();
            ui.post(noteUpdater);
        }
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        running = false;
        ui.removeCallbacks(noteUpdater);
        try { if (server != null) server.close(); } catch (IOException ignored) { }
        releaseLocks();
        thread = null;
        super.onDestroy();
    }

    Notification buildNote(String text) {
        Intent open = new Intent(this, MainActivity.class);
        open.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("NightSend")
                .setContentText(text)
                .setContentIntent(pi)
                .setOnlyAlertOnce(true)
                .setOngoing(true)
                .build();
    }

    /** Keeps the notification text in step with what the transfer is doing. */
    final Runnable noteUpdater = new Runnable() {
        @Override public void run() {
            String t;
            if (connected && curSize > 0) {
                t = currentFile + "  " + fmt(curDone) + " of " + fmt(curSize);
            } else if (connected) {
                t = "PC connected  -  " + sessionFiles + " files received";
            } else if (sessionFiles > 0) {
                t = "Waiting for PC  -  " + sessionFiles + " files received (" + fmt(sessionBytes) + ")";
            } else {
                t = "Waiting for PC...";
            }
            if (!t.equals(lastNote)) {
                lastNote = t;
                try {
                    ((NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE)).notify(NOTE_ID, buildNote(t));
                } catch (Exception ignored) { }
            }
            if (running) ui.postDelayed(this, 1500);
        }
    };

    // ---------------------------------------------------------------- network

    void serverLoop() {
        while (running) {
            // (Re)open the listening port. If it is busy, keep trying instead of giving up.
            try {
                server = new ServerSocket();
                server.setReuseAddress(true);
                server.bind(new InetSocketAddress(PORT));
            } catch (IOException e) {
                status = "Could not listen on port " + PORT + ": " + e.getMessage() + " (retrying)";
                try { if (server != null) server.close(); } catch (IOException ignored) { }
                pause(2000);
                continue;
            }
            status = "Waiting for PC...";
            while (running) {
                Socket s;
                try {
                    s = server.accept();
                } catch (IOException e) {
                    if (!running) return;
                    break; // listening socket broke: open a fresh one
                }
                if (!localPeer(s.getInetAddress()) || !SLOTS.tryAcquire()) {
                    try { s.close(); } catch (IOException ignored) { }
                    continue;
                }
                final Socket sock = s;
                new Thread(() -> {
                    try {
                        handle(sock);
                    } catch (Throwable t) {
                        // never let one bad connection kill the receiver
                        status = "Connection error: " + t;
                        try { sock.close(); } catch (IOException ignored) { }
                    } finally {
                        SLOTS.release();
                    }
                }, "nightsend-conn").start();
            }
            try { server.close(); } catch (IOException ignored) { }
            pause(500);
        }
    }

    static void pause(long ms) {
        try { Thread.sleep(ms); } catch (InterruptedException ignored) { }
    }

    void handle(Socket s) {
        // The whole login has a hard time limit, so a slow trickle of bytes cannot hold a slot.
        ScheduledFuture<?> watchdog = WATCH.schedule(() -> {
            try { s.close(); } catch (IOException ignored) { }
        }, HANDSHAKE_MS, TimeUnit.MILLISECONDS);
        try {
            // Nothing is answered or shown until the PC proves it knows the code or a saved key.
            s.setSoTimeout(10000);
            InputStream raw = new BufferedInputStream(s.getInputStream(), 1 << 20);
            OutputStream rawOut = s.getOutputStream();
            String first = readLine(raw);
            if (first == null) return; // a plain "is anyone there?" knock from Find phone
            if (!first.startsWith("NS2 ") || !Secure.isHex(first.substring(4), 128)) {
                send(rawOut, "ERR version"); // an older PC app: it needs the newest NightSend.exe
                return;
            }
            byte[] pc = Secure.unhex(first.substring(4));
            KeyPair kp = Secure.newKeyPair();
            byte[] ph = Secure.pubRaw(kp);
            byte[] zh = Secure.sharedHash(kp, pc);
            send(rawOut, Secure.hex(ph));

            String second = readLine(raw);
            if (second == null) return;
            byte[] t = Secure.cat(pc, ph);
            byte[] k = null;
            byte[] proof = null;
            boolean pairing = false;
            String[] w = second.split(" ");
            if (w.length == 3 && w[0].equals("AUTH") && Secure.isHex(w[1], 16) && Secure.isHex(w[2], 64)) {
                k = findKey(this, w[1]);
                proof = Secure.unhex(w[2]);
            } else if (w.length == 2 && w[0].equals("PAIR") && Secure.isHex(w[1], 64)) {
                pairing = true;
                k = Secure.utf8(pairCode);
                proof = Secure.unhex(w[1]);
            }
            boolean good = k != null && proof != null
                    && MessageDigest.isEqual(proof, Secure.hmac(k, Secure.utf8("NS2-C"), t));
            if (!good) {
                if (pairing) {
                    wrongTries++;
                    if (wrongTries >= MAX_WRONG) {
                        newCode(this);
                        status = "Wrong code tried " + MAX_WRONG + " times. A new code was made.";
                    } else {
                        status = "Wrong pairing code from " + s.getInetAddress().getHostAddress() + ". Blocked.";
                    }
                } else {
                    status = "Unknown or forgotten PC from " + s.getInetAddress().getHostAddress() + ". Blocked.";
                }
                Thread.sleep(1000); // slows down guessing
                send(rawOut, pairing ? "ERR code" : "ERR auth");
                return;
            }
            send(rawOut, "OK " + Secure.hex(Secure.hmac(k, Secure.utf8("NS2-S"), t)));
            if (pairing) {
                addKey(this, Secure.hmac(zh, Secure.utf8("NS2-PAIRKEY"), t));
                newCode(this);   // the code was used up: the next PC needs a fresh one
                status = "PC paired. A new code was made for the next PC.";
            }
            wrongTries = 0;
            Secure.Keys keys = new Secure.Keys(Secure.hmac(k, Secure.utf8("NS2-MASTER"), zh, t));
            InputStream in = new Secure.In(raw, keys.c2sEnc, keys.c2sMac);
            OutputStream out = new Secure.Out(rawOut, keys.s2cEnc, keys.s2cMac);
            watchdog.cancel(false);
            if (!SESSION.tryLock()) { send(out, "ERR busy"); return; }   // another PC is already connected
            try {
                session(s, in, out);
            } finally {
                SESSION.unlock();
            }
        } catch (Exception e) {
            // ignore: a bad or dropped connection before pairing
        } finally {
            watchdog.cancel(false);
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    void session(Socket s, InputStream in, OutputStream out) {
        connected = true;
        status = "PC connected";
        acquireLocks();
        try {
            s.setSoTimeout(15 * 60 * 1000);   // PC may sit in the folder picker for a while; a dead PC frees the phone after 15 min
            s.setKeepAlive(true);
            byte[] buf = new byte[1 << 20];
            File sessionDest = null;   // set by DEST; lasts for this connection only
            String line;
            while ((line = readLine(in)) != null) {
                File dest = sessionDest != null ? sessionDest : destFolder(this);
                if (line.equals("HELLO")) {
                    dest.mkdirs();
                    send(out, "NIGHTSEND|" + Build.MANUFACTURER + " " + Build.MODEL + "|" + freeBytes(dest) + "|" +
                            dest.getPath() + "|" + (hasStorage(this) ? 1 : 0) + "|" + rootOf(dest));
                } else if (line.equals("DIRS") || line.startsWith("DIRS ")) {
                    String p = line.length() > 5 ? line.substring(5).trim() : "";
                    if (!p.isEmpty() && !allowed(p)) { send(out, "ERR not allowed"); continue; }
                    File[] kids = (p.isEmpty() ? dest : new File(p)).listFiles(f -> f.isDirectory() && !f.getName().startsWith("."));
                    StringBuilder sb = new StringBuilder();
                    if (kids != null) {
                        java.util.Arrays.sort(kids, (x, y) -> x.getName().compareToIgnoreCase(y.getName()));
                        for (File k : kids) sb.append(k.getName()).append('\n');
                    }
                    sb.append("END\n");
                    out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } else if (line.startsWith("DEST ")) {
                    String p = line.substring(5).trim();
                    File d = new File(p);
                    if (!allowed(p)) send(out, "ERR not allowed");
                    else if (!d.isDirectory() && !d.mkdirs()) send(out, "ERR cannot create folder");
                    else { sessionDest = d; status = "PC connected\nSaving into: " + p; send(out, "OK|" + freeBytes(d)); }
                } else if (line.startsWith("MKDIR ")) {
                    String p = line.substring(6).trim();
                    File d = new File(p);
                    if (!allowed(p)) send(out, "ERR not allowed");
                    else if (!d.isDirectory() && !d.mkdirs()) send(out, "ERR cannot create folder");
                    else send(out, "OK");
                } else if (line.equals("LIST")) {
                    StringBuilder sb = new StringBuilder();
                    walk(dest, "", sb);
                    sb.append("END\n");
                    out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } else if (line.startsWith("PUT ")) {
                    String[] p = line.split(" ", 3);
                    if (p.length < 3) { send(out, "ERR bad command"); continue; }
                    long size = Long.parseLong(p[1]);
                    String rel = p[2];
                    if (size < 0) { send(out, "ERR bad size"); continue; }
                    String err = receive(in, dest, rel, size, buf);
                    send(out, err == null ? "OK" : "ERR " + err);
                    if (err != null && err.startsWith("!")) break; // stream broken
                } else if (line.equals("BYE")) {
                    break;
                } else {
                    send(out, "ERR unknown command");
                }
            }
        } catch (Exception e) {
            status = "Connection lost: " + e.getMessage();
        } finally {
            connected = false;
            curSize = 0; currentFile = "";
            releaseLocks();
            if (status.equals("PC connected")) status = "Waiting for PC...";
            else status = status + "\nWaiting for PC...";
        }
    }

    /** Returns null on success, an error text otherwise. "!"-prefixed errors mean the stream is out of sync. */
    String receive(InputStream in, File dest, String rel, long size, byte[] buf) {
        String safe = rel.replace('\\', '/');
        boolean bad = safe.isEmpty() || safe.startsWith("/") || safe.endsWith("/") || safe.endsWith(".nspart");
        for (int i = 0; i < safe.length() && !bad; i++) if (safe.charAt(i) < 32) bad = true;   // control characters
        for (String part : safe.split("/")) {
            if (part.equals("..") || part.equals(".") || part.isEmpty()) bad = true;
        }
        if (bad) { skip(in, size, buf); return "bad path"; }
        File target = new File(dest, safe);
        File partFile = new File(target.getPath() + ".nspart");
        currentFile = safe; curSize = size; curDone = 0;
        FileOutputStream fo = null;
        String writeErr = null;
        long left = size;
        try {
            File parent = target.getParentFile();
            if (parent != null) parent.mkdirs();
            fo = new FileOutputStream(partFile);
        } catch (IOException e) {
            writeErr = "cannot write (" + e.getMessage() + ")";
        }
        try {
            while (left > 0) {
                int n = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (n < 0) throw new IOException("PC disconnected");
                if (fo != null && writeErr == null) {
                    try { fo.write(buf, 0, n); } catch (IOException e) { writeErr = "write failed (" + e.getMessage() + ")"; }
                }
                left -= n;
                curDone += n;
            }
        } catch (IOException e) {
            closeQuietly(fo);
            partFile.delete();
            return "!" + e.getMessage();
        }
        closeQuietly(fo);
        if (writeErr != null) { partFile.delete(); return writeErr; }
        if (target.exists()) target.delete();
        if (!partFile.renameTo(target)) return "rename failed";
        if (target.length() != size) return "size mismatch";
        sessionFiles++;
        sessionBytes += size;
        return null;
    }

    static void skip(InputStream in, long size, byte[] buf) {
        try {
            long left = size;
            while (left > 0) {
                int n = in.read(buf, 0, (int) Math.min(buf.length, left));
                if (n < 0) return;
                left -= n;
            }
        } catch (IOException ignored) { }
    }

    static void closeQuietly(FileOutputStream f) {
        if (f == null) return;
        try { f.close(); } catch (IOException ignored) { }
    }

    static void walk(File dir, String prefix, StringBuilder sb) {
        File[] kids = dir.listFiles();
        if (kids == null) return;
        for (File k : kids) {
            String rel = prefix.isEmpty() ? k.getName() : prefix + "/" + k.getName();
            if (k.isDirectory()) walk(k, rel, sb);
            else if (!k.getName().endsWith(".nspart")) sb.append(k.length()).append('|').append(rel).append('\n');
        }
    }

    static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        int c;
        while ((c = in.read()) != -1) {
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > MAX_LINE) throw new IOException("line too long");
        }
        if (c == -1 && b.size() == 0) return null;
        return new String(b.toByteArray(), StandardCharsets.UTF_8);
    }

    static void send(OutputStream out, String s) throws IOException {
        out.write((s + "\n").getBytes(StandardCharsets.UTF_8));
        out.flush();
    }

    void acquireLocks() {
        try { wakeLock.acquire(12 * 60 * 60 * 1000L); } catch (Exception ignored) { }
        try { if (wifiLock != null) wifiLock.acquire(); } catch (Exception ignored) { }
    }

    void releaseLocks() {
        try { if (wakeLock != null && wakeLock.isHeld()) wakeLock.release(); } catch (Exception ignored) { }
        try { if (wifiLock != null && wifiLock.isHeld()) wifiLock.release(); } catch (Exception ignored) { }
    }
}
