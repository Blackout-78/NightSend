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
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Locale;

/**
 * NightSend receiver service. Runs in the foreground so it keeps receiving with the
 * screen off and the app closed. Listens on port 47800 for the NightSend PC app on the
 * same Wi-Fi. No internet, no cloud.
 *
 * Protocol (one line commands, UTF-8, ending in \n):
 *   PAIR code        -> OK, or ERR code (must be the first line; nothing else is answered before it)
 *   HELLO            -> NIGHTSEND|model|freeBytes|destPath|storageOk(1/0)
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
        if (Build.VERSION.SDK_INT >= 34) {
            startForeground(NOTE_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
        } else {
            startForeground(NOTE_ID, n);
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
        try {
            server = new ServerSocket();
            server.setReuseAddress(true);
            server.bind(new InetSocketAddress(PORT));
        } catch (IOException e) {
            status = "Could not start: " + e.getMessage();
            return;
        }
        status = "Waiting for PC...";
        while (running) {
            Socket s;
            try { s = server.accept(); } catch (IOException e) { if (!running) return; continue; }
            handle(s);
        }
    }

    /** Checks the PAIR line. Compares in constant time so the timing gives nothing away. */
    boolean codeMatches(String line) {
        if (line == null || !line.startsWith("PAIR ")) return false;
        byte[] a = line.substring(5).trim().getBytes(StandardCharsets.UTF_8);
        byte[] b = pairCode.getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(a, b);
    }

    void handle(Socket s) {
        try {
            // Nothing is answered or shown until the right code arrives.
            s.setSoTimeout(10000);
            InputStream in = new BufferedInputStream(s.getInputStream(), 1 << 20);
            OutputStream out = s.getOutputStream();
            String first = readLine(in);
            if (!codeMatches(first)) {
                if (first == null) return; // a plain "is anyone there?" knock from Find phone
                wrongTries++;
                if (wrongTries >= MAX_WRONG) {
                    newCode(this);
                    status = "Wrong code tried " + MAX_WRONG + " times. A new code was made.";
                } else {
                    status = "Wrong pairing code from " + s.getInetAddress().getHostAddress() + ". Blocked.";
                }
                Thread.sleep(1000); // slows down guessing
                send(out, "ERR code");
                return;
            }
            wrongTries = 0;
            send(out, "OK");
            session(s, in, out);
        } catch (Exception e) {
            // ignore: a bad or dropped connection before pairing
        } finally {
            try { s.close(); } catch (IOException ignored) { }
        }
    }

    void session(Socket s, InputStream in, OutputStream out) {
        connected = true;
        status = "PC connected";
        acquireLocks();
        try {
            s.setSoTimeout(180000);
            byte[] buf = new byte[1 << 20];
            String line;
            while ((line = readLine(in)) != null) {
                File dest = destFolder(this);
                if (line.equals("HELLO")) {
                    dest.mkdirs();
                    send(out, "NIGHTSEND|" + Build.MANUFACTURER + " " + Build.MODEL + "|" + freeBytes(dest) + "|" +
                            dest.getPath() + "|" + (hasStorage(this) ? 1 : 0));
                } else if (line.equals("LIST")) {
                    StringBuilder sb = new StringBuilder();
                    walk(dest, "", sb);
                    sb.append("END\n");
                    out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
                    out.flush();
                } else if (line.startsWith("PUT ")) {
                    String[] p = line.split(" ", 3);
                    long size = Long.parseLong(p[1]);
                    String rel = p[2];
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
        for (String part : safe.split("/")) {
            if (part.equals("..")) { skip(in, size, buf); return "bad path"; }
        }
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
