package com.blackout.nightsend;

import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.os.StatFs;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * NightSend receiver. Listens on port 47800 for the NightSend PC app on the
 * same Wi-Fi (the PC finds the phone by itself). No internet, no cloud.
 *
 * Protocol (one line commands, UTF-8, ending in \n):
 *   PAIR code        -> OK, or ERR code (must be the first line; nothing else is answered before it)
 *   HELLO            -> NIGHTSEND|model|freeBytes|destPath|storageOk(1/0)
 *   LIST             -> size|relativePath lines, then END
 *   PUT size relPath -> (then exactly size bytes) -> OK or ERR reason
 *   BYE
 */
public class MainActivity extends Activity {

    static final int PORT = 47800;
    static final int MAX_WRONG = 5;        // wrong codes in a row before a new code is made
    static final int MAX_LINE = 8192;      // longest command line accepted
    static final int BG = Color.rgb(10, 10, 12);
    static final int PANEL = Color.rgb(28, 28, 32);
    static final int TEXT = Color.rgb(220, 220, 225);
    static final int DIM = Color.rgb(130, 130, 140);
    static final int ACCENT = Color.rgb(150, 30, 40);
    static final int GOOD = Color.rgb(90, 170, 110);

    final Handler ui = new Handler(Looper.getMainLooper());
    final List<File> volumes = new ArrayList<>();
    final List<String> volumeNames = new ArrayList<>();

    TextView statusView, addrView, progressView, storageView, codeView;
    volatile String pairCode;
    volatile int wrongTries = 0;
    final SecureRandom rng = new SecureRandom();
    Button grantButton;
    Spinner volSpinner;
    EditText folderEdit;
    SharedPreferences prefs;

    volatile File destRoot;
    volatile String status = "Starting...";
    volatile String currentFile = "";
    volatile long curDone = 0, curSize = 0, sessionBytes = 0, sessionFiles = 0;
    volatile boolean connected = false;
    volatile boolean running = true;

    ServerSocket server;
    PowerManager.WakeLock wakeLock;
    WifiManager.WifiLock wifiLock;

    // ---------------------------------------------------------------- UI

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        prefs = getSharedPreferences("nightsend", MODE_PRIVATE);

        loadVolumes();

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(BG);
        int pad = dp(20);
        root.setPadding(pad, pad, pad, pad);

        TextView title = text("NIGHTSEND", 34, TEXT);
        title.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        title.setLetterSpacing(0.12f);
        root.addView(title);
        root.addView(text("Same Wi-Fi  -  just type the code  -  no cloud", 14, DIM));

        View line = new View(this);
        line.setBackgroundColor(ACCENT);
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(2));
        lp.setMargins(0, dp(12), 0, dp(16));
        root.addView(line, lp);

        statusView = text("", 20, TEXT);
        statusView.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        root.addView(statusView);
        progressView = text("", 15, DIM);
        root.addView(progressView);

        pairCode = prefs.getString("code", null);
        if (pairCode == null) newCode();
        root.addView(header("PAIRING CODE (type this into the PC app)"));
        codeView = text("", 34, TEXT);
        codeView.setTypeface(Typeface.MONOSPACE, Typeface.BOLD);
        codeView.setLetterSpacing(0.15f);
        root.addView(codeView);
        TextView newCodeBtn = text("Tap here to make a new code", 13, ACCENT);
        newCodeBtn.setOnClickListener(v -> { newCode(); status = "New code made. Type it into the PC app."; });
        root.addView(newCodeBtn);

        root.addView(header("PHONE ADDRESS (the PC finds it by itself)"));
        addrView = text("", 16, TEXT);
        addrView.setTypeface(Typeface.MONOSPACE);
        root.addView(addrView);

        root.addView(header("SAVE TO"));
        volSpinner = new Spinner(this);
        volSpinner.setBackgroundColor(PANEL);
        ArrayAdapter<String> ad = new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, volumeNames);
        volSpinner.setAdapter(ad);
        int savedVol = prefs.getInt("vol", 0);
        if (savedVol < volumes.size()) volSpinner.setSelection(savedVol);
        root.addView(volSpinner, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(48)));

        folderEdit = new EditText(this);
        folderEdit.setText(prefs.getString("folder", "Movies/TV"));
        folderEdit.setTextColor(TEXT);
        folderEdit.setBackgroundColor(PANEL);
        folderEdit.setPadding(dp(12), dp(10), dp(12), dp(10));
        folderEdit.setSingleLine(true);
        LinearLayout.LayoutParams fp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        fp.setMargins(0, dp(8), 0, 0);
        root.addView(folderEdit, fp);

        storageView = text("", 14, DIM);
        root.addView(storageView);

        grantButton = new Button(this);
        grantButton.setText("Allow NightSend to save files");
        grantButton.setTextColor(Color.WHITE);
        grantButton.setBackgroundColor(ACCENT);
        grantButton.setOnClickListener(v -> askStorage());
        LinearLayout.LayoutParams gp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        gp.setMargins(0, dp(12), 0, 0);
        root.addView(grantButton, gp);

        root.addView(header("HOW TO CONNECT"));
        root.addView(text(
                "1. Join the same Wi-Fi as the PC.\n" +
                "2. Open NightSend on the PC and type the code above.\n" +
                "Keep this screen open while sending.", 14, DIM));

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(BG);
        sv.addView(root);
        setContentView(sv);

        volSpinner.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
            @Override public void onItemSelected(AdapterView<?> p, View v, int pos, long id) {
                prefs.edit().putInt("vol", pos).apply();
                updateDest();
            }
            @Override public void onNothingSelected(AdapterView<?> p) { }
        });
        folderEdit.addTextChangedListener(new TextWatcher() {
            @Override public void beforeTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void onTextChanged(CharSequence s, int a, int b, int c) { }
            @Override public void afterTextChanged(Editable s) {
                prefs.edit().putString("folder", s.toString()).apply();
                updateDest();
            }
        });

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "nightsend:transfer");
        wakeLock.setReferenceCounted(false);
        WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm != null) {
            wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "nightsend:wifi");
            wifiLock.setReferenceCounted(false);
        }

        updateDest();
        new Thread(this::serverLoop, "nightsend-server").start();
        ui.post(refresher);
    }

    @Override
    protected void onResume() {
        super.onResume();
        updateDest();
    }

    @Override
    protected void onDestroy() {
        running = false;
        try { if (server != null) server.close(); } catch (IOException ignored) { }
        releaseLocks();
        ui.removeCallbacks(refresher);
        super.onDestroy();
    }

    final Runnable refresher = new Runnable() {
        @Override public void run() {
            statusView.setText(status);
            statusView.setTextColor(connected ? GOOD : TEXT);
            if (connected && curSize > 0) {
                progressView.setText(String.format(Locale.US, "%s\n%s of %s   |   this session: %d files, %s",
                        currentFile, fmt(curDone), fmt(curSize), sessionFiles, fmt(sessionBytes)));
            } else if (sessionFiles > 0) {
                progressView.setText(String.format(Locale.US, "Received this session: %d files, %s", sessionFiles, fmt(sessionBytes)));
            } else {
                progressView.setText("");
            }
            addrView.setText(addresses());
            String c = pairCode;
            codeView.setText(c.substring(0, 3) + " " + c.substring(3));
            ui.postDelayed(this, 700);
        }
    };

    TextView text(String s, int sp, int color) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(sp);
        t.setTextColor(color);
        t.setPadding(0, dp(4), 0, dp(4));
        return t;
    }

    TextView header(String s) {
        TextView t = text(s, 13, DIM);
        t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        t.setPadding(0, dp(22), 0, dp(6));
        return t;
    }

    int dp(int v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    static String fmt(long b) {
        String[] u = {"B", "KB", "MB", "GB", "TB"};
        double d = b; int i = 0;
        while (d >= 1024 && i < 4) { d /= 1024; i++; }
        return String.format(Locale.US, "%.1f %s", d, u[i]);
    }

    // ---------------------------------------------------------------- storage

    void loadVolumes() {
        volumes.clear(); volumeNames.clear();
        if (Build.VERSION.SDK_INT >= 30) {
            StorageManager sm = (StorageManager) getSystemService(Context.STORAGE_SERVICE);
            for (StorageVolume v : sm.getStorageVolumes()) {
                File d = v.getDirectory();
                if (d != null) { volumes.add(d); volumeNames.add(v.getDescription(this)); }
            }
        }
        if (volumes.isEmpty()) {
            volumes.add(Environment.getExternalStorageDirectory());
            volumeNames.add("Phone storage");
        }
    }

    boolean hasStorage() {
        if (Build.VERSION.SDK_INT >= 30) return Environment.isExternalStorageManager();
        return checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    void askStorage() {
        if (Build.VERSION.SDK_INT >= 30) {
            try {
                startActivity(new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                        Uri.parse("package:" + getPackageName())));
            } catch (Exception e) {
                startActivity(new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION));
            }
        } else {
            requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, 1);
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        updateDest();
    }

    void updateDest() {
        if (volSpinner == null) return;
        int pos = volSpinner.getSelectedItemPosition();
        if (pos < 0 || pos >= volumes.size()) pos = 0;
        String sub = folderEdit.getText().toString().trim().replace('\\', '/');
        while (sub.startsWith("/")) sub = sub.substring(1);
        while (sub.endsWith("/")) sub = sub.substring(0, sub.length() - 1);
        File d = sub.isEmpty() ? volumes.get(pos) : new File(volumes.get(pos), sub);
        destRoot = d;
        boolean ok = hasStorage();
        grantButton.setVisibility(ok ? View.GONE : View.VISIBLE);
        long free = freeBytes(volumes.get(pos));
        storageView.setText((ok ? "" : "Storage permission needed.  ") +
                (free >= 0 ? fmt(free) + " free  -  " : "") + d.getPath());
    }

    static long freeBytes(File f) {
        try {
            File p = f;
            while (p != null && !p.exists()) p = p.getParentFile();
            if (p == null) return -1;
            return new StatFs(p.getPath()).getAvailableBytes();
        } catch (Exception e) { return -1; }
    }

    // ---------------------------------------------------------------- network

    String addresses() {
        StringBuilder sb = new StringBuilder();
        try {
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                if (!ni.isUp() || ni.isLoopback()) continue;
                for (InetAddress a : Collections.list(ni.getInetAddresses())) {
                    if (a instanceof Inet4Address) {
                        String n = ni.getName();
                        String kind = n.startsWith("rndis") || n.startsWith("usb") || n.startsWith("ncm") ? "USB" :
                                n.startsWith("wlan") || n.startsWith("swlan") ? "Wi-Fi" : n;
                        if (sb.length() > 0) sb.append('\n');
                        sb.append(a.getHostAddress()).append("   (").append(kind).append(")");
                    }
                }
            }
        } catch (Exception ignored) { }
        return sb.length() == 0 ? "No connection yet - join the same Wi-Fi as the PC." : sb.toString();
    }

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

    void newCode() {
        pairCode = String.format(Locale.US, "%06d", rng.nextInt(1000000));
        wrongTries = 0;
        prefs.edit().putString("code", pairCode).apply();
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
                    newCode();
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
                File dest = destRoot;
                if (line.equals("HELLO")) {
                    dest.mkdirs();
                    send(out, "NIGHTSEND|" + Build.MANUFACTURER + " " + Build.MODEL + "|" + freeBytes(dest) + "|" +
                            dest.getPath() + "|" + (hasStorage() ? 1 : 0));
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
