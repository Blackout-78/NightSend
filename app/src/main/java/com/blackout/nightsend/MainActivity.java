package com.blackout.nightsend;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.os.storage.StorageManager;
import android.os.storage.StorageVolume;
import android.provider.Settings;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

/**
 * NightSend screen. The receiving itself runs in TransferService, which keeps going
 * with the screen off and this app closed. This screen shows the code, the status and
 * lets you pick the folder on the phone where files are saved.
 */
public class MainActivity extends Activity {

    static final int BG = Color.rgb(10, 10, 12);
    static final int PANEL = Color.rgb(28, 28, 32);
    static final int TEXT = Color.rgb(220, 220, 225);
    static final int DIM = Color.rgb(130, 130, 140);
    static final int ACCENT = Color.rgb(150, 30, 40);
    static final int GOOD = Color.rgb(90, 170, 110);

    final Handler ui = new Handler(Looper.getMainLooper());
    final List<File> volumes = new ArrayList<>();

    TextView statusView, addrView, progressView, storageView, codeView, folderView, outboxView;
    String pickKey = "dest";   // which setting the folder picker is choosing: "dest" (save folder) or "outbox" (folder sent to the PC)
    Button grantButton;
    SharedPreferences prefs;
    static final int REQ_SCAN = 7;

    // ---------------------------------------------------------------- UI

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // The pairing code is on this screen: keep it out of screenshots and the recent-apps preview.
        getWindow().setFlags(android.view.WindowManager.LayoutParams.FLAG_SECURE,
                android.view.WindowManager.LayoutParams.FLAG_SECURE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        prefs = TransferService.prefs(this);
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
        root.addView(text("Pair once with a QR code  -  no cloud", 14, DIM));

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

        root.addView(header("PAIR A NEW PC (once per PC)"));
        codeView = text("", 16, TEXT);
        root.addView(codeView);
        Button scanButton = new Button(this);
        scanButton.setText("Scan the PC's QR code");
        scanButton.setTextColor(Color.WHITE);
        scanButton.setBackgroundColor(ACCENT);
        scanButton.setOnClickListener(v -> startActivityForResult(new Intent(this, QrScanActivity.class), REQ_SCAN));
        LinearLayout.LayoutParams sp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        sp.setMargins(0, dp(8), 0, 0);
        root.addView(scanButton, sp);
        TextView typeBtn = text("No camera? Type the code instead", 13, ACCENT);
        typeBtn.setOnClickListener(v -> typeCode());
        root.addView(typeBtn);
        android.widget.CheckBox strictBox = new android.widget.CheckBox(this);
        strictBox.setText("Strict mode: new QR scan for every session");
        strictBox.setTextColor(TEXT);
        strictBox.setChecked(TransferService.strict(this));
        strictBox.setOnCheckedChangeListener((b, on) -> {
            prefs.edit().putBoolean("strict", on).apply();
            if (on) TransferService.forgetAll(this);   // nothing is remembered in strict mode
            TransferService.status = on ? "Strict mode on. Every session needs a fresh QR scan."
                    : "Strict mode off. A paired PC reconnects by itself.";
        });
        root.addView(strictBox);
        TextView newCodeBtn = text("Tap here to forget all paired PCs", 13, ACCENT);
        newCodeBtn.setOnClickListener(v -> new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle("Forget all paired PCs?")
                .setMessage("Every PC will need to be paired again with a new QR code.")
                .setPositiveButton("Forget all", (d, w) -> {
                    TransferService.forgetAll(this);
                    TransferService.status = "All PCs forgotten. Pair again with the PC's QR code.";
                })
                .setNegativeButton("Cancel", null)
                .show());
        root.addView(newCodeBtn);

        root.addView(header("PHONE ADDRESS (the PC finds it by itself)"));
        addrView = text("", 16, TEXT);
        addrView.setTypeface(Typeface.MONOSPACE);
        root.addView(addrView);

        root.addView(header("SAVE TO (folder on this phone)"));
        folderView = text("", 16, TEXT);
        folderView.setTypeface(Typeface.MONOSPACE);
        root.addView(folderView);
        Button chooseButton = new Button(this);
        chooseButton.setText("Choose folder");
        chooseButton.setTextColor(Color.WHITE);
        chooseButton.setBackgroundColor(PANEL);
        chooseButton.setOnClickListener(v -> chooseFolder());
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        cp.setMargins(0, dp(8), 0, 0);
        root.addView(chooseButton, cp);
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

        root.addView(header("SEND TO PC (folder on this phone)"));
        outboxView = text("", 16, TEXT);
        outboxView.setTypeface(Typeface.MONOSPACE);
        root.addView(outboxView);
        Button sendButton = new Button(this);
        sendButton.setText("Choose folder to send");
        sendButton.setTextColor(Color.WHITE);
        sendButton.setBackgroundColor(PANEL);
        sendButton.setOnClickListener(v -> chooseOutbox());
        LinearLayout.LayoutParams op = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(52));
        op.setMargins(0, dp(8), 0, 0);
        root.addView(sendButton, op);
        TextView stopShare = text("Tap here to stop sharing", 13, ACCENT);
        stopShare.setOnClickListener(v -> { prefs.edit().remove("outbox").apply(); updateDest(); });
        root.addView(stopShare);
        root.addView(text("Then press RECEIVE on the PC. The PC can only take files from this one folder.", 14, DIM));

        root.addView(header("HOW TO CONNECT"));
        root.addView(text(
                "1. Connect the phone and PC: USB cable (USB tethering), the phone's hotspot / Wi-Fi Direct, or the same Wi-Fi.\n" +
                "2. On the PC press Pair with QR. Here tap Scan the PC's QR code and point the camera at it.\n" +
                "3. On the PC press Find phone.\n" +
                "To send from this phone to the PC: choose a folder under SEND TO PC, then press RECEIVE on the PC.\n" +
                "NightSend keeps receiving in the background, even with the screen off or this app closed. " +
                "Stop it from the notification.", 14, DIM));

        ScrollView sv = new ScrollView(this);
        sv.setBackgroundColor(BG);
        sv.addView(root);
        setContentView(sv);

        if (Build.VERSION.SDK_INT >= 33
                && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 2);
        }
        startReceiver();
        updateDest();
        ui.post(refresher);
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQ_SCAN && result == RESULT_OK && data != null) {
            if (!TransferService.armPairing(data.getStringExtra("qr")))
                TransferService.status = "That QR code is not a NightSend pairing code.";
        }
    }

    /** Fallback when the camera cannot be used: type the code shown under the PC's QR picture. */
    void typeCode() {
        EditText e = new EditText(this);
        e.setSingleLine(true);
        e.setHint("32 letters and numbers");
        new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle("Code from the PC")
                .setView(e)
                .setPositiveButton("Pair", (d, w) -> {
                    if (!TransferService.armPairing(e.getText().toString()))
                        TransferService.status = "That is not a valid pairing code (32 letters and numbers).";
                })
                .setNegativeButton("Cancel", null)
                .show();
    }

    void startReceiver() {
        try { startForegroundService(new Intent(this, TransferService.class)); } catch (Exception ignored) { }
    }

    @Override
    protected void onResume() {
        super.onResume();
        startReceiver();
        updateDest();
    }

    @Override
    protected void onDestroy() {
        ui.removeCallbacks(refresher);
        super.onDestroy(); // the service keeps running
    }

    final Runnable refresher = new Runnable() {
        @Override public void run() {
            statusView.setText(TransferService.status);
            statusView.setTextColor(TransferService.connected ? GOOD : TEXT);
            if (TransferService.connected && TransferService.curSize > 0) {
                progressView.setText(String.format(Locale.US, "%s\n%s of %s   |   this session: %d received, %d sent",
                        TransferService.currentFile, TransferService.fmt(TransferService.curDone),
                        TransferService.fmt(TransferService.curSize), TransferService.sessionFiles,
                        TransferService.sentFiles));
            } else if (TransferService.sessionFiles > 0 || TransferService.sentFiles > 0) {
                progressView.setText(String.format(Locale.US, "This session: %d received (%s), %d sent (%s)",
                        TransferService.sessionFiles, TransferService.fmt(TransferService.sessionBytes),
                        TransferService.sentFiles, TransferService.fmt(TransferService.sentBytes)));
            } else {
                progressView.setText("");
            }
            addrView.setText(addresses());
            long left = (TransferService.pairExpires - System.currentTimeMillis()) / 1000;
            if (TransferService.pairSecret != null && left > 0) {
                codeView.setText("Ready to pair: " + left + " s left. Press Find phone on the PC.");
                codeView.setTextColor(GOOD);
            } else {
                codeView.setText("Not pairing. Saved PCs reconnect by themselves.");
                codeView.setTextColor(DIM);
            }
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

    // ---------------------------------------------------------------- storage

    void loadVolumes() {
        volumes.clear();
        if (Build.VERSION.SDK_INT >= 30) {
            StorageManager sm = (StorageManager) getSystemService(Context.STORAGE_SERVICE);
            for (StorageVolume v : sm.getStorageVolumes()) {
                File d = v.getDirectory();
                if (d != null) volumes.add(d);
            }
        }
        if (volumes.isEmpty()) volumes.add(Environment.getExternalStorageDirectory());
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
        if (folderView == null) return;
        File d = TransferService.destFolder(this);
        boolean ok = TransferService.hasStorage(this);
        grantButton.setVisibility(ok ? View.GONE : View.VISIBLE);
        long free = TransferService.freeBytes(d);
        folderView.setText(d.getPath());
        File ob = TransferService.outboxFolder(this);
        outboxView.setText(ob == null ? "Nothing shared." : ob.getPath());
        storageView.setText((ok ? "" : "Storage permission needed.  ") +
                (free >= 0 ? TransferService.fmt(free) + " free" : ""));
    }

    // ---------------------------------------------------------------- folder picker

    void chooseOutbox() {
        if (!TransferService.hasStorage(this)) { askStorage(); return; }
        pickKey = "outbox";
        File cur = TransferService.outboxFolder(this);
        if (cur == null) cur = Environment.getExternalStorageDirectory();
        while (cur != null && !cur.isDirectory()) cur = cur.getParentFile();
        showFolders(cur);
    }

    void chooseFolder() {
        if (!TransferService.hasStorage(this)) { askStorage(); return; }
        pickKey = "dest";
        File cur = TransferService.destFolder(this);
        while (cur != null && !cur.isDirectory()) cur = cur.getParentFile();
        showFolders(cur);
    }

    /** Lists the folders inside dir. dir == null lists the storage volumes. */
    void showFolders(File dir) {
        List<String> names = new ArrayList<>();
        List<File> targets = new ArrayList<>();
        if (dir == null) {
            for (File v : volumes) { names.add(v.getPath()); targets.add(v); }
        } else {
            names.add("..  (up)");
            targets.add(volumes.contains(dir) ? null : dir.getParentFile());
            File[] kids = dir.listFiles(f -> f.isDirectory());
            if (kids != null) {
                Arrays.sort(kids, (x, y) -> x.getName().compareToIgnoreCase(y.getName()));
                for (File k : kids) { names.add(k.getName()); targets.add(k); }
            }
        }
        final File shown = dir;
        AlertDialog.Builder b = new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert);
        b.setTitle(dir == null ? "Choose storage" : dir.getPath());
        b.setItems(names.toArray(new String[0]), (d, i) -> showFolders(targets.get(i)));
        if (dir != null) {
            final String key = pickKey;
            b.setPositiveButton("Use this folder", (d, w) -> {
                if (key.equals("outbox") && volumes.contains(shown)) {
                    // Sharing a whole storage would let the PC take everything on it.
                    Toast.makeText(this, "Pick a folder inside the storage, not the whole storage.", Toast.LENGTH_LONG).show();
                    return;
                }
                prefs.edit().putString(key, shown.getPath()).apply();
                updateDest();
            });
            if (key.equals("dest")) b.setNeutralButton("New folder", (d, w) -> newFolder(shown));
        }
        b.setNegativeButton("Cancel", null);
        b.show();
    }

    void newFolder(File parent) {
        EditText e = new EditText(this);
        e.setSingleLine(true);
        e.setHint("Folder name");
        new AlertDialog.Builder(this, android.R.style.Theme_DeviceDefault_Dialog_Alert)
                .setTitle("New folder in " + parent.getName())
                .setView(e)
                .setPositiveButton("Create", (d, w) -> {
                    String n = e.getText().toString().trim().replace('/', ' ').replace('\\', ' ');
                    File f = n.isEmpty() ? parent : new File(parent, n);
                    f.mkdirs();
                    showFolders(f.isDirectory() ? f : parent);
                })
                .setNegativeButton("Cancel", (d, w) -> showFolders(parent))
                .show();
    }

    // ---------------------------------------------------------------- network info

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
}
