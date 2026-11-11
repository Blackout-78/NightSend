package com.blackout.nightsend;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.SurfaceTexture;
import android.hardware.Camera;
import android.os.Bundle;
import android.view.Gravity;
import android.view.Surface;
import android.view.TextureView;
import android.view.ViewGroup;
import android.widget.FrameLayout;
import android.widget.TextView;

import com.google.zxing.BinaryBitmap;
import com.google.zxing.DecodeHintType;
import com.google.zxing.PlanarYUVLuminanceSource;
import com.google.zxing.Result;
import com.google.zxing.common.HybridBinarizer;
import com.google.zxing.qrcode.QRCodeReader;

import java.util.EnumMap;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Scans the pairing QR code shown by the PC app. Everything happens on the phone: the camera frames
 * are decoded here and thrown away, nothing is saved or sent anywhere. Returns the text as "qr".
 */
@SuppressWarnings("deprecation")
public class QrScanActivity extends Activity implements TextureView.SurfaceTextureListener, Camera.PreviewCallback {

    private TextureView view;
    private Camera camera;
    private int previewW, previewH;
    private final AtomicBoolean busy = new AtomicBoolean(false);
    private final AtomicBoolean done = new AtomicBoolean(false);
    private final ExecutorService decoder = Executors.newSingleThreadExecutor();
    private final QRCodeReader reader = new QRCodeReader();
    private final Map<DecodeHintType, Object> hints = new EnumMap<>(DecodeHintType.class);
    private SurfaceTexture surface;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        getWindow().setStatusBarColor(Color.BLACK);
        hints.put(DecodeHintType.TRY_HARDER, Boolean.TRUE);
        FrameLayout root = new FrameLayout(this);
        root.setBackgroundColor(Color.BLACK);
        view = new TextureView(this);
        view.setSurfaceTextureListener(this);
        root.addView(view, new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));
        TextView hint = new TextView(this);
        hint.setText("Point the camera at the QR code on the PC screen");
        hint.setTextColor(Color.WHITE);
        hint.setTextSize(16);
        hint.setGravity(Gravity.CENTER);
        hint.setPadding(40, 40, 40, 40);
        hint.setBackgroundColor(Color.argb(150, 0, 0, 0));
        FrameLayout.LayoutParams lp = new FrameLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT, Gravity.BOTTOM);
        root.addView(hint, lp);
        setContentView(root);
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            requestPermissions(new String[]{Manifest.permission.CAMERA}, 1);
        }
    }

    @Override
    public void onRequestPermissionsResult(int code, String[] perms, int[] results) {
        super.onRequestPermissionsResult(code, perms, results);
        if (results.length > 0 && results[0] == PackageManager.PERMISSION_GRANTED) {
            startCamera();
        } else {
            finish();   // no camera permission: the "Type the code instead" option still works
        }
    }

    @Override public void onSurfaceTextureAvailable(SurfaceTexture st, int w, int h) { surface = st; startCamera(); }
    @Override public void onSurfaceTextureSizeChanged(SurfaceTexture st, int w, int h) { }
    @Override public boolean onSurfaceTextureDestroyed(SurfaceTexture st) { stopCamera(); surface = null; return true; }
    @Override public void onSurfaceTextureUpdated(SurfaceTexture st) { }

    @Override
    protected void onResume() {
        super.onResume();
        if (surface != null) startCamera();
    }

    @Override
    protected void onPause() {
        stopCamera();
        super.onPause();
    }

    @Override
    protected void onDestroy() {
        stopCamera();
        decoder.shutdownNow();
        super.onDestroy();
    }

    private void startCamera() {
        if (camera != null || surface == null) return;
        if (checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return;
        try {
            camera = Camera.open();   // the back camera
            Camera.Parameters p = camera.getParameters();
            Camera.Size best = null;
            for (Camera.Size s : p.getSupportedPreviewSizes()) {
                // about 1 megapixel decodes fast and is sharp enough for a QR code
                long px = (long) s.width * s.height;
                if (px >= 600000 && px <= 2100000 && (best == null || px < (long) best.width * best.height)) best = s;
            }
            if (best == null) best = p.getPreviewSize();
            p.setPreviewSize(best.width, best.height);
            if (p.getSupportedFocusModes().contains(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE)) {
                p.setFocusMode(Camera.Parameters.FOCUS_MODE_CONTINUOUS_PICTURE);
            }
            camera.setParameters(p);
            previewW = best.width;
            previewH = best.height;
            camera.setDisplayOrientation(displayOrientation());
            camera.setPreviewTexture(surface);
            camera.setPreviewCallback(this);
            camera.startPreview();
        } catch (Exception e) {
            stopCamera();
            finish();   // camera busy or missing: use "Type the code instead"
        }
    }

    private void stopCamera() {
        if (camera == null) return;
        try { camera.setPreviewCallback(null); camera.stopPreview(); } catch (Exception ignored) { }
        try { camera.release(); } catch (Exception ignored) { }
        camera = null;
    }

    private int displayOrientation() {
        Camera.CameraInfo info = new Camera.CameraInfo();
        Camera.getCameraInfo(0, info);
        int deg = 0;
        switch (getWindowManager().getDefaultDisplay().getRotation()) {
            case Surface.ROTATION_90: deg = 90; break;
            case Surface.ROTATION_180: deg = 180; break;
            case Surface.ROTATION_270: deg = 270; break;
            default: deg = 0;
        }
        return (info.orientation - deg + 360) % 360;
    }

    @Override
    public void onPreviewFrame(final byte[] data, Camera cam) {
        if (done.get() || data == null || !busy.compareAndSet(false, true)) return;
        final byte[] copy = data.clone();
        final int w = previewW, h = previewH;
        decoder.execute(() -> {
            try {
                // QR codes are found at any rotation, so the frame is used as it comes from the camera.
                // Own offline reader first; ZXing is only the backup.
                String own = null;
                try { own = QrDecoder.decode(copy, w, h); } catch (RuntimeException ignored) { }
                if (own != null && own.startsWith("NS3:") && done.compareAndSet(false, true)) {
                    final String t = own;
                    runOnUiThread(() -> {
                        setResult(RESULT_OK, new Intent().putExtra("qr", t));
                        finish();
                    });
                    return;
                }
                PlanarYUVLuminanceSource src = new PlanarYUVLuminanceSource(copy, w, h, 0, 0, w, h, false);
                Result r = reader.decode(new BinaryBitmap(new HybridBinarizer(src)), hints);
                String text = r.getText();
                if (text != null && text.startsWith("NS3:") && done.compareAndSet(false, true)) {
                    runOnUiThread(() -> {
                        setResult(RESULT_OK, new Intent().putExtra("qr", text));
                        finish();
                    });
                }
            } catch (Exception ignored) {
                // no QR code in this frame: try the next one
            } finally {
                reader.reset();
                busy.set(false);
            }
        });
    }
}
