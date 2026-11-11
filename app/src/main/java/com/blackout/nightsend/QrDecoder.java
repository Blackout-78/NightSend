package com.blackout.nightsend;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Small offline QR code reader. Pure Java, no third-party code, no network.
 * Reads one QR code (models 2, versions 1-40, numeric / alphanumeric / byte modes)
 * from an 8-bit luminance image. Handles rotation, tilt and mild damage (Reed-Solomon).
 */
public final class QrDecoder {
    private QrDecoder() {}

    /** @param lum 8-bit luminance, row-major, row length == width. Returns the text, or null if no code was read. */
    private static long deadline;

    public static String decode(byte[] lum, int width, int height) {
        if (lum == null || width < 21 || height < 21 || lum.length < width * height) return null;
        deadline = System.nanoTime() + 1200_000_000L;
        for (int mode = 0; mode < 4; mode++) {
            if (System.nanoTime() > deadline) break;
            try {
                boolean[] bin = binarize(lum, width, height, mode);
                String s = decodeBinary(bin, width, height);
                if (s != null) return s;
            } catch (RuntimeException ignored) {
                // fall through to the next binarizer
            }
        }
        return null;
    }

    // ---------------------------------------------------------------- binarize

    private static byte[] boxBlur(byte[] lum, int w, int h) {
        byte[] out = new byte[w * h];
        for (int y = 0; y < h; y++)
            for (int x = 0; x < w; x++) {
                int sum = 0, cnt = 0;
                for (int dy = -1; dy <= 1; dy++)
                    for (int dx = -1; dx <= 1; dx++) {
                        int xx = x + dx, yy = y + dy;
                        if (xx >= 0 && yy >= 0 && xx < w && yy < h) { sum += lum[yy * w + xx] & 0xFF; cnt++; }
                    }
                out[y * w + x] = (byte) (sum / cnt);
            }
        return out;
    }

    private static boolean[] binarize(byte[] lum, int w, int h, int mode) {
        boolean[] out = new boolean[w * h];
        if (mode == 2 || mode == 3) { // noisy images: smooth first, then use a tighter local window
            lum = boxBlur(lum, w, h);
        }
        if (mode == 0 || mode == 2 || mode == 3) {
            long[] integral = new long[(w + 1) * (h + 1)];
            for (int y = 0; y < h; y++) {
                long row = 0;
                for (int x = 0; x < w; x++) {
                    row += lum[y * w + x] & 0xFF;
                    integral[(y + 1) * (w + 1) + x + 1] = integral[y * (w + 1) + x + 1] + row;
                }
            }
            int half = Math.max(8, Math.max(w, h) / (mode == 3 ? 14 : 6));
            for (int y = 0; y < h; y++) {
                int y0 = Math.max(0, y - half), y1 = Math.min(h, y + half + 1);
                for (int x = 0; x < w; x++) {
                    int x0 = Math.max(0, x - half), x1 = Math.min(w, x + half + 1);
                    long sum = integral[y1 * (w + 1) + x1] - integral[y0 * (w + 1) + x1]
                            - integral[y1 * (w + 1) + x0] + integral[y0 * (w + 1) + x0];
                    long count = (long) (x1 - x0) * (y1 - y0);
                    out[y * w + x] = (lum[y * w + x] & 0xFF) * count * 100 < sum * 90;
                }
            }
        } else {
            int[] hist = new int[256];
            for (int i = 0; i < w * h; i++) hist[lum[i] & 0xFF]++;
            long total = (long) w * h, sumAll = 0;
            for (int i = 0; i < 256; i++) sumAll += (long) i * hist[i];
            long sumB = 0, wB = 0;
            double best = -1;
            int thr = 128;
            for (int t = 0; t < 256; t++) {
                wB += hist[t];
                if (wB == 0) continue;
                long wF = total - wB;
                if (wF == 0) break;
                sumB += (long) t * hist[t];
                double mB = (double) sumB / wB, mF = (double) (sumAll - sumB) / wF;
                double between = (double) wB * wF * (mB - mF) * (mB - mF);
                if (between > best) { best = between; thr = t; }
            }
            for (int i = 0; i < w * h; i++) out[i] = (lum[i] & 0xFF) <= thr;
        }
        return out;
    }

    // ----------------------------------------------------------- finder search

    private static final class Finder {
        double x, y, size;
        int count = 1;
        Finder(double x, double y, double size) { this.x = x; this.y = y; this.size = size; }
    }

    private static String decodeBinary(boolean[] bin, int w, int h) {
        List<Finder> fs = findFinders(bin, w, h);
        if (fs.size() < 3) return null;
        Collections.sort(fs, (a, b) -> b.count - a.count);
        if (fs.size() > 10) fs = new ArrayList<>(fs.subList(0, 10));

        List<double[]> triples = new ArrayList<>(); // {score, i, j, k, tlIndex}
        for (int i = 0; i < fs.size(); i++)
            for (int j = i + 1; j < fs.size(); j++)
                for (int k = j + 1; k < fs.size(); k++) {
                    double[] t = scoreTriple(fs.get(i), fs.get(j), fs.get(k), i, j, k);
                    if (t != null) triples.add(t);
                }
        Collections.sort(triples, (a, b) -> Double.compare(a[0], b[0]));
        int tries = 0;
        for (double[] t : triples) {
            if (tries++ >= 8) break;
            Finder[] f = {fs.get((int) t[1]), fs.get((int) t[2]), fs.get((int) t[3])};
            Finder tl = f[(int) t[4]];
            Finder a = f[((int) t[4] + 1) % 3], b = f[((int) t[4] + 2) % 3];
            String s = tryTriple(bin, w, h, tl, a, b);
            if (s != null) return s;
        }
        return null;
    }

    private static boolean px(boolean[] bin, int w, int h, int x, int y) {
        return x >= 0 && y >= 0 && x < w && y < h && bin[y * w + x];
    }

    private static List<Finder> findFinders(boolean[] bin, int w, int h) {
        List<Finder> list = new ArrayList<>();
        int[] starts = new int[w + 2], lens = new int[w + 2];
        boolean[] blk = new boolean[w + 2];
        for (int y = 0; y < h; y++) {
            int n = 0, start = 0;
            boolean cur = bin[y * w];
            for (int x = 1; x <= w; x++) {
                boolean b = x < w ? bin[y * w + x] : !cur;
                if (b != cur) {
                    starts[n] = start; lens[n] = x - start; blk[n] = cur; n++;
                    start = x; cur = b;
                }
            }
            for (int i = 0; i + 4 < n; i++) {
                if (!blk[i]) continue;
                int a = lens[i], b = lens[i + 1], c = lens[i + 2], d = lens[i + 3], e = lens[i + 4];
                int total = a + b + c + d + e;
                if (total < 7) continue;
                double m = total / 7.0, tol = m * 0.6;
                if (Math.abs(a - m) < tol && Math.abs(b - m) < tol && Math.abs(c - 3 * m) < 3 * tol
                        && Math.abs(d - m) < tol && Math.abs(e - m) < tol) {
                    double cx = starts[i + 2] + c / 2.0;
                    double[] v = crossCheckVertical(bin, w, h, (int) cx, y, m);
                    if (v == null) continue;
                    addFinder(list, cx, v[0], (m + v[1]) / 2);
                }
            }
        }
        List<Finder> good = new ArrayList<>();
        for (Finder f : list) if (f.count >= 2) good.add(f);
        return good;
    }

    private static void addFinder(List<Finder> list, double x, double y, double size) {
        for (Finder f : list) {
            if (Math.abs(f.x - x) <= size && Math.abs(f.y - y) <= size && Math.abs(f.size - size) <= f.size * 0.5) {
                f.x = (f.x * f.count + x) / (f.count + 1);
                f.y = (f.y * f.count + y) / (f.count + 1);
                f.size = (f.size * f.count + size) / (f.count + 1);
                f.count++;
                return;
            }
        }
        list.add(new Finder(x, y, size));
    }

    /** Returns {centerY, moduleSize} or null. */
    private static double[] crossCheckVertical(boolean[] bin, int w, int h, int x, int y0, double m) {
        int yu = y0;
        while (yu >= 0 && px(bin, w, h, x, yu)) yu--;
        yu++;
        int yd = y0;
        while (yd < h && px(bin, w, h, x, yd)) yd++;
        int center = yd - yu;
        if (yu == 0 || yd >= h) return null;
        int y = yu - 1, wa = 0;
        while (y >= 0 && !px(bin, w, h, x, y)) { wa++; y--; }
        if (y < 0) return null;
        int ba = 0;
        while (y >= 0 && px(bin, w, h, x, y)) { ba++; y--; }
        y = yd; int wb = 0;
        while (y < h && !px(bin, w, h, x, y)) { wb++; y++; }
        if (y >= h) return null;
        int bb = 0;
        while (y < h && px(bin, w, h, x, y)) { bb++; y++; }
        int total = center + wa + ba + wb + bb;
        double vm = total / 7.0, tol = vm * 0.6;
        if (Math.abs(wa - vm) < tol && Math.abs(wb - vm) < tol && Math.abs(ba - vm) < tol && Math.abs(bb - vm) < tol
                && Math.abs(center - 3 * vm) < 3 * tol && Math.abs(vm - m) < m * 0.6) {
            return new double[]{yu + center / 2.0, vm};
        }
        return null;
    }

    private static double dist(Finder a, Finder b) { return Math.hypot(a.x - b.x, a.y - b.y); }

    /** Looks for a right-angle triple. Returns {score, i, j, k, indexOfTopLeft (0..2)} or null. */
    private static double[] scoreTriple(Finder a, Finder b, Finder c, int i, int j, int k) {
        Finder[] f = {a, b, c};
        double[] d = {dist(b, c), dist(a, c), dist(a, b)}; // d[n] is opposite f[n]
        int tl = 0;
        for (int n = 1; n < 3; n++) if (d[n] > d[tl]) tl = n; // longest side is opposite the top-left corner
        double hyp = d[tl], l1 = d[(tl + 1) % 3], l2 = d[(tl + 2) % 3];
        if (Math.min(l1, l2) < 10) return null;
        double ratio = Math.max(l1, l2) / Math.min(l1, l2);
        if (ratio > 1.6) return null;
        double dev = Math.abs(hyp - Math.sqrt(l1 * l1 + l2 * l2)) / hyp;
        if (dev > 0.2) return null;
        double smin = Math.min(a.size, Math.min(b.size, c.size)), smax = Math.max(a.size, Math.max(b.size, c.size));
        if (smax / smin > 1.7) return null;
        double score = (ratio - 1) + dev * 2 + (smax / smin - 1);
        return new double[]{score, i, j, k, tl};
    }

    // --------------------------------------------------------------- sampling

    private static String tryTriple(boolean[] bin, int w, int h, Finder tl, Finder a, Finder b) {
        double cross = (a.x - tl.x) * (b.y - tl.y) - (a.y - tl.y) * (b.x - tl.x);
        Finder tr = cross > 0 ? a : b, bl = cross > 0 ? b : a;
        double m = (tl.size + tr.size + bl.size) / 3.0;
        double dimEst = ((dist(tl, tr) + dist(tl, bl)) / 2.0) / m + 7;
        int ver = (int) Math.round((dimEst - 17) / 4.0);
        // Size estimates from finder patterns can be off by several versions under tilt, so try nearby ones.
        // A wrong version fails fast on the format-information check.
        for (int delta = 0; delta <= 6; delta++) for (int sign = 1; sign >= -1; sign -= 2) {
            if (delta == 0 && sign == -1) continue;
            int v = ver + sign * delta;
            if (v < 1 || v > 40) continue;
            boolean[] aligned = new boolean[1];
            boolean[][] mat = sample(bin, w, h, tl, tr, bl, v, 0, 0, aligned);
            if (mat == null) continue;
            String s = decodeMatrix(mat, v);
            if (s != null) return s;
            if (!aligned[0] && readFormat(mat, 17 + 4 * v) != null) {
                // No alignment pattern to anchor the fourth corner (version 1, or none found):
                // try nearby positions for it, which copes with tilted codes.
                for (int r = 1; r <= 3; r++)
                    for (int du = -r; du <= r; du++)
                        for (int dv = -r; dv <= r; dv++) {
                            if (Math.max(Math.abs(du), Math.abs(dv)) != r) continue;
                            if (System.nanoTime() > deadline) return null;
                            boolean[][] m2 = sample(bin, w, h, tl, tr, bl, v, du * 0.5, dv * 0.5, aligned);
                            if (m2 == null) continue;
                            String s2 = decodeMatrix(m2, v);
                            if (s2 != null) return s2;
                        }
            }
        }
        return null;
    }

    private static boolean[][] sample(boolean[] bin, int w, int h, Finder tl, Finder tr, Finder bl, int ver,
                                      double offU, double offV, boolean[] aligned) {
        int n = 17 + 4 * ver;
        double ux = (tr.x - tl.x) / (n - 7.0), uy = (tr.y - tl.y) / (n - 7.0); // one module along columns
        double vx = (bl.x - tl.x) / (n - 7.0), vy = (bl.y - tl.y) / (n - 7.0); // one module along rows
        double q = n - 6.5 - 3.5;
        double alx = tl.x + q * ux + q * vx, aly = tl.y + q * uy + q * vy;
        if (ver >= 2) {
            double mpx = Math.hypot(ux, uy);
            double bestScore = -1, bx = alx, by = aly, sumX = 0, sumY = 0;
            int plateau = 0;
            double step = Math.max(1.0, mpx / 4);
            for (double oy = -3 * mpx; oy <= 3 * mpx; oy += step)
                for (double ox = -3 * mpx; ox <= 3 * mpx; ox += step) {
                    int sc = 0;
                    for (int dy = -2; dy <= 2; dy++)
                        for (int dx = -2; dx <= 2; dx++) {
                            double sx = alx + ox + dx * ux + dy * vx, sy = aly + oy + dx * uy + dy * vy;
                            boolean dark = px(bin, w, h, (int) Math.round(sx), (int) Math.round(sy));
                            boolean expect = Math.max(Math.abs(dx), Math.abs(dy)) != 1;
                            if (dark == expect) sc++;
                        }
                    if (sc > bestScore) { bestScore = sc; sumX = alx + ox; sumY = aly + oy; plateau = 1; }
                    else if (sc == bestScore) { sumX += alx + ox; sumY += aly + oy; plateau++; }
                }
            // take the middle of all equally good positions, not the first one found
            if (bestScore >= 21) { alx = sumX / plateau; aly = sumY / plateau; aligned[0] = true; }
        }
        alx += offU * ux + offV * vx;
        aly += offU * uy + offV * vy;
        double[] hm = homography(
                new double[]{3.5, 3.5, n - 3.5, 3.5, n - 6.5, n - 6.5, 3.5, n - 3.5},
                new double[]{tl.x, tl.y, tr.x, tr.y, alx, aly, bl.x, bl.y});
        if (hm == null) return null;
        boolean[][] mat = new boolean[n][n];
        double[] off = {0, 0, -0.25, 0, 0.25, 0, 0, -0.25, 0, 0.25};
        for (int r = 0; r < n; r++)
            for (int c = 0; c < n; c++) {
                int dark = 0;
                for (int s = 0; s < 5; s++) {
                    double u = c + 0.5 + off[2 * s], v = r + 0.5 + off[2 * s + 1];
                    double den = hm[6] * u + hm[7] * v + 1;
                    double x = (hm[0] * u + hm[1] * v + hm[2]) / den, y = (hm[3] * u + hm[4] * v + hm[5]) / den;
                    int ix = (int) Math.round(x), iy = (int) Math.round(y);
                    if (ix < 0 || iy < 0 || ix >= w || iy >= h) return null;
                    if (bin[iy * w + ix]) dark++;
                }
                mat[r][c] = dark >= 3;
            }
        return mat;
    }

    /** Solves the projective map (u,v) -> (x,y) from 4 point pairs. Returns {a,b,c,d,e,f,g,h}. */
    private static double[] homography(double[] src, double[] dst) {
        double[][] m = new double[8][9];
        for (int i = 0; i < 4; i++) {
            double u = src[2 * i], v = src[2 * i + 1], x = dst[2 * i], y = dst[2 * i + 1];
            m[2 * i] = new double[]{u, v, 1, 0, 0, 0, -u * x, -v * x, x};
            m[2 * i + 1] = new double[]{0, 0, 0, u, v, 1, -u * y, -v * y, y};
        }
        for (int col = 0; col < 8; col++) {
            int piv = col;
            for (int r = col + 1; r < 8; r++) if (Math.abs(m[r][col]) > Math.abs(m[piv][col])) piv = r;
            if (Math.abs(m[piv][col]) < 1e-12) return null;
            double[] t = m[col]; m[col] = m[piv]; m[piv] = t;
            for (int r = 0; r < 8; r++) {
                if (r == col) continue;
                double f = m[r][col] / m[col][col];
                for (int c = col; c < 9; c++) m[r][c] -= f * m[col][c];
            }
        }
        double[] out = new double[8];
        for (int i = 0; i < 8; i++) out[i] = m[i][8] / m[i][i];
        return out;
    }

    // ----------------------------------------------------------------- decode

    private static final int[] LEVEL_INDEX = {1, 0, 3, 2}; // format bits (00=M, 01=L, 10=H, 11=Q) -> table row (L,M,Q,H)

    private static int bchFormat(int data) {
        int v = data << 10;
        for (int i = 14; i >= 10; i--) if (((v >> i) & 1) != 0) v ^= 0x537 << (i - 10);
        return v & 0x3FF;
    }

    private static int[] readFormat(boolean[][] m, int n) {
        int f1 = 0;
        for (int i = 0; i <= 5; i++) f1 = (f1 << 1) | (m[8][i] ? 1 : 0);
        f1 = (f1 << 1) | (m[8][7] ? 1 : 0);
        f1 = (f1 << 1) | (m[8][8] ? 1 : 0);
        f1 = (f1 << 1) | (m[7][8] ? 1 : 0);
        for (int j = 5; j >= 0; j--) f1 = (f1 << 1) | (m[j][8] ? 1 : 0);
        int f2 = 0;
        for (int j = n - 1; j >= n - 7; j--) f2 = (f2 << 1) | (m[j][8] ? 1 : 0);
        for (int i = n - 8; i <= n - 1; i++) f2 = (f2 << 1) | (m[8][i] ? 1 : 0);
        int best = -1, bestDist = 99;
        for (int data = 0; data < 32; data++) {
            int code = ((data << 10) | bchFormat(data)) ^ 0x5412;
            int d = Math.min(Integer.bitCount(f1 ^ code), Integer.bitCount(f2 ^ code));
            if (d < bestDist) { bestDist = d; best = data; }
        }
        if (bestDist > 3) return null;
        return new int[]{(best >> 3) & 3, best & 7};
    }

    private static int[] alignmentPositions(int ver) {
        if (ver == 1) return new int[0];
        int n = 17 + 4 * ver, count = ver / 7 + 2, last = n - 7;
        int step = ver == 32 ? 26 : ((last - 6) + 2 * (count - 1) - 1) / (2 * (count - 1)) * 2;
        int[] pos = new int[count];
        pos[0] = 6;
        for (int k = 0; k < count - 1; k++) pos[count - 1 - k] = last - step * k;
        return pos;
    }

    private static void fill(boolean[][] fn, int x0, int y0, int wid, int hei) {
        for (int y = y0; y < y0 + hei; y++)
            for (int x = x0; x < x0 + wid; x++)
                if (y >= 0 && x >= 0 && y < fn.length && x < fn.length) fn[y][x] = true;
    }

    private static boolean maskBit(int mask, int i, int j) {
        switch (mask) {
            case 0: return (i + j) % 2 == 0;
            case 1: return i % 2 == 0;
            case 2: return j % 3 == 0;
            case 3: return (i + j) % 3 == 0;
            case 4: return (i / 2 + j / 3) % 2 == 0;
            case 5: return (i * j) % 2 + (i * j) % 3 == 0;
            case 6: return ((i * j) % 2 + (i * j) % 3) % 2 == 0;
            default: return ((i + j) % 2 + (i * j) % 3) % 2 == 0;
        }
    }

    private static String decodeMatrix(boolean[][] m, int ver) {
        int n = 17 + 4 * ver;
        int[] fi = readFormat(m, n);
        if (fi == null) return null;
        int level = LEVEL_INDEX[fi[0]], mask = fi[1];

        boolean[][] fn = new boolean[n][n];
        fill(fn, 0, 0, 9, 9);
        fill(fn, n - 8, 0, 8, 9);
        fill(fn, 0, n - 8, 9, 8);
        for (int i = 0; i < n; i++) { fn[6][i] = true; fn[i][6] = true; }
        int[] pos = alignmentPositions(ver);
        for (int a = 0; a < pos.length; a++)
            for (int b = 0; b < pos.length; b++) {
                boolean corner = (a == 0 && b == 0) || (a == 0 && b == pos.length - 1) || (a == pos.length - 1 && b == 0);
                if (!corner) fill(fn, pos[b] - 2, pos[a] - 2, 5, 5);
            }
        if (ver >= 7) { fill(fn, n - 11, 0, 3, 6); fill(fn, 0, n - 11, 6, 3); }

        byte[] raw = new byte[(n * n) / 8 + 1];
        int bitCount = 0;
        boolean up = true;
        for (int j = n - 1; j > 0; j -= 2) {
            if (j == 6) j--;
            for (int c = 0; c < n; c++) {
                int i = up ? n - 1 - c : c;
                for (int k = 0; k < 2; k++) {
                    int x = j - k;
                    if (fn[i][x]) continue;
                    boolean bit = m[i][x] ^ maskBit(mask, i, x);
                    if (bit) raw[bitCount >> 3] |= (byte) (0x80 >> (bitCount & 7));
                    bitCount++;
                }
            }
            up = !up;
        }
        int[] groups = RS_TABLE[(ver - 1) * 4 + level];
        int blocks = 0, totalCw = 0;
        for (int g = 0; g < groups.length; g += 3) { blocks += groups[g]; totalCw += groups[g] * groups[g + 1]; }
        if (bitCount / 8 < totalCw) return null;
        int[] dataLen = new int[blocks], totLen = new int[blocks];
        int bi = 0;
        for (int g = 0; g < groups.length; g += 3)
            for (int c = 0; c < groups[g]; c++) { totLen[bi] = groups[g + 1]; dataLen[bi] = groups[g + 2]; bi++; }
        int[][] cw = new int[blocks][];
        int maxData = 0;
        for (int b = 0; b < blocks; b++) { cw[b] = new int[totLen[b]]; maxData = Math.max(maxData, dataLen[b]); }
        int idx = 0;
        for (int i = 0; i < maxData; i++)
            for (int b = 0; b < blocks; b++) if (i < dataLen[b]) cw[b][i] = raw[idx++] & 0xFF;
        int ecLen = totLen[0] - dataLen[0];
        for (int i = 0; i < ecLen; i++)
            for (int b = 0; b < blocks; b++) cw[b][dataLen[b] + i] = raw[idx++] & 0xFF;

        int dataTotal = 0;
        for (int b = 0; b < blocks; b++) dataTotal += dataLen[b];
        byte[] data = new byte[dataTotal];
        int di = 0;
        for (int b = 0; b < blocks; b++) {
            if (!rsCorrect(cw[b], totLen[b] - dataLen[b])) return null;
            for (int i = 0; i < dataLen[b]; i++) data[di++] = (byte) cw[b][i];
        }
        return parse(data, ver);
    }

    // ------------------------------------------------------------ Reed-Solomon

    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];
    static {
        int x = 1;
        for (int i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x >= 256) x ^= 0x11D; }
        for (int i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
    }
    private static int mul(int a, int b) { return (a == 0 || b == 0) ? 0 : EXP[LOG[a] + LOG[b]]; }
    private static int div(int a, int b) { return a == 0 ? 0 : EXP[LOG[a] + 255 - LOG[b]]; }

    private static int[] syndromes(int[] cw, int ec) {
        int[] s = new int[ec];
        for (int j = 0; j < ec; j++) {
            int a = EXP[j], v = 0;
            for (int k = 0; k < cw.length; k++) v = mul(v, a) ^ cw[k];
            s[j] = v;
        }
        return s;
    }

    private static boolean allZero(int[] a) { for (int v : a) if (v != 0) return false; return true; }

    /** Corrects errors in place. Returns false if the block can't be repaired. */
    private static boolean rsCorrect(int[] cw, int ec) {
        int n = cw.length;
        int[] S = syndromes(cw, ec);
        if (allZero(S)) return true;
        int[] C = new int[ec + 1], B = new int[ec + 1];
        C[0] = 1; B[0] = 1;
        int L = 0, m = 1, b = 1;
        for (int i = 0; i < ec; i++) {
            int d = S[i];
            for (int j = 1; j <= L; j++) d ^= mul(C[j], S[i - j]);
            if (d == 0) { m++; continue; }
            int[] T = C.clone();
            int coef = div(d, b);
            for (int j = 0; j + m <= ec; j++) C[j + m] ^= mul(coef, B[j]);
            if (2 * L <= i) { L = i + 1 - L; B = T; b = d; m = 1; } else m++;
        }
        if (L == 0 || L > ec / 2) return false;
        int[] errPos = new int[L];
        int cnt = 0;
        for (int p = 0; p < n; p++) {
            int xinv = EXP[(255 - p % 255) % 255];
            int val = 0, pw = 1;
            for (int j = 0; j <= L; j++) { val ^= mul(C[j], pw); pw = mul(pw, xinv); }
            if (val == 0) { if (cnt >= L) return false; errPos[cnt++] = p; }
        }
        if (cnt != L) return false;
        int[] omega = new int[ec];
        for (int i = 0; i < ec; i++) {
            int v = 0;
            for (int j = 0; j <= i && j <= L; j++) v ^= mul(C[j], S[i - j]);
            omega[i] = v;
        }
        for (int p : errPos) {
            int x = EXP[p % 255], xinv = EXP[(255 - p % 255) % 255];
            int om = 0, pw = 1;
            for (int j = 0; j < ec; j++) { om ^= mul(omega[j], pw); pw = mul(pw, xinv); }
            int lp = 0;
            pw = 1;
            for (int j = 1; j <= L; j += 2) { lp ^= mul(C[j], pw); pw = mul(pw, mul(xinv, xinv)); }
            if (lp == 0) return false;
            int idx = n - 1 - p;
            if (idx < 0) return false;
            cw[idx] ^= mul(x, div(om, lp));
        }
        return allZero(syndromes(cw, ec));
    }

    // ------------------------------------------------------------------ parse

    private static final String ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

    private static final class Bits {
        final byte[] d; int pos = 0;
        Bits(byte[] d) { this.d = d; }
        int left() { return d.length * 8 - pos; }
        int read(int n) {
            int v = 0;
            for (int i = 0; i < n; i++, pos++) v = (v << 1) | ((d[pos >> 3] >> (7 - (pos & 7))) & 1);
            return v;
        }
    }

    private static String parse(byte[] data, int ver) {
        Bits r = new Bits(data);
        StringBuilder sb = new StringBuilder();
        int idx = ver <= 9 ? 0 : ver <= 26 ? 1 : 2;
        while (r.left() >= 4) {
            int mode = r.read(4);
            if (mode == 0) break;
            if (mode == 7) { // ECI: skip the designator
                if (r.left() < 8) return null;
                int first = r.read(8);
                int extra = (first & 0x80) == 0 ? 0 : (first & 0x40) == 0 ? 1 : 2;
                if (r.left() < extra * 8) return null;
                r.read(extra * 8);
                continue;
            }
            if (mode == 1) {
                int cnt = r.read(new int[]{10, 12, 14}[idx]);
                while (cnt >= 3) { if (r.left() < 10) return null; int v = r.read(10); if (v >= 1000) return null; sb.append(String.format("%03d", v)); cnt -= 3; }
                if (cnt == 2) { if (r.left() < 7) return null; int v = r.read(7); if (v >= 100) return null; sb.append(String.format("%02d", v)); }
                if (cnt == 1) { if (r.left() < 4) return null; int v = r.read(4); if (v >= 10) return null; sb.append(v); }
            } else if (mode == 2) {
                int cnt = r.read(new int[]{9, 11, 13}[idx]);
                while (cnt >= 2) {
                    if (r.left() < 11) return null;
                    int v = r.read(11);
                    if (v / 45 >= 45) return null;
                    sb.append(ALNUM.charAt(v / 45)).append(ALNUM.charAt(v % 45));
                    cnt -= 2;
                }
                if (cnt == 1) { if (r.left() < 6) return null; int v = r.read(6); if (v >= 45) return null; sb.append(ALNUM.charAt(v)); }
            } else if (mode == 4) {
                int cnt = r.read(new int[]{8, 16, 16}[idx]);
                if (r.left() < cnt * 8) return null;
                byte[] bytes = new byte[cnt];
                for (int i = 0; i < cnt; i++) bytes[i] = (byte) r.read(8);
                try {
                    sb.append(StandardCharsets.UTF_8.newDecoder()
                            .onMalformedInput(CodingErrorAction.REPORT)
                            .onUnmappableCharacter(CodingErrorAction.REPORT)
                            .decode(ByteBuffer.wrap(bytes)));
                } catch (CharacterCodingException e) {
                    sb.append(new String(bytes, StandardCharsets.ISO_8859_1));
                }
            } else {
                return null; // kanji and other modes are not supported
            }
        }
        return sb.toString();
    }

    // Reed-Solomon block layout per version and level (L, M, Q, H): {count, totalCodewords, dataCodewords, ...}
    private static final int[][] RS_TABLE = {
        {1, 26, 19},
        {1, 26, 16},
        {1, 26, 13},
        {1, 26, 9},
        {1, 44, 34},
        {1, 44, 28},
        {1, 44, 22},
        {1, 44, 16},
        {1, 70, 55},
        {1, 70, 44},
        {2, 35, 17},
        {2, 35, 13},
        {1, 100, 80},
        {2, 50, 32},
        {2, 50, 24},
        {4, 25, 9},
        {1, 134, 108},
        {2, 67, 43},
        {2, 33, 15, 2, 34, 16},
        {2, 33, 11, 2, 34, 12},
        {2, 86, 68},
        {4, 43, 27},
        {4, 43, 19},
        {4, 43, 15},
        {2, 98, 78},
        {4, 49, 31},
        {2, 32, 14, 4, 33, 15},
        {4, 39, 13, 1, 40, 14},
        {2, 121, 97},
        {2, 60, 38, 2, 61, 39},
        {4, 40, 18, 2, 41, 19},
        {4, 40, 14, 2, 41, 15},
        {2, 146, 116},
        {3, 58, 36, 2, 59, 37},
        {4, 36, 16, 4, 37, 17},
        {4, 36, 12, 4, 37, 13},
        {2, 86, 68, 2, 87, 69},
        {4, 69, 43, 1, 70, 44},
        {6, 43, 19, 2, 44, 20},
        {6, 43, 15, 2, 44, 16},
        {4, 101, 81},
        {1, 80, 50, 4, 81, 51},
        {4, 50, 22, 4, 51, 23},
        {3, 36, 12, 8, 37, 13},
        {2, 116, 92, 2, 117, 93},
        {6, 58, 36, 2, 59, 37},
        {4, 46, 20, 6, 47, 21},
        {7, 42, 14, 4, 43, 15},
        {4, 133, 107},
        {8, 59, 37, 1, 60, 38},
        {8, 44, 20, 4, 45, 21},
        {12, 33, 11, 4, 34, 12},
        {3, 145, 115, 1, 146, 116},
        {4, 64, 40, 5, 65, 41},
        {11, 36, 16, 5, 37, 17},
        {11, 36, 12, 5, 37, 13},
        {5, 109, 87, 1, 110, 88},
        {5, 65, 41, 5, 66, 42},
        {5, 54, 24, 7, 55, 25},
        {11, 36, 12, 7, 37, 13},
        {5, 122, 98, 1, 123, 99},
        {7, 73, 45, 3, 74, 46},
        {15, 43, 19, 2, 44, 20},
        {3, 45, 15, 13, 46, 16},
        {1, 135, 107, 5, 136, 108},
        {10, 74, 46, 1, 75, 47},
        {1, 50, 22, 15, 51, 23},
        {2, 42, 14, 17, 43, 15},
        {5, 150, 120, 1, 151, 121},
        {9, 69, 43, 4, 70, 44},
        {17, 50, 22, 1, 51, 23},
        {2, 42, 14, 19, 43, 15},
        {3, 141, 113, 4, 142, 114},
        {3, 70, 44, 11, 71, 45},
        {17, 47, 21, 4, 48, 22},
        {9, 39, 13, 16, 40, 14},
        {3, 135, 107, 5, 136, 108},
        {3, 67, 41, 13, 68, 42},
        {15, 54, 24, 5, 55, 25},
        {15, 43, 15, 10, 44, 16},
        {4, 144, 116, 4, 145, 117},
        {17, 68, 42},
        {17, 50, 22, 6, 51, 23},
        {19, 46, 16, 6, 47, 17},
        {2, 139, 111, 7, 140, 112},
        {17, 74, 46},
        {7, 54, 24, 16, 55, 25},
        {34, 37, 13},
        {4, 151, 121, 5, 152, 122},
        {4, 75, 47, 14, 76, 48},
        {11, 54, 24, 14, 55, 25},
        {16, 45, 15, 14, 46, 16},
        {6, 147, 117, 4, 148, 118},
        {6, 73, 45, 14, 74, 46},
        {11, 54, 24, 16, 55, 25},
        {30, 46, 16, 2, 47, 17},
        {8, 132, 106, 4, 133, 107},
        {8, 75, 47, 13, 76, 48},
        {7, 54, 24, 22, 55, 25},
        {22, 45, 15, 13, 46, 16},
        {10, 142, 114, 2, 143, 115},
        {19, 74, 46, 4, 75, 47},
        {28, 50, 22, 6, 51, 23},
        {33, 46, 16, 4, 47, 17},
        {8, 152, 122, 4, 153, 123},
        {22, 73, 45, 3, 74, 46},
        {8, 53, 23, 26, 54, 24},
        {12, 45, 15, 28, 46, 16},
        {3, 147, 117, 10, 148, 118},
        {3, 73, 45, 23, 74, 46},
        {4, 54, 24, 31, 55, 25},
        {11, 45, 15, 31, 46, 16},
        {7, 146, 116, 7, 147, 117},
        {21, 73, 45, 7, 74, 46},
        {1, 53, 23, 37, 54, 24},
        {19, 45, 15, 26, 46, 16},
        {5, 145, 115, 10, 146, 116},
        {19, 75, 47, 10, 76, 48},
        {15, 54, 24, 25, 55, 25},
        {23, 45, 15, 25, 46, 16},
        {13, 145, 115, 3, 146, 116},
        {2, 74, 46, 29, 75, 47},
        {42, 54, 24, 1, 55, 25},
        {23, 45, 15, 28, 46, 16},
        {17, 145, 115},
        {10, 74, 46, 23, 75, 47},
        {10, 54, 24, 35, 55, 25},
        {19, 45, 15, 35, 46, 16},
        {17, 145, 115, 1, 146, 116},
        {14, 74, 46, 21, 75, 47},
        {29, 54, 24, 19, 55, 25},
        {11, 45, 15, 46, 46, 16},
        {13, 145, 115, 6, 146, 116},
        {14, 74, 46, 23, 75, 47},
        {44, 54, 24, 7, 55, 25},
        {59, 46, 16, 1, 47, 17},
        {12, 151, 121, 7, 152, 122},
        {12, 75, 47, 26, 76, 48},
        {39, 54, 24, 14, 55, 25},
        {22, 45, 15, 41, 46, 16},
        {6, 151, 121, 14, 152, 122},
        {6, 75, 47, 34, 76, 48},
        {46, 54, 24, 10, 55, 25},
        {2, 45, 15, 64, 46, 16},
        {17, 152, 122, 4, 153, 123},
        {29, 74, 46, 14, 75, 47},
        {49, 54, 24, 10, 55, 25},
        {24, 45, 15, 46, 46, 16},
        {4, 152, 122, 18, 153, 123},
        {13, 74, 46, 32, 75, 47},
        {48, 54, 24, 14, 55, 25},
        {42, 45, 15, 32, 46, 16},
        {20, 147, 117, 4, 148, 118},
        {40, 75, 47, 7, 76, 48},
        {43, 54, 24, 22, 55, 25},
        {10, 45, 15, 67, 46, 16},
        {19, 148, 118, 6, 149, 119},
        {18, 75, 47, 31, 76, 48},
        {34, 54, 24, 34, 55, 25},
        {20, 45, 15, 61, 46, 16},
    };
}
