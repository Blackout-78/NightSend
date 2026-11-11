# NightSend

Private direct file transfer from a Windows PC to an Android phone.
The PC finds the phone by itself; you pair once by scanning a QR code. No internet, no cloud, no relay.

- `app/` - Android receiver app (APK built automatically by GitHub Actions, see Releases)
- PC sender: `NightSend.exe` (see Releases), or `pc/NightSend.bat` + `pc/NightSend.ps1` (Windows 10/11, nothing to install)

## Screens

These are design previews. The finished app follows this look.

<table>
  <tr>
    <td><img src="docs/screenshots/01-phone-code.png" width="180" alt="Phone code"></td>
    <td><img src="docs/screenshots/02-receiving.png" width="180" alt="Receiving"></td>
    <td><img src="docs/screenshots/03-pc-sender.png" width="360" alt="Pc sender"></td>
  </tr>
</table>

## Pairing and encryption (v3)
Pair once per PC with a QR code:
1. On the PC press **Pair with QR**. A one-time QR code appears (a random 128-bit secret made on the PC).
2. On the phone tap **Scan the PC's QR code** and point the camera at the PC screen. (No camera? Choose **Type the code instead** and type the code shown under the picture.)
3. On the PC press **Find phone**.

- The secret is never sent. PC and phone prove they know it, and swap fresh one-time keys (ECDH P-256) for every connection. It is 128 bits, so it cannot be guessed, even by someone on the same Wi-Fi.
- It works once and only for 2 minutes after the phone scans it. 3 wrong tries close the pairing window. Without a scan the phone does not accept any pairing at all.
- Everything after that (commands, file names, file data) is encrypted and signed (AES-256 + HMAC-SHA256). Anyone watching the Wi-Fi sees nothing readable and cannot change or replay anything.
- After pairing the PC keeps a secret key (locked to your Windows user). From then on the PC reconnects by itself, with no QR code.
- Tap "forget all paired PCs" on the phone to lock out every PC.
- **Strict mode** (tick it on the phone and on the PC): nothing is remembered. Every session needs a fresh QR scan, and a dropped connection means scanning again. Most private; least convenient.
- The phone scans the picture with its camera and throws the frames away. Nothing is saved or sent anywhere.
- Best links: a USB cable (USB tethering) or the phone's own hotspot / Wi-Fi Direct. Your home Wi-Fi works too.
- The phone app and the PC app must both be v3. The build publishes them together.

## Background
- Phone: NightSend receives in the background (foreground service, notification). Pick the save folder with **Choose folder**.
- PC: minimize or press X while sending and it keeps going from the system tray. Right-click the tray icon > Exit to quit.
