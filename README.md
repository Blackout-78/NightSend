# NightSend

Private direct file transfer between a Windows PC and an Android phone, both ways.
The PC finds the phone by itself; you pair once by scanning a QR code. No internet, no cloud, no relay.

- `app/` - Android receiver app (APK built automatically by GitHub Actions, see Releases)
- PC sender (Windows): `NightSend.exe` (see Releases), or `pc/NightSend.bat` + `pc/NightSend.ps1` (Windows 10/11, nothing to install)
- PC sender (Linux): `NightSend-linux-x86_64.tar.gz` (see Releases), or `pc/linux/nightsend.py` (see below)

## Screens

These are design previews. The finished app follows this look.

<table>
  <tr>
    <td><img src="docs/screenshots/01-phone-code.png" width="180" alt="Phone code"></td>
    <td><img src="docs/screenshots/02-receiving.png" width="180" alt="Receiving"></td>
    <td><img src="docs/screenshots/03-pc-sender.png" width="360" alt="Pc sender"></td>
  </tr>
</table>

## Linux
Same app, same look, same pairing as the Windows one. It pairs with the same NightSend phone app (v3).
- Download `NightSend-linux-x86_64.tar.gz` from Releases, extract it, run `./NightSend`. One file, nothing to install. Built on Ubuntu 24.04, so it needs glibc 2.39 or newer (Linux Mint 22 and later).
- Or run the source: `sudo apt install python3-tk python3-cryptography`, then `python3 pc/linux/nightsend.py`.
- The pairing key is kept in `~/.config/nightsend/pairing-key.dat`, readable only by your Linux user (mode 600). Tick **Strict** to keep nothing.
- It keeps the computer awake while sending (`systemd-inhibit`). Closing the window while a transfer runs minimizes it instead of stopping; use **Stop** to cancel.
- Different from Windows: there is no tray icon. Finished-transfer notices use `notify-send` when the window is minimized.
- Updates: the **Open GitHub Releases** button opens the Releases page in your browser. The app itself stays offline.
- Tested on every build: the QR picture is checked against the Windows reference, the handshake runs against the phone's real `Secure.java`, and send / receive / reconnect / archive run against a fake phone (`pc/linux/selftest.py`).

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

## Send from the phone to the PC
1. On the phone, under **SEND TO PC**, tap **Choose folder to send** and pick a folder (not a whole storage).
2. On the PC, pick **Save on this PC** (section 3) and press **RECEIVE**.

- The PC can only take files from the one folder the phone chose, and only while it is paired. Tap **stop sharing** on the phone to close it.
- Same encryption, same pairing, same Wi-Fi as sending. Folders keep their structure.
- Files already on the PC with the same size are skipped, so pressing RECEIVE again continues where it stopped. A file is only kept once its size matches the phone's.
- Both apps need this version. An older phone app answers "too old"; install the newest NightSend.apk.

## Archive after sending
Tick **After a clean send, archive the folder to** in the PC app and pick an archive folder. When every file has been sent and size-checked by the phone, the sent folder is moved into the archive folder. It is a plain move on the same drive: nothing is copied, compressed or deleted. If any file failed, or the archive folder is on another drive, nothing is moved.

## Background
- Phone: NightSend receives in the background (foreground service, notification). Pick the save folder with **Choose folder**.
- PC: minimize or press X while sending and it keeps going from the system tray. Right-click the tray icon > Exit to quit.
