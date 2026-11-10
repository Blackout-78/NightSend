# NightSend

Private direct file transfer from a Windows PC to an Android phone.
Both on the same Wi-Fi: the PC finds the phone by itself, you only type the code. No internet, no cloud, no relay.

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

## Pairing and encryption (v2)
The phone app shows a 6-digit pairing code. Type it into the **Code** box in the PC app **once**.
- The code is never sent. PC and phone prove they know it, and swap fresh one-time keys (ECDH P-256) for every connection.
- Everything after that (commands, file names, file data) is encrypted and signed (AES-256 + HMAC-SHA256). Anyone watching the Wi-Fi sees nothing readable and cannot change or replay anything.
- After the first pairing the PC keeps a secret key (locked to your Windows user) and the phone makes a new code. From then on the PC reconnects by itself, with no code.
- Pairing another PC needs the new code shown on the phone.
- Without the right code or key the phone answers nothing. 5 wrong codes in a row make a new code.
- Tap "forget all paired PCs and make a new code" on the phone to lock out every PC.
- The one weak spot is the very first pairing: pair at home, not while a stranger is on the same Wi-Fi.
- The phone app and the PC app must both be v2. The build publishes them together.

## Background
- Phone: NightSend receives in the background (foreground service, notification). Pick the save folder with **Choose folder**.
- PC: minimize or press X while sending and it keeps going from the system tray. Right-click the tray icon > Exit to quit.
