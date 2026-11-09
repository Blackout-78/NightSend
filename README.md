# NightSend

Private direct file transfer from a Windows PC to an Android phone.
Both on the same Wi-Fi: the PC finds the phone by itself, you only type the code. No internet, no cloud, no relay.

- `app/` - Android receiver app (APK built automatically by GitHub Actions, see Releases)
- PC sender: `NightSend.exe` (see Releases), or `pc/NightSend.bat` + `pc/NightSend.ps1` (Windows 10/11, nothing to install)

## Pairing code (v0.3)
The phone app shows a 6-digit pairing code. Type it into the **Code** box in the PC app once; the PC remembers it.
Without the right code the phone answers nothing: no file list, no saving. 5 wrong codes in a row make a new code.
Tap "make a new code" on the phone any time to lock out every PC until the new code is typed in.

## Background
- Phone: NightSend receives in the background (foreground service, notification). Pick the save folder with **Choose folder**.
- PC: minimize or press X while sending and it keeps going from the system tray. Right-click the tray icon > Exit to quit.
