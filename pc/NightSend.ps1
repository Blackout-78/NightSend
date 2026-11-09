# NightSend PC (v0.5 - same Wi-Fi + pairing code + background/tray)
# Sends a whole folder from this PC to the NightSend phone app.
# Both devices on the same Wi-Fi: the PC finds the phone by itself, you only type the code. No internet, no cloud, no extra downloads.
# Skips files already on the phone, re-sends unfinished ones, phone checks every file's size.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Keeps Windows from sleeping while a transfer runs.
try {
    Add-Type -Namespace NS -Name Power -MemberDefinition '[System.Runtime.InteropServices.DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint f);'
} catch {}
function Keep-Awake([bool]$on) {
    try { if ($on) { [void][NS.Power]::SetThreadExecutionState([uint32]2147483649) } else { [void][NS.Power]::SetThreadExecutionState([uint32]2147483648) } } catch {}
}
$script:Quit = $false

$Port = 47800
# The phone's pairing code is remembered here after it works once.
$CodeDir = Join-Path $env:APPDATA "NightSend"
$CodeFile = Join-Path $CodeDir "pairing-code.txt"
try { [void](New-Item -ItemType Directory -Force -Path $CodeDir) } catch {}
$SavedCode = ""
try { if (Test-Path -LiteralPath $CodeFile) { $SavedCode = ([IO.File]::ReadAllText($CodeFile)).Trim() } } catch {}
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$script:Tcp = $null; $script:Ns = $null; $script:Rd = $null
$script:PhoneIp = $null; $script:PhoneFree = -1
$script:Queue = New-Object System.Collections.ArrayList
$script:Failed = New-Object System.Collections.ArrayList
$script:Index = 0; $script:Fs = $null; $script:Left = [int64]0
$script:TotalBytes = [int64]0; $script:DoneBytes = [int64]0; $script:CurBytes = [int64]0
$script:StartTime = $null; $script:Running = $false
$script:Buf = New-Object byte[] (1MB)

# ---------- colours ----------
$cBg     = [Drawing.Color]::FromArgb(10,10,12)
$cPanel  = [Drawing.Color]::FromArgb(28,28,32)
$cText   = [Drawing.Color]::FromArgb(220,220,225)
$cDim    = [Drawing.Color]::FromArgb(130,130,140)
$cAccent = [Drawing.Color]::FromArgb(150,30,40)
$cGood   = [Drawing.Color]::FromArgb(90,170,110)
$fUi     = New-Object Drawing.Font("Segoe UI", 10)
$fBold   = New-Object Drawing.Font("Segoe UI Semibold", 10)

# ---------- helpers ----------
function Log([string]$msg) { $txtLog.AppendText((Get-Date -Format "HH:mm:ss") + "  " + $msg + "`r`n") }

function Fmt([double]$b) {
    $u = "B","KB","MB","GB","TB"; $i = 0
    while ($b -ge 1024 -and $i -lt 4) { $b /= 1024; $i++ }
    "{0:N1} {1}" -f $b, $u[$i]
}

function Send-Line([string]$s) {
    $bytes = $Utf8.GetBytes($s + "`n")
    $script:Ns.Write($bytes, 0, $bytes.Length)
    $script:Ns.Flush()
}

function Close-Conn {
    try { if ($script:Ns) { Send-Line "BYE" } } catch {}
    try { if ($script:Tcp) { $script:Tcp.Close() } } catch {}
    $script:Tcp = $null; $script:Ns = $null; $script:Rd = $null
}

function Open-Conn([string]$ip) {
    Close-Conn
    $t = New-Object Net.Sockets.TcpClient
    $t.SendBufferSize = 1MB
    $t.ReceiveTimeout = 180000
    $t.SendTimeout = 180000
    $ar = $t.BeginConnect($ip, $Port, $null, $null)
    if (-not $ar.AsyncWaitHandle.WaitOne(3000)) { $t.Close(); throw "Phone did not answer at $ip" }
    $t.EndConnect($ar)
    $script:Tcp = $t
    $script:Ns = $t.GetStream()
    $script:Rd = New-Object IO.StreamReader($script:Ns, $Utf8)
}

function Say-Hello {
    $code = ($txtCode.Text -replace "\D", "")
    if ($code.Length -ne 6) { throw "Type the 6-digit pairing code shown on the phone." }
    Send-Line ("PAIR " + $code)
    $ok = $script:Rd.ReadLine()
    if ($ok -ne "OK") { throw "Wrong pairing code. Check the code on the phone screen and type it again." }
    try { [IO.File]::WriteAllText($CodeFile, $code) } catch {}
    Send-Line "HELLO"
    $r = $script:Rd.ReadLine()
    if (-not $r -or -not $r.StartsWith("NIGHTSEND|")) { throw "Not a NightSend phone." }
    $p = $r.Split("|")
    $script:PhoneFree = [int64]$p[2]
    return @{ Model = $p[1]; Free = [int64]$p[2]; Path = $p[3]; StorageOk = ($p[4] -eq "1") }
}

# Look for the phone: USB-tethering gateways first, then the PC hotspot range, then every local /24.
function Find-PhoneIp {
    $cands = New-Object System.Collections.ArrayList
    try {
        Get-NetIPConfiguration -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($g in $_.IPv4DefaultGateway) { if ($g.NextHop -and $g.NextHop -ne "0.0.0.0") { [void]$cands.Add($g.NextHop) } }
        }
    } catch {}
    $locals = @()
    try {
        $locals = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" } |
            Select-Object -ExpandProperty IPAddress
    } catch {}
    $prefixes = @($locals | ForEach-Object { ($_ -split "\.")[0..2] -join "." } | Sort-Object -Unique)
    $prefixes = @($prefixes | Sort-Object { if ($_ -eq "192.168.137") { 0 } else { 1 } })
    foreach ($pre in $prefixes) {
        for ($i = 1; $i -le 254; $i++) {
            $ip = "$pre.$i"
            if ($locals -notcontains $ip -and $cands -notcontains $ip) { [void]$cands.Add($ip) }
        }
    }
    Log ("Searching {0} addresses..." -f $cands.Count)
    $tries = @()
    foreach ($ip in $cands) {
        $c = New-Object Net.Sockets.TcpClient
        $tries += @{ Ip = $ip; Client = $c; Ar = $c.BeginConnect($ip, $Port, $null, $null) }
    }
    $deadline = (Get-Date).AddMilliseconds(2500)
    $found = $null
    while (-not $found -and (Get-Date) -lt $deadline) {
        foreach ($t in $tries) {
            if ($t.Ar.IsCompleted) {
                try { $t.Client.EndConnect($t.Ar); if ($t.Client.Connected) { $found = $t.Ip; break } } catch {}
            }
        }
        Start-Sleep -Milliseconds 100
        [Windows.Forms.Application]::DoEvents()
    }
    foreach ($t in $tries) { try { $t.Client.Close() } catch {} }
    return $found
}

function Set-Busy([bool]$busy) {
    $btnSend.Enabled = -not $busy; $btnFind.Enabled = -not $busy
    $btnBrowse.Enabled = -not $busy; $btnStop.Enabled = $busy
}

# ---------- connect ----------
function Connect-Phone {
    $lblPhone.Text = "Looking for the phone..."; $lblPhone.ForeColor = $cDim
    [Windows.Forms.Application]::DoEvents()
    $ip = $txtIp.Text.Trim()
    if (-not $ip) { $ip = Find-PhoneIp }
    if (-not $ip) {
        $lblPhone.Text = "Phone not found. Open NightSend on the phone and make sure the phone and this PC are on the same Wi-Fi."
        $lblPhone.ForeColor = $cAccent
        return $false
    }
    try {
        Open-Conn $ip
        $h = Say-Hello
        $script:PhoneIp = $ip
        $txtIp.Text = $ip
        $lblPhone.Text = "Connected: {0}  -  {1} free  -  saving to {2}" -f $h.Model, (Fmt $h.Free), $h.Path
        $lblPhone.ForeColor = $cGood
        Log "Connected to $($h.Model) at $ip."
        if (-not $h.StorageOk) {
            $lblPhone.Text = "Connected, but the phone app needs storage permission. Tap 'Allow NightSend to save files' on the phone."
            $lblPhone.ForeColor = $cAccent
            Close-Conn
            return $false
        }
        return $true
    } catch {
        $lblPhone.Text = "Could not connect: " + $_.Exception.Message
        $lblPhone.ForeColor = $cAccent
        Close-Conn
        return $false
    }
}

# ---------- send ----------
function Start-Send {
    $src = $txtSrc.Text.Trim().TrimEnd("\")
    if (-not (Test-Path -LiteralPath $src -PathType Container)) { Log "Source folder not found."; return }
    Set-Busy $true
    if (-not (Connect-Phone)) { Set-Busy $false; return }

    $lblStatus.Text = "Reading files on the PC..."; [Windows.Forms.Application]::DoEvents()
    $local = @(Get-ChildItem -LiteralPath $src -Recurse -File -Force -ErrorAction SilentlyContinue)

    $lblStatus.Text = "Reading what is already on the phone..."; [Windows.Forms.Application]::DoEvents()
    $have = @{}
    try {
        Send-Line "LIST"
        while ($true) {
            $l = $script:Rd.ReadLine()
            if ($l -eq $null -or $l -eq "END") { break }
            $i = $l.IndexOf("|")
            if ($i -gt 0) { $have[$l.Substring($i + 1)] = [int64]$l.Substring(0, $i) }
        }
    } catch { Log ("Could not read phone files: " + $_.Exception.Message); Close-Conn; Set-Busy $false; return }

    $script:Queue.Clear(); $script:Failed.Clear()
    $script:TotalBytes = 0; $skipped = 0
    foreach ($f in $local) {
        $rel = $f.FullName.Substring($src.Length).TrimStart("\").Replace("\", "/")
        if ($have.ContainsKey($rel) -and $have[$rel] -eq $f.Length) { $skipped++; continue }
        [void]$script:Queue.Add(@{ Local = $f.FullName; Rel = $rel; Size = [int64]$f.Length })
        $script:TotalBytes += $f.Length
    }
    Log ("{0} files on PC. {1} already on phone (skipped). {2} to send ({3})." -f $local.Count, $skipped, $script:Queue.Count, (Fmt $script:TotalBytes))

    if ($script:Queue.Count -eq 0) {
        $lblStatus.Text = "Everything is already on the phone."; $bar.Value = 1000
        Close-Conn; Set-Busy $false; return
    }
    if ($script:PhoneFree -ge 0 -and $script:PhoneFree -lt $script:TotalBytes) {
        $ans = [Windows.Forms.MessageBox]::Show(
            ("Not enough space on the phone.`r`nNeeded: {0}`r`nFree: {1}`r`n`r`nSend as much as fits anyway?" -f (Fmt $script:TotalBytes), (Fmt $script:PhoneFree)),
            "NightSend", "YesNo", "Warning")
        if ($ans -ne "Yes") { $lblStatus.Text = "Cancelled - not enough space."; Close-Conn; Set-Busy $false; return }
    }

    $script:Index = 0; $script:DoneBytes = 0; $script:CurBytes = 0
    $script:StartTime = Get-Date; $script:Running = $true
    Keep-Awake $true
    Start-Next
    $timer.Start()
}

function Start-Next {
    while ($script:Index -lt $script:Queue.Count) {
        $item = $script:Queue[$script:Index]
        try {
            $script:Fs = [IO.File]::Open($item.Local, "Open", "Read", "Read")
            $lblFile.Text = $item.Rel
            Send-Line ("PUT {0} {1}" -f $item.Size, $item.Rel)
            $script:Left = $item.Size; $script:CurBytes = 0
            return
        } catch {
            if ($script:Fs) { $script:Fs.Close(); $script:Fs = $null }
            if (-not $script:Tcp -or -not $script:Tcp.Connected) { Abort-Send ("Connection lost: " + $_.Exception.Message); return }
            [void]$script:Failed.Add($item.Rel); Log ("SKIPPED (cannot read on PC): " + $item.Rel)
            $script:DoneBytes += $item.Size; $script:Index++
        }
    }
    Finish-Send
}

function On-Tick {
    if (-not $script:Running -or -not $script:Fs) { return }
    $item = $script:Queue[$script:Index]
    try {
        $sw = [Diagnostics.Stopwatch]::StartNew()
        while ($script:Left -gt 0 -and $sw.ElapsedMilliseconds -lt 300) {
            $want = [int][Math]::Min([int64]$script:Buf.Length, [int64]$script:Left)
            $n = $script:Fs.Read($script:Buf, 0, $want)
            if ($n -le 0) { throw "File got shorter while sending: $($item.Rel)" }
            $script:Ns.Write($script:Buf, 0, $n)
            $script:Left -= $n; $script:CurBytes += $n
        }
        if ($script:Left -eq 0) {
            $script:Fs.Close(); $script:Fs = $null
            $resp = $script:Rd.ReadLine()
            if ($resp -ne "OK") { [void]$script:Failed.Add($item.Rel); Log ("FAILED on phone: {0}  ({1})" -f $item.Rel, $resp) }
            if ($resp -eq $null -or $resp.StartsWith("ERR !")) { Abort-Send "Phone stopped answering."; return }
            $script:DoneBytes += $item.Size; $script:CurBytes = 0; $script:Index++
            Update-Progress
            Start-Next
            return
        }
        Update-Progress
    } catch {
        Abort-Send ("Connection lost: " + $_.Exception.Message)
    }
}

function Update-Progress {
    $done = $script:DoneBytes + $script:CurBytes
    if ($script:TotalBytes -gt 0) { $bar.Value = [int][Math]::Min(1000, ($done * 1000 / $script:TotalBytes)) }
    $secs = ((Get-Date) - $script:StartTime).TotalSeconds
    $speed = 0; if ($secs -gt 1) { $speed = $done / $secs }
    $eta = ""
    if ($speed -gt 0) {
        $left = [TimeSpan]::FromSeconds(($script:TotalBytes - $done) / $speed)
        $eta = "  -  about {0}h {1}m left" -f [int][Math]::Floor($left.TotalHours), $left.Minutes
    }
    $lblStatus.Text = ("File {0} of {1}  -  {2} of {3}  -  {4}/s{5}" -f
        [Math]::Min($script:Index + 1, $script:Queue.Count), $script:Queue.Count,
        (Fmt $done), (Fmt $script:TotalBytes), (Fmt $speed), $eta)
}

function Finish-Send {
    $timer.Stop(); $script:Running = $false; Keep-Awake $false
    Close-Conn
    $bar.Value = 1000; $lblFile.Text = ""
    if ($script:Failed.Count -eq 0) {
        $lblStatus.Text = "Done. All files sent and checked."
        Log "DONE - all files sent and size-checked by the phone."
    } else {
        $lblStatus.Text = "Done with $($script:Failed.Count) failed file(s). Press SEND again to retry them."
        Log "Finished. $($script:Failed.Count) file(s) failed - press SEND again to retry only those."
    }
    Set-Busy $false
    Tray-Note "NightSend" $lblStatus.Text
}

function Abort-Send([string]$why) {
    $timer.Stop(); $script:Running = $false; Keep-Awake $false
    if ($script:Fs) { try { $script:Fs.Close() } catch {}; $script:Fs = $null }
    Close-Conn
    $lblStatus.Text = "Stopped. Press SEND to continue where it left off."
    Log ($why + "  Next SEND skips finished files.")
    Set-Busy $false
    Tray-Note "NightSend stopped" $lblStatus.Text
}

# ---------- UI ----------
$form = New-Object Windows.Forms.Form
$form.Text = "NightSend"
$form.ClientSize = New-Object Drawing.Size(720, 600)
$form.BackColor = $cBg; $form.ForeColor = $cText; $form.Font = $fUi
$form.FormBorderStyle = "FixedSingle"; $form.MaximizeBox = $false
$form.StartPosition = "CenterScreen"

function L($text, $x, $y, $w, $h, $font, $color) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.Location = New-Object Drawing.Point($x, $y); $l.Size = New-Object Drawing.Size($w, $h)
    if ($font) { $l.Font = $font }; if ($color) { $l.ForeColor = $color }
    $form.Controls.Add($l); $l
}
function B($text, $x, $y, $w) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object Drawing.Point($x, $y); $b.Size = New-Object Drawing.Size($w, 32)
    $b.FlatStyle = "Flat"; $b.BackColor = $cPanel; $b.ForeColor = $cText
    $b.FlatAppearance.BorderColor = $cAccent
    $form.Controls.Add($b); $b
}
function T($text, $x, $y, $w) {
    $t = New-Object Windows.Forms.TextBox
    $t.Text = $text; $t.Location = New-Object Drawing.Point($x, $y); $t.Size = New-Object Drawing.Size($w, 28)
    $t.BackColor = $cPanel; $t.ForeColor = $cText; $t.BorderStyle = "FixedSingle"
    $form.Controls.Add($t); $t
}

[void](L "NIGHTSEND" 20 14 400 44 (New-Object Drawing.Font("Segoe UI Black", 24)) $cText)
[void](L "Same Wi-Fi  -  just type the code  -  no cloud, no internet" 22 58 660 22 $null $cDim)
$line = New-Object Windows.Forms.Panel; $line.BackColor = $cAccent
$line.Location = New-Object Drawing.Point(20, 86); $line.Size = New-Object Drawing.Size(680, 2); $form.Controls.Add($line)

[void](L "1  PHONE" 20 102 200 22 $fBold $cDim)
$btnFind = B "Find phone" 20 126 150
[void](L "Address (auto):" 182 132 64 22 $null $cDim)
$txtIp = T "" 248 129 150
[void](L "Code:" 410 132 44 22 $null $cDim)
$txtCode = T $SavedCode 456 129 90
$txtCode.MaxLength = 7
[void](L "(from phone)" 552 132 150 22 $null $cDim)
$lblPhone = L "Not connected." 20 164 680 40 $null $cDim

[void](L "2  SEND FROM (this PC)" 20 210 300 22 $fBold $cDim)
$txtSrc = T "D:\BnM\TV & Movie\TV" 20 234 560
$btnBrowse = B "Browse" 590 231 110
[void](L "Where it goes on the phone is set in the phone app." 20 266 680 22 $null $cDim)

$btnSend = B "SEND" 20 300 150
$btnSend.BackColor = $cAccent; $btnSend.Font = $fBold
$btnStop = B "Stop" 180 300 110; $btnStop.Enabled = $false

$bar = New-Object Windows.Forms.ProgressBar
$bar.Location = New-Object Drawing.Point(20, 348); $bar.Size = New-Object Drawing.Size(680, 18); $bar.Maximum = 1000
$form.Controls.Add($bar)
$lblStatus = L "Ready." 20 372 680 22 $null $cText
$lblFile = L "" 20 394 680 22 $null $cDim

$txtLog = New-Object Windows.Forms.TextBox
$txtLog.Multiline = $true; $txtLog.ScrollBars = "Vertical"; $txtLog.ReadOnly = $true
$txtLog.Location = New-Object Drawing.Point(20, 424); $txtLog.Size = New-Object Drawing.Size(680, 160)
$txtLog.BackColor = $cPanel; $txtLog.ForeColor = $cDim; $txtLog.BorderStyle = "FixedSingle"
$txtLog.Font = New-Object Drawing.Font("Consolas", 9)
$form.Controls.Add($txtLog)

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 20
$timer.Add_Tick({ On-Tick })

$btnFind.Add_Click({ Set-Busy $true; $btnStop.Enabled = $false; [void](Connect-Phone); Close-Conn; Set-Busy $false })
$btnSend.Add_Click({ Start-Send })
$btnStop.Add_Click({ Abort-Send "Stopped by you." })
$btnBrowse.Add_Click({
    $d = New-Object Windows.Forms.FolderBrowserDialog
    $d.SelectedPath = $txtSrc.Text
    if ($d.ShowDialog() -eq "OK") { $txtSrc.Text = $d.SelectedPath }
})
# ---------- background (system tray) ----------
$tray = New-Object Windows.Forms.NotifyIcon
$tray.Icon = [Drawing.SystemIcons]::Application
$tray.Text = "NightSend"
$tray.Visible = $true
$menu = New-Object Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add("Open NightSend", $null, { Show-Window })
[void]$menu.Items.Add("Exit", $null, { $script:Quit = $true; $form.Close() })
$tray.ContextMenuStrip = $menu

function Show-Window { $form.Show(); $form.WindowState = "Normal"; $form.ShowInTaskbar = $true; [void]$form.Activate() }
function Hide-Window {
    $form.ShowInTaskbar = $false; $form.Hide()
    if ($script:Running) { $tray.BalloonTipTitle = "NightSend"; $tray.BalloonTipText = "Still sending in the background. Click the tray icon to open."; $tray.ShowBalloonTip(3000) }
}
function Tray-Note([string]$title, [string]$msg) {
    if (-not $form.Visible) { $tray.BalloonTipTitle = $title; $tray.BalloonTipText = $msg; $tray.ShowBalloonTip(5000) }
}
$tray.Add_DoubleClick({ Show-Window })
$tray.Add_MouseClick({ if ($_.Button -eq "Left") { Show-Window } })
# Minimizing sends it to the tray, and keeps any transfer running.
$form.Add_Resize({ if ($form.WindowState -eq "Minimized") { Hide-Window } })
$form.Add_FormClosing({
    if ($script:Running -and -not $script:Quit) {
        # X while sending: keep sending in the background instead of stopping.
        $_.Cancel = $true; Hide-Window; return
    }
    if ($script:Running) {
        $a = [Windows.Forms.MessageBox]::Show("A transfer is running. Stop it and exit?", "NightSend", "YesNo", "Warning")
        if ($a -ne "Yes") { $script:Quit = $false; $_.Cancel = $true; return }
        Abort-Send "Closed."
    }
    $tray.Visible = $false; $tray.Dispose()
})
$form.Add_Shown({ Log "NightSend ready. Put the phone and this PC on the same Wi-Fi, open NightSend on the phone and type its pairing code here."
    if ($SavedCode.Length -eq 6) { Set-Busy $true; $btnStop.Enabled = $false; [void](Connect-Phone); Close-Conn; Set-Busy $false }
})

[void]$form.ShowDialog()
