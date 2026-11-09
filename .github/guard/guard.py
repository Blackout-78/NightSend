#!/usr/bin/env python3
"""Security guard. Runs in the build before anything is published.

Fails the build (exit 1) if a change adds something dangerous:
  - a signing key, keystore, .env or secrets file
  - the INTERNET permission (unless --allow-internet) or other risky permissions
  - code that loads other code, runs commands, or hides what it does
  - invisible text-direction characters (the "Trojan Source" trick)
  - a new compiled file (.jar .aar .so .dex .exe .dll .apk .aab .class)
    other than gradle/wrapper/gradle-wrapper.jar (checked separately by Gradle's own validator)

To allow something on purpose, add a line to .github/guard/allow.txt:
    <rule> <path>        e.g.   binary assets/native/foo.so
Rules: key, permission, code, unicode, binary.  Every allow line is visible in the repo history.
"""
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ANDROID = "{http://schemas.android.com/apk/res/android}"
TOOLS = "{http://schemas.android.com/tools}"

RISKY_PERMS = {
    "QUERY_ALL_PACKAGES", "REQUEST_INSTALL_PACKAGES", "INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW", "BIND_ACCESSIBILITY_SERVICE", "BIND_DEVICE_ADMIN",
    "READ_LOGS", "WRITE_SECURE_SETTINGS", "MANAGE_EXTERNAL_STORAGE_FOR_ALL",
}
KEY_FILE = re.compile(r"\.(jks|keystore|p12|pfx|pem|key|env)$", re.I)
SECRET_NAME = re.compile(r"(^|/)(secrets?|github-secrets)[^/]*\.txt$", re.I)
BINARY = re.compile(r"\.(jar|aar|so|dex|exe|dll|apk|aab|class)$", re.I)
CODE_PATTERNS = [
    (re.compile(r"\b(InMemoryDexClassLoader|DexClassLoader|PathClassLoader)\b"), "loads code at run time"),
    (re.compile(r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\("), "runs a command"),
    (re.compile(r"\bProcessBuilder\s*\("), "runs a command"),
    (re.compile(r"\baddJavascriptInterface\s*\("), "opens a WebView to scripts"),
    (re.compile(r"\bInvoke-Expression\b|\bDownloadString\b|\bIEX\s*\("), "PowerShell runs downloaded or built text"),
    (re.compile(r"shell\s*=\s*True"), "Python shell=True"),
    (re.compile(r"\bos\.system\s*\("), "Python os.system"),
    (re.compile(r"(?<![.\w])(eval|exec)\s*\("), "Python eval/exec"),
    (re.compile(r"\bpickle\.loads?\s*\("), "Python pickle (can run code)"),
]
CODE_EXT = {".kt", ".java", ".py", ".ps1", ".bat", ".kts", ".gradle", ".yml", ".yaml"}
TEXT_EXT = CODE_EXT | {".xml", ".md", ".txt", ".json", ".toml", ".properties"}
BIDI = re.compile("[" + "".join(chr(c) for c in (0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069)) + "]")


def load_allow():
    allow = set()
    p = Path(".github/guard/allow.txt")
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split(None, 1)
                if len(parts) == 2:
                    allow.add((parts[0].lower(), parts[1].strip()))
    return allow


def main():
    allow_internet = "--allow-internet" in sys.argv
    allow = load_allow()
    problems = []

    def flag(rule, path, why):
        if (rule, path) in allow:
            return
        problems.append(f"[{rule}] {path}: {why}")

    files = subprocess.check_output(["git", "ls-files"], text=True).splitlines()
    for f in files:
        low = f.lower()
        name = f.rsplit("/", 1)[-1]
        if KEY_FILE.search(name) or SECRET_NAME.search(f):
            flag("key", f, "a key or secrets file must never be committed")
        if BINARY.search(name) and f != "gradle/wrapper/gradle-wrapper.jar":
            flag("binary", f, "new compiled file; confirm it is yours, then allow it")

        suffix = Path(f).suffix.lower()
        if "/build/" in f or low.startswith("build/"):
            continue
        if name == "AndroidManifest.xml":
            check_manifest(f, allow_internet, flag)
        if suffix in TEXT_EXT:
            try:
                text = Path(f).read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if BIDI.search(text):
                flag("unicode", f, "hidden text-direction characters can disguise code")
            if suffix in CODE_EXT and not f.startswith(".github/guard/"):
                for pat, why in CODE_PATTERNS:
                    # workflows may legitimately mention words in comments/echo; only check app code
                    if suffix in {".yml", ".yaml"}:
                        continue
                    m = pat.search(text)
                    if m:
                        line = text.count("\n", 0, m.start()) + 1
                        flag("code", f, f"line {line}: {why}")
    if problems:
        print("SECURITY GUARD: STOP. The build was blocked.\n")
        for p in problems:
            print("  " + p)
        print("\nIf this is on purpose, add a line to .github/guard/allow.txt (rule path).")
        sys.exit(1)
    print("Security guard: all clear.")


def check_manifest(path, allow_internet, flag):
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        flag("permission", path, f"manifest could not be read: {e}")
        return
    for el in root.iter("uses-permission"):
        perm = (el.get(ANDROID + "name") or "").split(".")[-1]
        removed = el.get(TOOLS + "node") == "remove"
        if removed:
            continue
        if perm == "INTERNET" and not allow_internet:
            flag("permission", path, "INTERNET permission added (this app must stay offline)")
        if perm in RISKY_PERMS:
            flag("permission", path, f"risky permission {perm}")
    app = root.find("application")
    if app is not None:
        if app.get(ANDROID + "usesCleartextTraffic") == "true":
            flag("permission", path, "usesCleartextTraffic=true")
        if app.get(ANDROID + "debuggable") == "true":
            flag("permission", path, "debuggable=true")


if __name__ == "__main__":
    main()
