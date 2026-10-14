# -*- coding: utf-8 -*-
"""backfill_pat.py — recover PAT for saved accounts missing it.

Per account in accounts/BACKFILL_QUEUE.txt:
  1. github.com/password_reset  -> request reset email
  2. Gmail IMAP (donor, alias)  -> extract reset link
  3. set new password           -> usually auto-login
  4. login fallback + TOTP 2FA  (if secret known)
  5. /settings/tokens/new       -> sudo gate -> note -> repo+workflow -> Generate
  6. append full line to accounts/BACKFILL_RESULTS.txt, drop from queue

Secrets are read at runtime from config.json / accounts files / batch log.
Usage: python backfill_pat.py [only-suffix ...]
"""
import hashlib
import imaplib
import email as emaillib
import json
import random
import re
import string
import sys
import time
from pathlib import Path

import pyotp
from camoufox.sync_api import Camoufox

ROOT = Path(__file__).resolve().parent
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
cfg = json.loads((ROOT / "config.json").read_text(encoding="utf-8"))
RESULTS = ROOT / "accounts" / "BACKFILL_RESULTS.txt"
QUEUE = ROOT / "accounts" / "BACKFILL_QUEUE.txt"
RECOVERY_DIR = ROOT / "accounts" / "recovery"


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def gen_pass():
    alpha = string.ascii_letters + string.digits
    return "Bx9!" + "".join(random.choice(alpha) for _ in range(14)) + "q2"


def collect_accounts(only=None):
    accs = []
    known = {}
    for f in sorted((ROOT / "accounts").glob("github_accounts_*.txt")):
        for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            p = ln.strip().split("----")
            if len(p) >= 3 and p[0]:
                known[p[0].strip().lower()] = (p[2].strip(), p[3].strip() if len(p) > 3 else "")
    # g7xdk89or9 was never saved — recover username+totp from batch B log slice
    g7 = None
    try:
        lb = (ROOT / "batch_b_1012.log").read_text(encoding="utf-8", errors="ignore")
        i = lb.find("g7xdk89or9@gmail.com")
        if i >= 0:
            j = lb.find("--- account", i)
            sl = lb[i:j if j > i else i + 40000]
            mt = re.search(r"TOTP secret captured: ([A-Z2-7]{16})", sl)
            g7 = ("baradok609g7xdk89or9", mt.group(1) if mt else "")
    except Exception:
        pass
    for ln in QUEUE.read_text(encoding="utf-8").splitlines():
        em = ln.strip().split("|")[0].strip()
        if not em or "@" not in em:
            continue
        if only and not any(s in em for s in only):
            continue
        if em.lower() in known:
            u, t = known[em.lower()]
        elif g7 and "g7xdk89or9" in em.lower():
            u, t = g7
        else:
            u = em.split("+")[0].split("@")[0] + re.sub(r"[^a-z0-9]", "", em.split("+")[1].split("@")[0])
            t = ""
        accs.append({"email": em, "username": u, "totp": t})
    return accs


def imap_reset_link(email_addr, timeout=240):
    suffix = email_addr.split("+")[1].split("@")[0].lower()
    end = time.time() + timeout
    while time.time() < end:
        try:
            M = imaplib.IMAP4_SSL(cfg["imap_host"], int(cfg["imap_port"]))
            M.login(cfg["imap_user"], cfg["imap_password"])
            M.select("INBOX")
            for crit in (f'TO "{suffix}"', "UNSEEN", 'SINCE "12-Oct-2026"'):
                typ, data = M.search(None, crit)
                ids = (data[0].split() or [])[-80:]
                for i in reversed(ids):
                    try:
                        typ, md = M.fetch(i, "(BODY.PEEK[])")
                        msg = emaillib.message_from_bytes(md[0][1])
                        to = (msg.get("To") or "").lower()
                        subj = (msg.get("Subject") or "").lower()
                        if suffix not in to:
                            continue
                        if "password" not in subj and "reset" not in subj:
                            continue
                        body = ""
                        if msg.is_multipart():
                            for part in msg.walk():
                                if part.get_content_type() == "text/html":
                                    body = part.get_payload(decode=True).decode("utf-8", "ignore")
                                    break
                        else:
                            body = msg.get_payload(decode=True).decode("utf-8", "ignore")
                        m = re.search(r"https://github\.com/[^\"'\s<>]*password[^\"'\s<>]*", body)
                        if m:
                            link = m.group(0).replace("&amp;", "&").rstrip(".")
                            M.logout()
                            return link
                    except Exception:
                        continue
            M.logout()
        except Exception as e:
            log(f"imap err: {type(e).__name__} {e}")
        time.sleep(10)
    return ""


def _fill_first(page, selectors, value):
    for s in selectors:
        try:
            loc = page.locator(s).first
            if loc.count() and loc.is_visible():
                loc.fill(value)
                return True
        except Exception:
            pass
    return False


def _click(page, selectors):
    for s in selectors:
        try:
            loc = page.locator(s).first
            if loc.count() and loc.is_visible():
                loc.click(timeout=8000)
                return True
        except Exception:
            try:
                page.evaluate(
                    "(sel) => { const e = document.querySelector(sel); if (e) e.click(); }", s)
            except Exception:
                pass
    return False


def _ensure_login(page, acc, newpass):
    page.goto("https://github.com/settings/profile", wait_until="domcontentloaded", timeout=60000)
    time.sleep(3)
    if "/login" not in page.url:
        return True
    log("login form fallback")
    _fill_first(page, ["#login_field", "input[name='login']"], acc["username"])
    _fill_first(page, ["#password", "input[name='password']"], newpass)
    _click(page, ["input[type='submit']", "button[type='submit']"])
    time.sleep(6)
    if re.search(r"two-factor|otp|authenticator", page.content().lower()):
        if not acc["totp"]:
            log("2FA required but no TOTP secret — abort")
            return False
        code = pyotp.TOTP(acc["totp"]).now()
        log(f"2FA code submitted")
        _fill_first(page, ["#otp", "input[name='otp']", "input[autocomplete='one-time-code']",
                           "#app_totp"], code)
        _click(page, ["button[type='submit']", "input[type='submit']"])
        time.sleep(6)
    page.goto("https://github.com/settings/profile", wait_until="domcontentloaded", timeout=60000)
    return "/login" not in page.url


def _create_pat(page, newpass):
    page.goto("https://github.com/settings/tokens/new", wait_until="domcontentloaded", timeout=60000)
    time.sleep(3)
    # sudo gate
    if page.locator("#sudo_password, input[name='sudo_password']").count():
        log("sudo gate -> new password")
        _fill_first(page, ["#sudo_password", "input[name='sudo_password']"], newpass)
        _click(page, ["button[type='submit']", "input[type='submit']"])
        time.sleep(5)
    _fill_first(page, ["#oauth_access_description", "textarea#oauth_access_description"], "ci")
    page.evaluate("""() => {
        for (const v of ['repo','workflow']) {
            const cb = document.querySelector(`input[type=checkbox][value='${v}']`);
            if (cb && !cb.checked) { cb.click(); }
        }
    }""")
    time.sleep(1)
    _click(page, ["button:has-text('Generate token')", "input[value='Generate token']",
                  "input[name='commit']", "button[type='submit']"])
    time.sleep(6)
    m = re.search(r"ghp_[A-Za-z0-9]{36}", page.inner_text("body"))
    if not m:
        m = re.search(r"ghp_[A-Za-z0-9]{36}", page.content())
    if not m:
        time.sleep(6)
        m = re.search(r"ghp_[A-Za-z0-9]{36}", page.content())
    return m.group(0) if m else ""


def backfill_one(acc, proxies):
    em = acc["email"]
    newpass = gen_pass()
    for attempt in range(3):
        px = random.choice(proxies)
        log(f"--- {em} (try {attempt+1}, proxy {px.split('@')[-1]}) ---")
        try:
            with Camoufox(headless=True, proxy={"server": px}) as browser:
                page = browser.new_page()
                page.set_default_timeout(45000)
                # 1) request reset
                page.goto("https://github.com/password_reset", wait_until="domcontentloaded", timeout=60000)
                # fail fast on block pages (free proxies are often flagged)
                try:
                    _bt = page.inner_text("body", timeout=4000).lower()
                except Exception:
                    _bt = ""
                if not _bt.strip():
                    try:
                        _bt = page.content().lower()
                    except Exception:
                        _bt = ""
                if ("access is temporarily restricted" in _bt or "unusual activity" in _bt
                        or "enable js" in _bt or "slide right to secure" in _bt):
                    raise RuntimeError("block page on /password_reset — flagged proxy")
                sel = None
                for s in ("#login_field", "input[name='user[email]']",
                          "input[type='email']", "input[type='text']"):
                    try:
                        page.wait_for_selector(s, state="visible", timeout=12000)
                        sel = s
                        break
                    except Exception:
                        continue
                if not sel:
                    raise RuntimeError("reset form not found")
                page.locator(sel).first.fill(em)
                filled = True
                if not filled:
                    raise RuntimeError("reset form not found")
                _click(page, ["button[type='submit']", "input[type='submit']"])
                time.sleep(5)
                # 2) link from IMAP
                link = imap_reset_link(em)
                if not link:
                    raise RuntimeError("no reset email in IMAP")
                log("reset link received")
                # 3) set new password (proper waits — slow proxies render late)
                page.goto(link, wait_until="domcontentloaded", timeout=60000)
                # 3a) 2FA gate on reset link (accounts have TOTP enabled)
                try:
                    otp_box = page.wait_for_selector("input[name='app_otp'], #otp", state="visible", timeout=8000)
                except Exception:
                    otp_box = None
                if otp_box:
                    code = ""
                    if acc.get("totp"):
                        try:
                            import pyotp
                            code = pyotp.TOTP(acc["totp"].replace(" ", "")).now()
                        except Exception:
                            code = ""
                    if not code:
                        try:
                            key = hashlib.sha256(em.strip().lower().encode()).hexdigest()
                            rf = RECOVERY_DIR / f"{key}.txt"
                            if rf.exists():
                                for tok in rf.read_text().split():
                                    if tok.count("-") == 1 and len(tok) == 11:
                                        code = tok
                                        break
                        except Exception:
                            pass
                    if not code:
                        raise RuntimeError("2FA gate on reset link but no TOTP/recovery code")
                    log(f"reset link 2FA gate — filling {'TOTP' if len(code) == 6 else 'recovery code'}")
                    otp_box.fill(code)
                    try:
                        page.wait_for_function(
                            "() => !document.querySelector(\"input[name='app_otp']\")",
                            timeout=20000)
                    except Exception:
                        _click(page, ["button[type='submit']", "input[type='submit']"])
                        time.sleep(6)
                psel = None
                for s in ("#password", "input[name='user[password]']",
                          "input[type='password']"):
                    try:
                        page.wait_for_selector(s, state="visible", timeout=15000)
                        psel = s
                        break
                    except Exception:
                        continue
                if not psel:
                    try:
                        _bt2 = page.inner_text("body", timeout=4000).lower()
                    except Exception:
                        _bt2 = ""
                    if not _bt2.strip():
                        try:
                            _bt2 = page.content().lower()
                        except Exception:
                            _bt2 = ""
                    if ("access is temporarily restricted" in _bt2
                            or "slide right to secure" in _bt2 or "enable js" in _bt2
                            or "security risk" in _bt2 or "aboutneterror" in _bt2
                            or "certerror" in _bt2):
                        raise RuntimeError("block/TLS-error page on reset link — bad proxy")
                    try:
                        import time as _t
                        dbg = ROOT / "accounts" / f"bf_debug_{int(_t.time())}.html"
                        dbg.write_text(page.content(), encoding="utf-8", errors="ignore")
                        log(f"reset-page debug dump: {dbg.name} (url={page.url})")
                    except Exception:
                        pass
                    raise RuntimeError("reset form fields not found")
                page.locator(psel).first.fill(newpass)
                _fill_first(page, ["#password_confirmation", "input[name='user[password_confirmation]']"], newpass)
                _click(page, ["button[type='submit']", "input[type='submit']"])
                time.sleep(8)
                # 4) ensure logged in
                if not _ensure_login(page, acc, newpass):
                    raise RuntimeError("login failed")
                log("logged in")
                # 5) PAT
                pat = _create_pat(page, newpass)
                if not pat:
                    raise RuntimeError("PAT not created")
                log(f"PAT recovered: ghp_...{pat[-4:]}")
            # 6) persist
            rec = ""
            try:
                key = hashlib.sha256(em.strip().lower().encode()).hexdigest()
                rf = RECOVERY_DIR / f"{key}.txt"
                if rf.exists():
                    rec = " ".join(rf.read_text().split())
            except Exception:
                pass
            line = f"{em}----{newpass}----{acc['username']}----{acc['totp']}----{rec}----{pat}"
            with RESULTS.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
            qlines = [l for l in QUEUE.read_text(encoding="utf-8").splitlines()
                      if em.lower() not in l.lower()]
            QUEUE.write_text("\n".join(qlines) + ("\n" if qlines else ""), encoding="utf-8")
            log(f"SAVED + dequeued: {em}")
            return True
        except Exception as e:
            log(f"attempt failed: {type(e).__name__}: {e}")
            time.sleep(10)
    log(f"GIVE UP: {em}")
    return False


def main():
    only = sys.argv[1:] or None
    accs = collect_accounts(only)
    log(f"queue: {len(accs)} accounts: {[a['email'].split('+')[1].split('@')[0] for a in accs]}")
    proxies = [l.strip() for l in (ROOT / "proxies.txt").read_text().splitlines()
               if l.strip() and not l.lstrip().startswith("#") and l.strip().startswith("http")]
    proxies_b = [l.strip() for l in (ROOT / "proxies_b.txt").read_text().splitlines()
                 if l.strip() and not l.lstrip().startswith("#") and l.strip().startswith("http")]
    allp = list(set(proxies + proxies_b)) or proxies
    ok = 0
    for acc in accs:
        if backfill_one(acc, allp):
            ok += 1
        time.sleep(random.uniform(20, 40))
    log(f"BACKFILL DONE: {ok}/{len(accs)} recovered")


if __name__ == "__main__":
    main()
