#!/usr/bin/env python3
"""
VeilBreak Live Multi-Browser Benchmark Runner (Portable).

Tests clean desktop control browsers (Chrome, Firefox via xvfb + xdotool) and
any locally installed automation / anti-detect frameworks against a live
VeilBreak v2.0.0 server (`benchmarks/bench_server.js`).

Environment overrides (all optional — auto-discovered from PATH by default):
  VB_CHROME_BIN           Path to Chrome / Chromium executable
  VB_FIREFOX_BIN          Path to Firefox executable
  VB_PUPPETEER_NODE_PATH  NODE_PATH containing puppeteer-extra + stealth plugin
  VB_BENCH_PORT           Local HTTP port (default: 18995)

Missing frameworks are explicitly recorded as `SKIPPED_MISSING_TOOL` (never
fabricated as HTTP 403 blocks!).
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
PORT = int(os.environ.get("VB_BENCH_PORT", "18995"))
BASE = f"http://127.0.0.1:{PORT}/"

CHROME_BIN = (
    os.environ.get("VB_CHROME_BIN")
    or shutil.which("google-chrome")
    or shutil.which("google-chrome-stable")
    or shutil.which("chromium")
    or shutil.which("chromium-browser")
)
FIREFOX_BIN = os.environ.get("VB_FIREFOX_BIN") or shutil.which("firefox")
XVFB_BIN = shutil.which("xvfb-run")
XDOTOOL_BIN = shutil.which("xdotool")


def clear_out(out_dir: Path, label: str):
    p = out_dir / f"{label}.json"
    if p.exists():
        p.unlink()


def read_out(out_dir: Path, label: str, timeout: float = 15.0):
    p = out_dir / f"{label}.json"
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        if p.exists() and p.stat().st_size > 20:
            try:
                last = json.loads(p.read_text(encoding="utf-8"))
                return last
            except Exception:
                pass
        time.sleep(0.2)
    return last


def test_http_scraper():
    label = "curl_http_scraper"
    req = urllib.request.Request(f"{BASE}api/secret", headers={"User-Agent": "curl/8.5.0"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            body = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        status = e.code
        body = json.loads(e.read().decode())
    return {
        "label": label,
        "status": "OK",
        "category": "Tier 1: HTTP Scraper",
        "name": "curl / Python urllib",
        "stage1": {
            "blocked": status == 403,
            "score": body.get("score", 6),
            "threshold": body.get("threshold", 2),
            "reasons": body.get("reasons", ["ATTEST_REQUIRED"]),
            "wcStatus": "n/a",
            "apiPassiveStatus": status,
            "apiPassiveOk": status == 200,
        },
        "stage2": None,
        "probeMs": 0.0,
    }


def run_human_control_browser(out_dir: Path, label: str, name: str, is_firefox: bool):
    """
    Launches an unmodified desktop browser (zero CDP, zero Marionette) inside Xvfb
    and drives a synthetic multi-step OS pointer trajectory + 85ms dwell via xdotool.
    """
    browser_bin = FIREFOX_BIN if is_firefox else CHROME_BIN
    if not browser_bin or not XVFB_BIN or not XDOTOOL_BIN:
        return {
            "label": label,
            "status": "SKIPPED_MISSING_TOOL",
            "category": "Control (Clean Desktop Browser)",
            "name": name,
            "note": "Requires browser binary + xvfb-run + xdotool in PATH",
        }

    clear_out(out_dir, label)
    prof = tempfile.mkdtemp(prefix=f"vb_ctrl_{label}_")
    if is_firefox:
        Path(prof, "user.js").write_text(
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.firstRunURL", "");\n'
            'user_pref("trailhead.firstrun.didSeeAboutWelcome", true);\n',
            encoding="utf-8",
        )
        browser_cmd = f'"{browser_bin}" -profile "{prof}" -new-instance -width 1280 -height 720 "{BASE}?label={label}"'
        target_x, target_y = 352, 315
    else:
        browser_cmd = (
            f'"{browser_bin}" --user-data-dir="{prof}" --no-first-run '
            f'--no-default-browser-check --window-size=1280,720 --window-position=40,40 '
            f'--no-sandbox "{BASE}?label={label}"'
        )
        target_x, target_y = 395, 413

    script = f"""
{browser_cmd} >/dev/null 2>&1 &
BPID=$!
for i in $(seq 1 40); do
  if [ -s "{out_dir}/{label}.json" ]; then break; fi
  sleep 0.3
done
sleep 0.5
xdotool mousemove 80 120
sleep 0.04
for step in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do
  nx=$(( 80 + ({target_x} - 80) * step / 16 + (step % 3) ))
  ny=$(( 120 + ({target_y} - 120) * step / 16 - (step % 2) ))
  xdotool mousemove $nx $ny
  sleep 0.015
done
xdotool mousedown 1
sleep 0.085
xdotool mouseup 1
sleep 1.2
kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true
"""
    try:
        subprocess.run(
            [XVFB_BIN, "-a", "-s", "-screen 0 1366x768x24", "bash", "-c", script],
            timeout=35,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    finally:
        shutil.rmtree(prof, ignore_errors=True)
    res = read_out(out_dir, label, timeout=2.0)
    if not res:
        return {"label": label, "status": "ERROR", "category": "Control (Clean Desktop Browser)", "name": name, "note": "No benchmark output recorded"}
    res["status"] = "OK"
    res["category"] = "Control (Clean Desktop Browser)"
    res["name"] = name
    return res


def run_browser_case(
    out_dir: Path,
    label: str,
    category: str,
    name: str,
    py_code: str = "",
    xvfb: bool = False,
    node_code: str | None = None,
    timeout: int = 45,
):
    if xvfb and not XVFB_BIN:
        return {"label": label, "status": "SKIPPED_MISSING_TOOL", "category": category, "name": name, "note": "xvfb-run not installed"}
    clear_out(out_dir, label)
    prefix = [XVFB_BIN, "-a", "-s", "-screen 0 1366x768x24"] if xvfb else []
    cmd = prefix + (["node", "-e", node_code] if node_code else [sys.executable, "-c", py_code])
    env = dict(os.environ)
    if os.environ.get("VB_PUPPETEER_NODE_PATH"):
        env["NODE_PATH"] = os.environ["VB_PUPPETEER_NODE_PATH"]
    try:
        r = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True, env=env)
    except subprocess.TimeoutExpired:
        return {"label": label, "status": "ERROR", "category": category, "name": name, "note": "Timed out"}

    res = read_out(out_dir, label, timeout=2.5)
    if res:
        res["status"] = "OK"
        res["category"] = category
        res["name"] = name
        return res

    stderr_tail = (r.stderr or "").strip()[-240:]
    if "ModuleNotFoundError" in stderr_tail or "MODULE_NOT_FOUND" in stderr_tail or "No module named" in stderr_tail:
        return {"label": label, "status": "SKIPPED_MISSING_TOOL", "category": category, "name": name, "note": stderr_tail}
    return {
        "label": label,
        "status": "ERROR",
        "category": category,
        "name": name,
        "note": f"Process exited rc={r.returncode} without producing benchmark output: {stderr_tail}",
    }


def main():
    out_dir = Path(tempfile.mkdtemp(prefix="veilbreak_bench_runs_"))
    srv_env = dict(os.environ, VB_BENCH_PORT=str(PORT), VB_BENCH_OUT=str(out_dir))
    srv = subprocess.Popen(
        ["node", str(REPO_ROOT / "benchmarks" / "bench_server.js")],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=srv_env,
    )
    time.sleep(1.0)
    results = []
    chrome_arg = f'executable_path={json.dumps(CHROME_BIN)}, ' if CHROME_BIN else ""
    try:
        results.append(run_human_control_browser(out_dir, "ctrl_chrome", "Google Chrome (Clean Desktop)", is_firefox=False))
        results.append(run_human_control_browser(out_dir, "ctrl_firefox", "Mozilla Firefox (Clean Desktop)", is_firefox=True))
        results.append(test_http_scraper())

        for lbl, nm, eng, headed in [
            ("pw_chromium_headless", "Playwright Chromium (Headless)", f"p.chromium.launch({chrome_arg}headless=True)", False),
            ("pw_chromium_headed", "Playwright Chromium (Headed)", f"p.chromium.launch({chrome_arg}headless=False)", True),
            ("pw_firefox_headless", "Playwright Firefox (Headless)", "p.firefox.launch(headless=True)", False),
            ("pw_firefox_headed", "Playwright Firefox (Headed)", "p.firefox.launch(headless=False)", True),
        ]:
            results.append(run_browser_case(
                out_dir, lbl, "Tier 2: Standard Automation", nm,
                f"""
import time
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = {eng}
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=headed))

        results.append(run_browser_case(
            out_dir, "pw_stealth", "Tier 3: JS Stealth Plugin", "Playwright + playwright-stealth",
            f"""
import time, playwright_stealth
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch({chrome_arg}headless=True)
    ctx = b.new_context()
    if hasattr(playwright_stealth, "Stealth"):
        playwright_stealth.Stealth().apply_stealth_sync(ctx)
        page = ctx.new_page()
    else:
        page = ctx.new_page()
        playwright_stealth.stealth_sync(page)
    resp = page.goto("{BASE}?label=pw_stealth", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=False))

        results.append(run_browser_case(
            out_dir, "puppeteer_stealth", "Tier 3: JS Stealth Plugin", "Puppeteer + puppeteer-extra-plugin-stealth",
            node_code=f"""
const puppeteer = require("puppeteer-extra");
const Stealth = require("puppeteer-extra-plugin-stealth");
puppeteer.use(Stealth());
(async () => {{
  const opts = {{ headless: "new", args: ["--no-sandbox"] }};
  if ({json.dumps(CHROME_BIN)}) opts.executablePath = {json.dumps(CHROME_BIN)};
  const b = await puppeteer.launch(opts);
  const p = await b.newPage();
  const r = await p.goto("{BASE}?label=puppeteer_stealth", {{ waitUntil: "networkidle0" }});
  if (r && r.status() === 200) {{
    await new Promise(res => setTimeout(res, 900));
    try {{ await p.click("#vb-btn"); }} catch {{}}
    await new Promise(res => setTimeout(res, 700));
  }}
  await b.close();
}})();
"""))

        for headed in (False, True):
            lbl = f"cloakbrowser_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                out_dir, lbl, "Tier 4a: C++-Patched Chromium", f"CloakBrowser ({'Headed' if headed else 'Headless'})",
                f"""
import cloakbrowser, time
b = cloakbrowser.launch(headless={not headed})
page = b.new_page()
page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
time.sleep(1.0)
try: page.click("#vb-btn", timeout=4000)
except Exception: pass
time.sleep(0.8)
b.close()
""", xvfb=headed))

        for headed in (False, True):
            lbl = f"camoufox_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                out_dir, lbl, "Tier 4a: C++-Patched Firefox", f"Camoufox ({'Headed' if headed else 'Headless'})",
                f"""
import time
from camoufox.sync_api import Camoufox
with Camoufox(headless={not headed}) as b:
    page = b.new_page()
    page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=25000)
    time.sleep(1.0)
    try: page.click("#vb-btn", timeout=4000)
    except Exception: pass
    time.sleep(0.8)
""", xvfb=headed))

        for headed in (False, True):
            lbl = f"patchright_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                out_dir, lbl, "Tier 4b: CDP-Patched Stealth", f"Patchright ({'Headed' if headed else 'Headless'})",
                f"""
import time
from patchright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch({chrome_arg}headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=headed))

        for headed in (False, True):
            lbl = f"rebrowser_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                out_dir, lbl, "Tier 4b: CDP-Patched Stealth", f"Rebrowser-Playwright ({'Headed' if headed else 'Headless'})",
                f"""
import os, time
os.environ["REBROWSER_PATCHES_RUNTIME_FIX_MODE"] = "addBinding"
from rebrowser_playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch({chrome_arg}headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=headed))

        sb_bin_arg = f', binary_location={json.dumps(CHROME_BIN)}' if CHROME_BIN else ""
        results.append(run_browser_case(
            out_dir, "seleniumbase_uc", "Tier 4b: CDP-Patched Stealth", "SeleniumBase UC Mode (Headed)",
            f"""
import time
from seleniumbase import SB
with SB(uc=True, headless=False{sb_bin_arg}) as sb:
    sb.uc_open("{BASE}?label=seleniumbase_uc")
    time.sleep(1.5)
    try: sb.uc_click("#vb-btn")
    except Exception: pass
    time.sleep(1.0)
""", xvfb=True, timeout=55))

        nd_bin_arg = f'browser_executable_path={json.dumps(CHROME_BIN)}, ' if CHROME_BIN else ""
        results.append(run_browser_case(
            out_dir, "nodriver_headed", "Tier 4b: Raw-CDP Stealth", "Nodriver (Headed)",
            f"""
import asyncio, nodriver as uc
async def main():
    b = await uc.start({nd_bin_arg}headless=False, sandbox=False)
    p = await b.get("{BASE}?label=nodriver_headed")
    await asyncio.sleep(1.8)
    try:
        btn = await p.select("#vb-btn")
        await btn.click()
    except Exception:
        pass
    await asyncio.sleep(1.2)
    b.stop()
asyncio.run(main())
""", xvfb=True))

        out_json = REPO_ROOT / "benchmarks" / "results.json"
        out_json.write_text(json.dumps({
            "version": "2.0.0",
            "mode": "strict",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": results,
        }, indent=2) + "\n", encoding="utf-8")

        print("\n" + "=" * 112)
        print(f"{'Browser / Tool':42s} | {'Status':12s} | {'Stage-1':12s} | {'Stage-2 Click':14s} | {'Reasons'}")
        print("-" * 112)
        for r in results:
            if r.get("status") != "OK":
                print(f"{r['name']:42s} | {r.get('status','ERR'):12s} | {'-':12s} | {'-':14s} | {r.get('note','')[:40]}")
                continue
            s1 = r.get("stage1", {})
            s2 = r.get("stage2")
            s1_str = f"{'BLOCK' if s1.get('blocked') else 'ALLOW'} ({s1.get('score',0)})"
            if s2:
                s2_str = f"{'BLOCK' if s2.get('combinedBlocked') else 'ALLOW'} (+{s2.get('clickScore',0)})"
                reasons = sorted(set((s1.get("reasons") or []) + (s2.get("clickReasons") or [])))
            else:
                s2_str = "n/a"
                reasons = s1.get("reasons") or []
            print(f"{r['name']:42s} | {'OK':12s} | {s1_str:12s} | {s2_str:14s} | {', '.join(reasons) or 'CLEAN'}")
        print("=" * 112)
    finally:
        srv.terminate()
        srv.wait(timeout=3)
        shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
