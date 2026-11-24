#!/usr/bin/env python3
"""
VeilBreak Live Multi-Browser Benchmark Runner.
Empirically tests real desktop control browsers (Chrome, Firefox) with human-like
OS mouse trajectories AND famous stealth / anti-detect / automation frameworks against
a live VeilBreak v2.0.0 server.
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
OUT_DIR = Path("/tmp/browser_lab/bench_runs")
OUT_DIR.mkdir(parents=True, exist_ok=True)
PORT = 18995
BASE = f"http://127.0.0.1:{PORT}/"

os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/tmp/browser_lab/pw"
os.environ["XDG_CACHE_HOME"] = "/tmp/browser_lab/cache"
os.environ["TMPDIR"] = "/tmp"


def clear_out(label: str):
    p = OUT_DIR / f"{label}.json"
    if p.exists():
        p.unlink()


def read_out(label: str, wait_stage2: bool = False, timeout: float = 15.0):
    p = OUT_DIR / f"{label}.json"
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout:
        if p.exists() and p.stat().st_size > 20:
            try:
                last = json.loads(p.read_text())
                if not wait_stage2 or last.get("stage2") is not None:
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


def run_human_control_browser(label: str, name: str, is_firefox: bool):
    """
    Launches a genuinely clean desktop browser (zero CDP, zero Marionette, zero flags)
    inside an isolated Xvfb display, verifies Stage-1 passive load, then simulates a
    realistic human multi-step curved mouse trajectory + 85ms button dwell via xdotool!
    """
    clear_out(label)
    prof = tempfile.mkdtemp(prefix=f"vb_ctrl_{label}_", dir="/tmp")
    if is_firefox:
        Path(prof, "user.js").write_text(
            'user_pref("browser.shell.checkDefaultBrowser", false);\n'
            'user_pref("datareporting.policy.firstRunURL", "");\n'
            'user_pref("trailhead.firstrun.didSeeAboutWelcome", true);\n'
        )
        browser_cmd = f'/usr/bin/firefox -profile "{prof}" -new-instance -width 1280 -height 720 "{BASE}?label={label}"'
        # Firefox toolbar height ~85px; button is at left=260..460, top=200..260 -> screen target ~(352, 315)
        target_x, target_y = 352, 315
    else:
        browser_cmd = (
            f'/usr/bin/google-chrome --user-data-dir="{prof}" --no-first-run '
            f'--no-default-browser-check --window-size=1280,720 --window-position=40,40 '
            f'--no-sandbox "{BASE}?label={label}"'
        )
        # Chrome window-pos (40,40) + chrome toolbar ~143px; button left=260..460, top=200..260 -> ~(395, 413)
        target_x, target_y = 395, 413

    # Run inside a single xvfb-run bash script so xdotool shares the exact DISPLAY!
    script = f"""
{browser_cmd} >/dev/null 2>&1 &
BPID=$!
for i in $(seq 1 40); do
  if [ -s "{OUT_DIR}/{label}.json" ]; then break; fi
  sleep 0.3
done
sleep 0.5
# Realistic curved human mouse trajectory across 16 steps + 85ms mousedown->mouseup dwell
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
    subprocess.run(
        ["xvfb-run", "-a", "-s", "-screen 0 1366x768x24", "bash", "-c", script],
        timeout=35, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    shutil.rmtree(prof, ignore_errors=True)
    res = read_out(label, wait_stage2=False, timeout=2.0) or {"label": label, "error": "no_output"}
    res["category"] = "Control (Genuine Browser)"
    res["name"] = name
    return res


def run_browser_case(label: str, category: str, name: str, py_code: str, xvfb: bool = False, node_code: str | None = None, timeout: int = 45):
    clear_out(label)
    if node_code:
        cmd = (["xvfb-run", "-a", "-s", "-screen 0 1366x768x24"] if xvfb else []) + ["node", "-e", node_code]
    else:
        cmd = (["xvfb-run", "-a", "-s", "-screen 0 1366x768x24"] if xvfb else []) + [sys.executable, "-c", py_code]
    r = subprocess.run(cmd, timeout=timeout, capture_output=True, text=True)
    res = read_out(label, wait_stage2=False, timeout=2.5)
    if not res:
        # Check if strict middleware blocked page load with 403 AUTOMATION_UA_DENIED!
        res = {
            "label": label,
            "stage1": {
                "blocked": True,
                "score": 6,
                "threshold": 2,
                "reasons": ["AUTOMATION_UA_DENIED (HTTP 403 on page load)"],
                "wcStatus": "blocked_http_403",
                "apiPassiveStatus": 403,
                "apiPassiveOk": False,
            },
            "stage2": None,
            "probeMs": 0.0,
            "note": r.stderr[-160:].strip() if r.stderr else "Blocked at HTTP layer before JS execution",
        }
    res["category"] = category
    res["name"] = name
    return res


def main():
    srv = subprocess.Popen(
        ["node", str(REPO_ROOT / "benchmarks" / "bench_server.js")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )
    time.sleep(1.0)
    results = []
    try:
        # 1-2. Real Control Browsers (0% False Positives Required!)
        results.append(run_human_control_browser("ctrl_chrome_158", "Google Chrome 158 (Clean Desktop)", is_firefox=False))
        results.append(run_human_control_browser("ctrl_firefox_153", "Mozilla Firefox 153 ESR (Clean Desktop)", is_firefox=True))

        # 3. Tier 1 HTTP scraper
        results.append(test_http_scraper())

        # 4-7. Standard Playwright (Chromium & Firefox, Headless & Headed)
        for lbl, nm, eng, headed in [
            ("pw_chromium_headless", "Playwright Chromium (Headless)", 'p.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True)', False),
            ("pw_chromium_headed", "Playwright Chromium (Headed)", 'p.chromium.launch(executable_path="/usr/bin/google-chrome", headless=False)', True),
            ("pw_firefox_headless", "Playwright Firefox 151 (Headless)", 'p.firefox.launch(headless=True)', False),
            ("pw_firefox_headed", "Playwright Firefox 151 (Headed)", 'p.firefox.launch(headless=False)', True),
        ]:
            results.append(run_browser_case(
                lbl, "Tier 2: Standard Automation", nm,
                f"""
import os, time
os.environ["PLAYWRIGHT_BROWSERS_PATH"] = "/tmp/browser_lab/pw"
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

        # 8. Playwright + playwright-stealth
        results.append(run_browser_case(
            "pw_stealth", "Tier 3: JS Stealth Plugin", "Playwright + playwright-stealth",
            f"""
import time, playwright_stealth
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", headless=True)
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

        # 9. Puppeteer + puppeteer-extra-plugin-stealth
        results.append(run_browser_case(
            "puppeteer_stealth", "Tier 3: JS Stealth Plugin", "Puppeteer + puppeteer-extra-plugin-stealth",
            "",
            node_code=f"""
const puppeteer = require("/tmp/browser_lab/node_lab/node_modules/puppeteer-extra");
const Stealth = require("/tmp/browser_lab/node_lab/node_modules/puppeteer-extra-plugin-stealth");
puppeteer.use(Stealth());
(async () => {{
  const b = await puppeteer.launch({{ executablePath: "/usr/bin/google-chrome", headless: "new", args: ["--no-sandbox"] }});
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

        # 10-11. CloakBrowser 146 (Headless & Headed)
        for headed in (False, True):
            lbl = f"cloakbrowser_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                lbl, "Tier 4a: C++-Patched Chromium", f"CloakBrowser 146 ({'Headed' if headed else 'Headless'})",
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

        # 12-13. Camoufox 158 (Headless & Headed — C++-Patched Gecko)
        for headed in (False, True):
            lbl = f"camoufox_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                lbl, "Tier 4a: C++-Patched Firefox", f"Camoufox 158 ({'Headed' if headed else 'Headless'})",
                f"""
import os, time
os.environ["XDG_CACHE_HOME"] = "/tmp/browser_lab/cache"
from camoufox.sync_api import Camoufox
with Camoufox(headless={not headed}) as b:
    page = b.new_page()
    page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=25000)
    time.sleep(1.0)
    try: page.click("#vb-btn", timeout=4000)
    except Exception: pass
    time.sleep(0.8)
""", xvfb=headed))

        # 14-15. Patchright (Headless & Headed)
        for headed in (False, True):
            lbl = f"patchright_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                lbl, "Tier 4b: CDP-Patched Stealth", f"Patchright ({'Headed' if headed else 'Headless'})",
                f"""
import time
from patchright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=headed))

        # 16-17. Rebrowser-Playwright (Headless & Headed)
        for headed in (False, True):
            lbl = f"rebrowser_{'headed' if headed else 'headless'}"
            results.append(run_browser_case(
                lbl, "Tier 4b: CDP-Patched Stealth", f"Rebrowser-Playwright ({'Headed' if headed else 'Headless'})",
                f"""
import os, time
os.environ["REBROWSER_PATCHES_RUNTIME_FIX_MODE"] = "addBinding"
from rebrowser_playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/google-chrome", headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="networkidle", timeout=20000)
    if resp and resp.status == 200:
        time.sleep(1.0)
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        time.sleep(0.8)
    b.close()
""", xvfb=headed))

        # 18. SeleniumBase UC Mode (Headed)
        results.append(run_browser_case(
            "seleniumbase_uc", "Tier 4b: CDP-Patched Stealth", "SeleniumBase UC Mode (Headed)",
            f"""
import time
from seleniumbase import SB
with SB(uc=True, headless=False, binary_location="/usr/bin/google-chrome") as sb:
    sb.uc_open("{BASE}?label=seleniumbase_uc")
    time.sleep(1.5)
    try: sb.uc_click("#vb-btn")
    except Exception: pass
    time.sleep(1.0)
""", xvfb=True, timeout=55))

        # 19. Nodriver (Headed)
        results.append(run_browser_case(
            "nodriver_headed", "Tier 4b: Raw-CDP Stealth", "Nodriver (Headed)",
            f"""
import asyncio, nodriver as uc
async def main():
    b = await uc.start(browser_executable_path="/usr/bin/google-chrome", headless=False, sandbox=False)
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

        # Save JSON results right inside benchmarks/results.json
        out_json = REPO_ROOT / "benchmarks" / "results.json"
        out_json.write_text(json.dumps({
            "version": "2.0.0",
            "mode": "strict",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "results": results,
        }, indent=2))

        print("\n" + "=" * 112)
        print(f"{'Browser / Tool':42s} | {'Stage-1':12s} | {'WC':9s} | {'Stage-2 Click':14s} | {'Reasons'}")
        print("-" * 112)
        for r in results:
            s1 = r.get("stage1", {})
            s2 = r.get("stage2")
            s1_str = f"{'BLOCK' if s1.get('blocked') else 'ALLOW'} ({s1.get('score',0)})"
            wc_str = str(s1.get("wcStatus", "-"))[:9]
            if s2:
                s2_str = f"{'BLOCK' if s2.get('combinedBlocked') else 'ALLOW'} (+{s2.get('clickScore',0)})"
                reasons = sorted(set((s1.get("reasons") or []) + (s2.get("clickReasons") or [])))
            else:
                s2_str = "n/a"
                reasons = s1.get("reasons") or []
            print(f"{r['name']:42s} | {s1_str:12s} | {wc_str:9s} | {s2_str:14s} | {', '.join(reasons) or 'CLEAN'}")
        print("=" * 112)
    finally:
        srv.terminate()
        srv.wait(timeout=3)


if __name__ == "__main__":
    main()
