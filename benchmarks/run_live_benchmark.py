#!/usr/bin/env python3
"""
VeilBreak Live Multi-Browser & Anti-Scraper Benchmark Runner (Portable).

Tests clean desktop control browsers (Chrome, Firefox via xvfb + xdotool),
Tier-1 HTTP/scripted clients (raw curl, spoofed-UA curl, ticket theft/replay),
and any locally installed automation / anti-detect frameworks against a live
VeilBreak server (`benchmarks/bench_server.js`).

Pass `--write` (or `--out <path>`) to write JSON results without clobbering
tracked `benchmarks/results.json` by default.
"""
import argparse
import hashlib
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
PKG_VERSION = json.loads((REPO_ROOT / "package.json").read_text(encoding="utf-8")).get("version", "2.1.0")
PORT = int(os.environ.get("VB_BENCH_PORT", "18995"))
MODE = os.environ.get("VB_BENCH_MODE", "strict")
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


def _http_json(url: str, headers: dict[str, str]):
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw}


def test_http_scrapers():
    out = []
    # Tier 1a: Raw curl / Python urllib
    status, body = _http_json(f"{BASE}api/secret", {"User-Agent": "curl/8.5.0"})
    out.append({
        "label": "curl_http_scraper",
        "status": "OK",
        "category": "Tier 1: HTTP Scraper",
        "name": "curl / Python urllib (raw)",
        "stage1": {
            "blocked": status >= 400,
            "score": body.get("score", 6),
            "threshold": body.get("threshold", 2),
            "reasons": body.get("reasons", [body.get("error", "BLOCKED")]),
            "wcStatus": "n/a",
            "apiPassiveStatus": status,
            "apiPassiveOk": status == 200,
        },
        "stage2": None,
        "probeMs": 0.0,
    })

    # Tier 1b: Spoofed Chrome UA curl trying /__veilbreak/ticket + forged VB_ATTEST_V2 (no Sec-Fetch / no PoW)
    spoof_ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36"
    t_status, t_body = _http_json(f"{BASE}__veilbreak/ticket", {"User-Agent": spoof_ua})
    if t_status == 200 and t_body.get("ticket"):
        tk = t_body["ticket"]
        d = hashlib.sha256(f"VB_ATTEST_V2|{tk}|nonce1234|0|0|Linux x86_64".encode()).hexdigest()
        a_status, a_body = _http_json(
            f"{BASE}api/secret",
            {
                "User-Agent": spoof_ua,
                "X-VB-Ticket": tk,
                "X-VB-Nonce": "nonce1234",
                "X-VB-Attest": json.dumps({"v": 2, "s": 0, "f": 0, "p": "Linux x86_64", "d": d}),
            },
        )
    else:
        a_status, a_body = t_status, t_body
    out.append({
        "label": "curl_spoofed_ua",
        "status": "OK",
        "category": "Tier 1b: Spoofed HTTP Client",
        "name": "Spoofed-UA curl (/ticket + forged V2)",
        "stage1": {
            "blocked": a_status >= 400,
            "score": a_body.get("score", 6),
            "threshold": a_body.get("threshold", 2),
            "reasons": a_body.get("reasons", [a_body.get("error", "BLOCKED")]),
            "wcStatus": "n/a",
            "apiPassiveStatus": a_status,
            "apiPassiveOk": a_status == 200,
        },
        "stage2": None,
        "probeMs": 0.0,
    })
    return out


def run_human_control_browser(out_dir: Path, label: str, name: str, is_firefox: bool):
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
for i in $(seq 1 50); do
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
for i in $(seq 1 20); do
  if grep -q '"stage2":{' "{out_dir}/{label}.json" 2>/dev/null; then break; fi
  sleep 0.25
done
kill $BPID 2>/dev/null || true
wait $BPID 2>/dev/null || true
"""
    try:
        subprocess.run(
            [XVFB_BIN, "-a", "-s", "-screen 0 1366x768x24", "bash", "-c", script],
            timeout=45,
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
    timeout: int = 55,
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

    full_err = r.stderr or ""
    missing_markers = (
        "ModuleNotFoundError",
        "MODULE_NOT_FOUND",
        "No module named",
        "Executable doesn't exist",
        "Could not find Chrome",
        "Failed to launch the browser process",
    )
    if any(m in full_err for m in missing_markers):
        return {"label": label, "status": "SKIPPED_MISSING_TOOL", "category": category, "name": name, "note": full_err.strip()[-240:]}
    return {
        "label": label,
        "status": "ERROR",
        "category": category,
        "name": name,
        "note": f"Process exited rc={r.returncode} without producing benchmark output: {full_err.strip()[-240:]}",
    }


def wait_server_ready(proc: subprocess.Popen, timeout: float = 10.0) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        line = proc.stdout.readline() if proc.stdout else ""
        if "VB_BENCH_READY" in line:
            return
        if proc.poll() is not None:
            raise RuntimeError(f"bench_server.js exited early with rc={proc.returncode}")
        time.sleep(0.05)
    raise TimeoutError("Timed out waiting for bench_server.js VB_BENCH_READY")


def main():
    parser = argparse.ArgumentParser(description="VeilBreak Live Multi-Browser Benchmark Runner")
    parser.add_argument("--write", action="store_true", help="Write results to benchmarks/results.json")
    parser.add_argument("--out", type=str, default=None, help="Write results to a custom JSON path")
    args = parser.parse_args()

    out_dir = Path(tempfile.mkdtemp(prefix="veilbreak_bench_runs_"))
    srv_log = out_dir / "bench_server.err.log"
    srv_env = dict(os.environ, VB_BENCH_PORT=str(PORT), VB_BENCH_OUT=str(out_dir), VB_BENCH_MODE=MODE)
    with srv_log.open("w", encoding="utf-8") as err_fp:
        srv = subprocess.Popen(
            ["node", str(REPO_ROOT / "benchmarks" / "bench_server.js")],
            stdout=subprocess.PIPE,
            stderr=err_fp,
            text=True,
            env=srv_env,
        )
        try:
            wait_server_ready(srv, timeout=10.0)
            results = []
            chrome_arg = f"executable_path={json.dumps(CHROME_BIN)}, " if CHROME_BIN else ""

            results.append(run_human_control_browser(out_dir, "ctrl_chrome", "Google Chrome (Clean Desktop)", is_firefox=False))
            results.append(run_human_control_browser(out_dir, "ctrl_firefox", "Mozilla Firefox (Clean Desktop)", is_firefox=True))
            results.extend(test_http_scrapers())

            pw_wait = """
    if resp and resp.status == 200:
        try: page.wait_for_function("document.getElementById('state')?.textContent === 'STAGE1_DONE'", timeout=15000)
        except Exception: pass
        try: page.click("#vb-btn", timeout=4000)
        except Exception: pass
        try: page.wait_for_function("document.getElementById('state')?.textContent === 'STAGE2_DONE'", timeout=10000)
        except Exception: pass
"""

            for lbl, nm, eng, headed in [
                ("pw_chromium_headless", "Playwright Chromium (Headless)", f"p.chromium.launch({chrome_arg}headless=True)", False),
                ("pw_chromium_headed", "Playwright Chromium (Headed)", f"p.chromium.launch({chrome_arg}headless=False)", True),
                ("pw_firefox_headless", "Playwright Firefox (Headless)", "p.firefox.launch(headless=True)", False),
                ("pw_firefox_headed", "Playwright Firefox (Headed)", "p.firefox.launch(headless=False)", True),
            ]:
                results.append(run_browser_case(
                    out_dir, lbl, "Tier 2: Standard Automation", nm,
                    f"""
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = {eng}
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="domcontentloaded", timeout=20000)
{pw_wait}
    b.close()
""", xvfb=headed))

            results.append(run_browser_case(
                out_dir, "pw_stealth", "Tier 3: JS Stealth Plugin", "Playwright + playwright-stealth",
                f"""
import playwright_stealth
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
    resp = page.goto("{BASE}?label=pw_stealth", wait_until="domcontentloaded", timeout=20000)
{pw_wait}
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
  const r = await p.goto("{BASE}?label=puppeteer_stealth", {{ waitUntil: "domcontentloaded" }});
  if (r && r.status() === 200) {{
    try {{ await p.waitForFunction(() => document.getElementById("state")?.textContent === "STAGE1_DONE", {{ timeout: 15000 }}); }} catch {{}}
    try {{ await p.click("#vb-btn"); }} catch {{}}
    try {{ await p.waitForFunction(() => document.getElementById("state")?.textContent === "STAGE2_DONE", {{ timeout: 10000 }}); }} catch {{}}
  }}
  await b.close();
}})();
"""))

            for headed in (False, True):
                lbl = f"cloakbrowser_{'headed' if headed else 'headless'}"
                results.append(run_browser_case(
                    out_dir, lbl, "Tier 4a: C++-Patched Chromium", f"CloakBrowser ({'Headed' if headed else 'Headless'})",
                    f"""
import cloakbrowser
b = cloakbrowser.launch(headless={not headed})
page = b.new_page()
resp = page.goto("{BASE}?label={lbl}", wait_until="domcontentloaded", timeout=20000)
{pw_wait}
b.close()
""", xvfb=headed))

            for headed in (False, True):
                lbl = f"camoufox_{'headed' if headed else 'headless'}"
                results.append(run_browser_case(
                    out_dir, lbl, "Tier 4a: C++-Patched Firefox", f"Camoufox ({'Headed' if headed else 'Headless'})",
                    f"""
from camoufox.sync_api import Camoufox
with Camoufox(headless={not headed}) as b:
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="domcontentloaded", timeout=25000)
{pw_wait}
""", xvfb=headed))

            for headed in (False, True):
                lbl = f"patchright_{'headed' if headed else 'headless'}"
                results.append(run_browser_case(
                    out_dir, lbl, "Tier 4b: CDP-Patched Stealth", f"Patchright ({'Headed' if headed else 'Headless'})",
                    f"""
from patchright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch({chrome_arg}headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="domcontentloaded", timeout=20000)
{pw_wait}
    b.close()
""", xvfb=headed))

            for headed in (False, True):
                lbl = f"rebrowser_{'headed' if headed else 'headless'}"
                results.append(run_browser_case(
                    out_dir, lbl, "Tier 4b: CDP-Patched Stealth", f"Rebrowser-Playwright ({'Headed' if headed else 'Headless'})",
                    f"""
import os
os.environ["REBROWSER_PATCHES_RUNTIME_FIX_MODE"] = "addBinding"
from rebrowser_playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch({chrome_arg}headless={not headed})
    page = b.new_page()
    resp = page.goto("{BASE}?label={lbl}", wait_until="domcontentloaded", timeout=20000)
{pw_wait}
    b.close()
""", xvfb=headed))

            sb_bin_arg = f", binary_location={json.dumps(CHROME_BIN)}" if CHROME_BIN else ""
            results.append(run_browser_case(
                out_dir, "seleniumbase_uc", "Tier 4b: CDP-Patched Stealth", "SeleniumBase UC Mode (Headed)",
                f"""
import time
from seleniumbase import SB
with SB(uc=True, headless=False{sb_bin_arg}) as sb:
    sb.uc_open("{BASE}?label=seleniumbase_uc")
    for _ in range(30):
        if sb.get_text("#state") == "STAGE1_DONE": break
        time.sleep(0.3)
    try: sb.uc_click("#vb-btn")
    except Exception: pass
    for _ in range(20):
        if sb.get_text("#state") == "STAGE2_DONE": break
        time.sleep(0.3)
""", xvfb=True, timeout=60))

            nd_bin_arg = f"browser_executable_path={json.dumps(CHROME_BIN)}, " if CHROME_BIN else ""
            results.append(run_browser_case(
                out_dir, "nodriver_headed", "Tier 4b: Raw-CDP Stealth", "Nodriver (Headed)",
                f"""
import asyncio, nodriver as uc
async def main():
    b = await uc.start({nd_bin_arg}headless=False, sandbox=False)
    p = await b.get("{BASE}?label=nodriver_headed")
    for _ in range(30):
        st = await p.evaluate("document.getElementById('state')?.textContent || ''")
        if st == "STAGE1_DONE": break
        await asyncio.sleep(0.3)
    try:
        btn = await p.select("#vb-btn")
        await btn.click()
    except Exception:
        pass
    for _ in range(20):
        st = await p.evaluate("document.getElementById('state')?.textContent || ''")
        if st == "STAGE2_DONE": break
        await asyncio.sleep(0.3)
    b.stop()
asyncio.run(main())
""", xvfb=True))

            if args.write or args.out:
                out_json = Path(args.out).resolve() if args.out else (REPO_ROOT / "benchmarks" / "results.json")
                out_json.write_text(json.dumps({
                    "version": PKG_VERSION,
                    "mode": MODE,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "results": results,
                }, indent=2) + "\n", encoding="utf-8")

            print("\n" + "=" * 116)
            print(f"{'Browser / Tool':42s} | {'Status':12s} | {'Stage-1':12s} | {'Stage-2 Click':14s} | {'Reasons'}")
            print("-" * 116)
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
            print("=" * 116)
        finally:
            srv.terminate()
            try:
                srv.wait(timeout=3)
            except subprocess.TimeoutExpired:
                srv.kill()
            shutil.rmtree(out_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
