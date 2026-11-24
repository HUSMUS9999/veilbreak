"""
VeilBreak Python Verifier (Zero Dependencies, Python >= 3.10).
Wire-compatible with the VeilBreak v2 browser SDK (`VB_ATTEST_V2|` SHA-256 attestation).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from dataclasses import dataclass, field


@dataclass
class VeilBreakVerdict:
    ok: bool
    blocked: bool
    score: int
    threshold: int
    mode: str
    reasons: list[str] = field(default_factory=list)


def verify_attestation(
    *,
    mode: str = "strict",
    headers: dict[str, str],
    attest: dict | str | None,
    ticket: str = "",
    nonce: str = "",
) -> VeilBreakVerdict:
    m = mode.strip().lower()
    if m not in ("off", "monitor", "balanced", "strict"):
        raise ValueError(f"Unsupported VeilBreak mode: {mode}")
    threshold = 2 if m == "strict" else (4 if m == "balanced" else 999)
    if m == "off":
        return VeilBreakVerdict(True, False, 0, threshold, m)

    hdr = {k.lower(): v for k, v in headers.items()}
    ua = hdr.get("user-agent", "")
    sec_ch_ua = hdr.get("sec-ch-ua", "")
    sec_plat = hdr.get("sec-ch-ua-platform", "").replace('"', "").lower()
    reasons: list[str] = []
    score = 0

    if m == "strict" and (
        re.search(r"HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS", ua, re.I)
        or re.search(r"HeadlessChrome", sec_ch_ua, re.I)
    ):
        reasons.append("AUTOMATION_UA_DENIED")
        score += 6

    ua_linux = "Linux" in ua and "Android" not in ua
    ua_win = "Windows NT" in ua
    ua_mac = "Macintosh" in ua
    if sec_plat:
        if (
            (ua_linux and sec_plat in ("windows", "macos"))
            or (ua_win and sec_plat in ("linux", "macos"))
            or (ua_mac and sec_plat in ("windows", "linux"))
        ):
            reasons.append("OS_HEADER_CONTRADICTION")
            score += 4

    chrome_ver = re.search(r"Chrome/(\d+)", ua)
    if chrome_ver and int(chrome_ver.group(1)) >= 115 and '" Not A;Brand";v="99"' in sec_ch_ua:
        reasons.append("SEC_CH_UA_GREASE_LIE")
        score += 2

    if isinstance(attest, str):
        try:
            attest = json.loads(attest)
        except Exception:
            attest = {"invalid": True}

    if not isinstance(attest, dict):
        if m == "strict":
            reasons.append("ATTEST_REQUIRED")
            score += 6
    else:
        s = attest.get("s")
        f = attest.get("f")
        p = str(attest.get("p", ""))[:48]
        d = str(attest.get("d", ""))
        if (
            not isinstance(s, int)
            or isinstance(s, bool)
            or s < 0
            or not isinstance(f, int)
            or isinstance(f, bool)
            or f < 0
            or len(d) != 64
        ):
            reasons.append("ATTEST_INVALID")
            score += 6
        else:
            expected = hashlib.sha256(f"VB_ATTEST_V2|{ticket}|{nonce}|{s}|{f}|{p}".encode("utf-8")).hexdigest()
            if not hmac.compare_digest(d, expected):
                reasons.append("ATTEST_DIGEST_MISMATCH")
                score += 6
            score += s
            if s >= threshold:
                reasons.append("BROWSER_INVARIANTS_FAILED")
            if (
                (ua_linux and (p.startswith("Win") or p == "MacIntel"))
                or (ua_win and (p.startswith("Linux") or p == "MacIntel"))
                or (ua_mac and (p.startswith("Win") or p.startswith("Linux")))
            ):
                reasons.append("OS_PLATFORM_CONTRADICTION")
                score += 4

    hard_fail = any(
        r in reasons
        for r in ("ATTEST_REQUIRED", "ATTEST_INVALID", "ATTEST_DIGEST_MISMATCH", "AUTOMATION_UA_DENIED")
    )
    blocked = m != "monitor" and (score >= threshold or hard_fail)
    return VeilBreakVerdict(not blocked, blocked, score, threshold, m, reasons)
