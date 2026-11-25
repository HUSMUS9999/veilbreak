"""
VeilBreak Python Verifier & One-Time Ticket Store (Zero Dependencies, Python >= 3.10).
Wire- and validation-compatible with the VeilBreak v2 browser SDK (`VB_ATTEST_V2|` SHA-256 envelope).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
import time
from dataclasses import dataclass, field

FLAG_REASON_MAP: tuple[tuple[int, str], ...] = (
    (1 << 0, "CANVAS2D_SYNTHETIC_NOISE"),
    (1 << 1, "WEBGL_CLEAR_SYNTHETIC_NOISE"),
    (1 << 2, "SILENT_AUDIO_SYNTHETIC_NOISE"),
    (1 << 3, "DOMRECT_SUBPIXEL_POISONING"),
    (1 << 4, "OS_CORE_FONT_LIE"),
    (1 << 5, "WEBGL_HARDWARE_COHERENCE_LIE"),
    (1 << 6, "WEBDRIVER_FLAG"),
    (1 << 7, "CDP_RUNTIME_ENABLE"),
    (1 << 8, "AUTOMATION_GLOBAL_ARTIFACT"),
    (1 << 9, "WEBDRIVER_GETTER_SPOOFED"),
    (1 << 10, "NATIVE_FUNCTION_TAMPERED"),
    (1 << 11, "WORKER_REALM_CONTRADICTION"),
    (1 << 12, "VIEWPORT_GEOMETRY_IMPOSSIBILITY"),
    (1 << 13, "ENGINE_COHERENCE_LIE"),
    (1 << 14, "SYNTHETIC_INTERACTION"),
)

_DEFINED_FLAG_MASK = 0x7FFF
_FLAG_MIN_WEIGHTS: tuple[int, ...] = (2, 2, 2, 2, 2, 2, 4, 4, 4, 4, 4, 4, 2, 2, 4)


def _min_score_for_flags(flags: int) -> int:
    return sum(w for i, w in enumerate(_FLAG_MIN_WEIGHTS) if (flags & (1 << i)) != 0)


def decode_flags(flags: int) -> list[str]:
    return [name for bit, name in FLAG_REASON_MAP if (flags & bit) != 0]


@dataclass
class VeilBreakVerdict:
    ok: bool
    blocked: bool
    score: int
    threshold: int | float
    mode: str
    reasons: list[str] = field(default_factory=list)


def _normalize_mode(mode: str | None) -> str:
    m = str("strict" if mode is None else mode).strip().lower()
    if m not in ("off", "monitor", "observe", "balanced", "strict"):
        raise ValueError(f"Unsupported VeilBreak mode: {mode}")
    return "monitor" if m == "observe" else m


def _normalize_headers(headers: dict | None) -> dict[str, str]:
    if not isinstance(headers, dict):
        return {}
    out: dict[str, str] = {}
    for k, v in headers.items():
        kl = str(k).lower()
        if kl in out:
            continue  # first-key precedence matches Node.js getHeader
        if isinstance(v, (list, tuple)):
            out[kl] = ", ".join("" if x is None else str(x) for x in v)
        else:
            out[kl] = "" if v is None else str(v)
    return out


def verify_attestation(
    *,
    mode: str | None = "strict",
    headers: dict | None,
    attest: dict | str | None,
    ticket: str = "",
    nonce: str = "",
) -> VeilBreakVerdict:
    m = _normalize_mode(mode)
    threshold: int | float = 2 if m == "strict" else (4 if m == "balanced" else math.inf)
    if m == "off":
        return VeilBreakVerdict(True, False, 0, threshold, m)

    hdr = _normalize_headers(headers)
    ua = hdr.get("user-agent", "")
    sec_ch_ua = hdr.get("sec-ch-ua", "")
    sec_plat = hdr.get("sec-ch-ua-platform", "").replace('"', "").lower()
    reasons: list[str] = []
    score = 0

    if m in ("strict", "balanced") and (
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

    att_obj = attest
    if isinstance(att_obj, str):
        stripped = att_obj.strip()
        if not stripped:
            att_obj = None
        else:
            try:
                att_obj = json.loads(stripped)
            except Exception:
                att_obj = {"invalid": True}

    tk_str = "" if ticket is None else str(ticket)
    nn_str = "" if nonce is None else str(nonce)

    if att_obj is None:
        if m in ("strict", "balanced"):
            reasons.append("ATTEST_REQUIRED")
            score += 6
    elif not isinstance(att_obj, dict):
        reasons.append("ATTEST_INVALID")
        score += 6
    else:
        has_v = "v" in att_obj
        v = att_obj.get("v")
        s = att_obj.get("s")
        f = att_obj.get("f")
        p_raw = att_obj.get("p")
        p = ("" if p_raw is None else str(p_raw))[:48]
        d = att_obj.get("d") if isinstance(att_obj.get("d"), str) else ""

        valid_v = (not has_v) or (isinstance(v, int) and not isinstance(v, bool) and v == 2)
        valid_nums = (
            valid_v
            and isinstance(s, int)
            and not isinstance(s, bool)
            and 0 <= s <= 10_000
            and isinstance(f, int)
            and not isinstance(f, bool)
            and 0 <= f <= _DEFINED_FLAG_MASK
        )
        valid_delims = ("|" not in tk_str) and ("|" not in nn_str) and ("|" not in p)
        valid_hex = bool(re.fullmatch(r"[0-9a-fA-F]{64}", d))
        coherent_flag_score = valid_nums and (s >= _min_score_for_flags(f))

        if not (valid_nums and valid_delims and valid_hex and coherent_flag_score):
            reasons.append("ATTEST_INVALID")
            score += 6
        else:
            expected = hashlib.sha256(f"VB_ATTEST_V2|{tk_str}|{nn_str}|{s}|{f}|{p}".encode("utf-8")).hexdigest()
            if not hmac.compare_digest(d.lower(), expected):
                reasons.append("ATTEST_DIGEST_MISMATCH")
                score += 6
            score += s
            for rname in decode_flags(f):
                if rname not in reasons:
                    reasons.append(rname)
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


class VeilBreakTicketStore:
    """
    Zero-dependency one-time ticket store & request verifier for FastAPI/Flask/Django,
    providing full replay-protection parity with the Node.js VeilBreak middleware.
    """

    def __init__(self, *, mode: str = "strict", ticket_ttl_ms: int = 60_000, max_tickets: int = 30_000) -> None:
        self.mode = _normalize_mode(mode)
        if not isinstance(ticket_ttl_ms, (int, float)) or isinstance(ticket_ttl_ms, bool) or ticket_ttl_ms <= 0:
            raise ValueError("ticket_ttl_ms must be a positive number")
        if not isinstance(max_tickets, int) or isinstance(max_tickets, bool) or max_tickets < 1:
            raise ValueError("max_tickets must be a positive integer")
        self.ticket_ttl_ms = ticket_ttl_ms
        self.max_tickets = max_tickets
        self._tickets: dict[str, float] = {}

    def mint_ticket(self) -> str | None:
        now = time.time() * 1000.0
        if len(self._tickets) >= self.max_tickets:
            expired = [k for k, exp in self._tickets.items() if exp <= now]
            for k in expired:
                self._tickets.pop(k, None)
            # Refuse minting at capacity instead of evicting live active tickets (MED-22)
            if len(self._tickets) >= self.max_tickets:
                return None
        tk = secrets.token_hex(16)
        self._tickets[tk] = now + float(self.ticket_ttl_ms)
        return tk

    def consume_ticket(self, ticket: str) -> bool:
        if not ticket:
            return False
        now = time.time() * 1000.0
        exp = self._tickets.pop(ticket, None)
        return exp is not None and exp > now

    def verify_request(self, *, headers: dict | None) -> VeilBreakVerdict:
        hdr = _normalize_headers(headers)
        ticket = hdr.get("x-vb-ticket", "")
        nonce = hdr.get("x-vb-nonce", "")
        attest = hdr.get("x-vb-attest")
        ticket_ok = self.consume_ticket(ticket)
        verdict = verify_attestation(mode=self.mode, headers=hdr, attest=attest, ticket=ticket, nonce=nonce)
        if self.mode in ("strict", "balanced") and not ticket_ok:
            verdict.blocked = True
            verdict.ok = False
            verdict.score += 6
            verdict.reasons.append("TICKET_REPLAYED_OR_INVALID")
        return verdict
