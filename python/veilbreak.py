"""
VeilBreak Python Verifier & One-Time Ticket Store (Zero Dependencies, Python >= 3.10).
Wire- and validation-compatible with the VeilBreak v2.1 browser SDK:
  - IP + UA + SHA-256 PoW + method/path-bound one-time tickets (`VB_ATTEST_V2|`)
  - CLI/proxy/automation UA + Fetch Metadata + smuggling checks
  - Path normalization parity with Node.js middleware (`normalize_pathname`, `is_path_protected`)
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import posixpath
import re
import secrets
import threading
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

_AUTOMATION_OR_CLI_UA_RE = re.compile(
    r"HeadlessChrome|Playwright|Puppeteer|PhantomJS|SlimerJS|curl/|wget/|"
    r"python-requests|python-urllib|python-httpx|aiohttp|go-http-client|httpie|"
    r"libwww-perl|java/|okhttp|axios/|node-fetch|undici|burp|caido|mitmproxy|"
    r"insomnia|postman|sqlmap|ffuf|nuclei",
    re.I,
)

_PROXY_LEAK_HEADERS = (
    "proxy-connection",
    "x-burp-header",
    "x-burp-collaborator",
    "x-caido-id",
    "x-caido-replay",
    "x-mitmproxy",
)

_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _min_score_for_flags(flags: int) -> int:
    return sum(w for i, w in enumerate(_FLAG_MIN_WEIGHTS) if (flags & (1 << i)) != 0)


def decode_flags(flags: int) -> list[str]:
    return [name for bit, name in FLAG_REASON_MAP if (flags & bit) != 0]


def _sha256_bytes(s: str) -> bytes:
    return hashlib.sha256(str(s or "").encode("utf-8")).digest()


def _sha256_hex(s: str) -> str:
    return _sha256_bytes(s).hex()


def _count_leading_zero_bits(buf: bytes) -> int:
    bits = 0
    for byte in buf:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def verify_pow_solution(ticket: str, challenge: str, pow_nonce: str, difficulty: int) -> bool:
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or difficulty <= 0:
        return True
    if not ticket or not challenge or not isinstance(pow_nonce, str):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pow_nonce):
        return False
    digest = _sha256_bytes(f"VB_POW_V2|{ticket}|{challenge}|{pow_nonce}")
    return _count_leading_zero_bits(digest) >= difficulty


def solve_pow_challenge(ticket: str, challenge: str, difficulty: int) -> str:
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or difficulty <= 0:
        return "0"
    for i in range(10_000_000):
        nonce = format(i, "x")
        if _count_leading_zero_bits(_sha256_bytes(f"VB_POW_V2|{ticket}|{challenge}|{nonce}")) >= difficulty:
            return nonce
    raise RuntimeError("VB_POW_SOLVE_EXCEEDED_LIMIT")


def _normalize_ip(ip: str) -> str:
    s = str(ip or "").strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return "127.0.0.1" if s == "::1" else s


def _decode_percent_lenient(s: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        run = match.group(0)
        out: list[str] = []
        i = 0
        n_run = len(run)
        while i < n_run:
            b = int(run[i + 1 : i + 3], 16)
            if b == 0x00:
                out.append("\0")
                i += 3
                continue
            if 0x01 <= b <= 0x7F:
                out.append(chr(b))
                i += 3
                continue
            matched = False
            for seq_len in (2, 3, 4):
                if i + seq_len * 3 <= n_run:
                    raw_bytes = bytes(
                        int(run[i + k * 3 + 1 : i + k * 3 + 3], 16) for k in range(seq_len)
                    )
                    try:
                        out.append(raw_bytes.decode("utf-8", errors="strict"))
                        i += seq_len * 3
                        matched = True
                        break
                    except UnicodeDecodeError:
                        pass
            if not matched:
                out.append(run[i : i + 3])
                i += 3
        return "".join(out)

    return _PCT_RUN_RE.sub(_repl, s)


def _strip_scheme_and_authority(raw_url: str) -> str:
    s = str(raw_url or "/").lstrip()
    if not s:
        return "/"
    if re.match(r"^https?://", s, re.I):
        after = s.find("://") + 3
        cuts = [
            idx
            for idx in (s.find("/", after), s.find("\\", after), s.find("?", after), s.find("#", after))
            if idx >= 0
        ]
        if not cuts:
            return "/"
        first = min(cuts)
        if s[first] == "/":
            s = s[first:]
        elif s[first] == "\\":
            s = "/" + s[first + 1 :]
        else:
            s = "/" + s[first:]
    return s


def _clean_path_no_collapse(raw_path: str) -> str:
    s = str(raw_path or "/").replace("\\", "/").split("\0", 1)[0]
    if not s.startswith("/"):
        s = "/" + s
    s = "/".join(seg.split(";", 1)[0] for seg in s.split("/"))
    s = re.sub(r"/+", "/", s)
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def _trim_segment_noise(norm_path: str) -> str:
    s = "/".join(re.sub(r"[\s.]+$", "", seg) for seg in str(norm_path or "/").split("/"))
    s = re.sub(r"/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def normalize_pathname(raw_url: str) -> str:
    s = _strip_scheme_and_authority(raw_url)
    q_idx = s.find("?")
    if q_idx >= 0:
        s = s[:q_idx]
    if not s:
        return "/"
    for _ in range(2):
        dec = _decode_percent_lenient(s)
        if dec == s:
            break
        s = dec
    s = s.replace("\0", "").replace("\\", "/")
    if not s.startswith("/"):
        s = "/" + s
    s = "/".join(seg.split(";", 1)[0] for seg in s.split("/"))
    s = posixpath.normpath(s)
    s = re.sub(r"^/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    if len(s) > 1:
        s = s.rstrip("/")
    s = s.replace("?", "%3F")
    return s


def _expand_path_candidates(raw_url: str) -> list[str]:
    raw = _strip_scheme_and_authority(raw_url)
    q_idx = raw.find("?")
    raw_path = raw[:q_idx] if q_idx >= 0 else raw
    seen: list[str] = []

    def _add(val: str) -> None:
        n1 = normalize_pathname(val)
        n2 = _clean_path_no_collapse(val)
        for cand in (n1, n2, _trim_segment_noise(n1), _trim_segment_noise(n2)):
            if cand not in seen:
                seen.append(cand)

    _add(raw_path)
    raw_h = raw_path.find("#")
    if raw_h >= 0:
        _add(raw_path[:raw_h])
    dec = raw_path
    for _ in range(2):
        nxt = _decode_percent_lenient(dec)
        if nxt == dec:
            break
        dec = nxt
    _add(dec)
    null_idx = dec.find("\0")
    if null_idx >= 0:
        _add(dec[:null_idx])
    dec_q = dec.find("?")
    if dec_q >= 0:
        _add(dec[:dec_q])
    dec_h = dec.find("#")
    if dec_h >= 0:
        _add(dec[:dec_h])
    return seen


def is_path_protected(raw_url: str, protected_paths: list[str | re.Pattern] | None = None) -> bool:
    rules = protected_paths or ["/api"]
    for norm in _expand_path_candidates(raw_url):
        low = norm.lower()
        for rule in rules:
            if isinstance(rule, re.Pattern):
                if rule.search(norm):
                    return True
            else:
                raw_rule = str(rule).strip()
                if raw_rule == "*":
                    return True
                rl = normalize_pathname(raw_rule).lower()
                if rl == "/" or low == rl or low.startswith(rl if rl.endswith("/") else rl + "/"):
                    return True
    return False


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
            continue
        if isinstance(v, (list, tuple)):
            out[kl] = ", ".join("" if x is None else str(x) for x in v)
        else:
            out[kl] = "" if v is None else str(v)
    return out


def is_automation_or_cli_ua(headers: dict | None) -> bool:
    hdr = _normalize_headers(headers)
    ua = hdr.get("user-agent", "").strip()
    sec_ch = hdr.get("sec-ch-ua", "")
    if not ua:
        return True
    return bool(_AUTOMATION_OR_CLI_UA_RE.search(ua) or re.search(r"HeadlessChrome", sec_ch, re.I))


def verify_attestation(
    *,
    mode: str | None = "strict",
    headers: dict | None,
    attest: dict | str | None,
    ticket: str = "",
    nonce: str = "",
    expected_challenge: str = "",
    expected_difficulty: int = 0,
    expected_method: str = "",
    expected_path: str = "",
    require_fetch_metadata: bool = False,
) -> VeilBreakVerdict:
    m = _normalize_mode(mode)
    threshold: int | float = 2 if m == "strict" else (4 if m == "balanced" else math.inf)
    if m == "off":
        return VeilBreakVerdict(True, False, 0, threshold, m)

    hdr = _normalize_headers(headers)
    ua = hdr.get("user-agent", "")
    sec_ch_ua = hdr.get("sec-ch-ua", "")
    sec_plat = hdr.get("sec-ch-ua-platform", "").replace('"', "").lower()
    sfs = hdr.get("sec-fetch-site", "").strip().lower()
    sfm = hdr.get("sec-fetch-mode", "").strip().lower()
    reasons: list[str] = []
    score = 0

    if hdr.get("content-length") and hdr.get("transfer-encoding"):
        reasons.append("CL_TE_SMUGGLING")
        score += 10
    if any(ph in hdr for ph in _PROXY_LEAK_HEADERS):
        reasons.append("PROXY_HEADER_LEAK")
        score += 6

    is_cli = is_automation_or_cli_ua(hdr)
    if m in ("strict", "balanced") and is_cli:
        reasons.append("AUTOMATION_UA_DENIED")
        score += 6

    if "cross-site" in sfs:
        reasons.append("CROSS_SITE_REQUEST_DENIED")
        score += 6

    chrome_ver = re.search(r"Chrome/(\d+)", ua, re.I)
    ff_ver = re.search(r"Firefox/(\d+)", ua, re.I)
    claims_modern = (chrome_ver is not None and int(chrome_ver.group(1)) >= 80) or (
        ff_ver is not None and int(ff_ver.group(1)) >= 90
    )
    if require_fetch_metadata and claims_modern and not is_cli:
        if not sfs or sfs not in ("same-origin", "same-site") or not sfm:
            reasons.append("FETCH_METADATA_MISSING")
            score += 4

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
    exp_chal = "" if expected_challenge is None else str(expected_challenge)
    exp_diff = (
        expected_difficulty
        if isinstance(expected_difficulty, int) and not isinstance(expected_difficulty, bool) and expected_difficulty > 0
        else 0
    )
    exp_method = str(expected_method or "").strip().upper()
    exp_path = normalize_pathname(expected_path) if expected_path else ""

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
        w = "" if att_obj.get("w") is None else str(att_obj.get("w"))
        att_m = "" if att_obj.get("m") is None else str(att_obj.get("m")).strip().upper()
        att_u = "" if att_obj.get("u") is None else str(att_obj.get("u"))

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
        valid_delims = all("|" not in x for x in (tk_str, nn_str, p, w, att_m, att_u))
        valid_hex = bool(re.fullmatch(r"[0-9a-fA-F]{64}", d))
        coherent_flag_score = valid_nums and (s >= _min_score_for_flags(f))
        valid_nonce = (not exp_chal) or bool(re.fullmatch(r"[A-Za-z0-9_-]{8,64}", nn_str))

        if not (valid_nums and valid_delims and valid_hex and coherent_flag_score and valid_nonce):
            reasons.append("ATTEST_INVALID")
            score += 6
        else:
            if exp_chal:
                if exp_diff > 0 and not verify_pow_solution(tk_str, exp_chal, w, exp_diff):
                    reasons.append("POW_INVALID")
                    score += 6
                if exp_method and att_m != exp_method:
                    reasons.append("REQUEST_BINDING_MISMATCH")
                    score += 6
                if exp_path and (not att_u or normalize_pathname(att_u) != exp_path):
                    if "REQUEST_BINDING_MISMATCH" not in reasons:
                        reasons.append("REQUEST_BINDING_MISMATCH")
                        score += 6
                expected = _sha256_hex(
                    f"VB_ATTEST_V2|{tk_str}|{nn_str}|{s}|{f}|{p}|{exp_chal}|{w}|{att_m}|{att_u}"
                )
            else:
                expected = _sha256_hex(f"VB_ATTEST_V2|{tk_str}|{nn_str}|{s}|{f}|{p}")

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
        for r in (
            "ATTEST_REQUIRED",
            "ATTEST_INVALID",
            "ATTEST_DIGEST_MISMATCH",
            "AUTOMATION_UA_DENIED",
            "POW_INVALID",
            "REQUEST_BINDING_MISMATCH",
            "CROSS_SITE_REQUEST_DENIED",
            "CL_TE_SMUGGLING",
            "PROXY_HEADER_LEAK",
        )
    )
    blocked = m != "monitor" and (score >= threshold or hard_fail)
    return VeilBreakVerdict(not blocked, blocked, score, threshold, m, reasons)


class VeilBreakTicketStore:
    """
    Zero-dependency IP + UA + SHA-256 PoW one-time ticket store & request verifier
    for FastAPI/Flask/Django, with full parity to the Node.js VeilBreak v2.1 middleware.
    """

    def __init__(
        self,
        *,
        mode: str = "strict",
        ticket_ttl_ms: int = 60_000,
        max_tickets: int = 30_000,
        ticket_pow_bits: int | None = None,
        bind_ip: bool = True,
        require_fetch_metadata: bool | None = None,
    ) -> None:
        self.mode = _normalize_mode(mode)
        if (
            not isinstance(ticket_ttl_ms, (int, float))
            or isinstance(ticket_ttl_ms, bool)
            or not math.isfinite(ticket_ttl_ms)
            or ticket_ttl_ms <= 0
        ):
            raise ValueError("ticket_ttl_ms must be a positive finite number")
        if not isinstance(max_tickets, int) or isinstance(max_tickets, bool) or max_tickets < 1:
            raise ValueError("max_tickets must be a positive integer")
        if ticket_pow_bits is None:
            self.ticket_pow_bits = 12 if self.mode == "strict" else (10 if self.mode == "balanced" else 0)
        else:
            if not isinstance(ticket_pow_bits, int) or isinstance(ticket_pow_bits, bool) or not (0 <= ticket_pow_bits <= 22):
                raise ValueError("ticket_pow_bits must be an integer in 0..22")
            self.ticket_pow_bits = ticket_pow_bits
        self.bind_ip = bool(bind_ip)
        self.require_fetch_metadata = (self.mode == "strict") if require_fetch_metadata is None else bool(require_fetch_metadata)
        self.ticket_ttl_ms = ticket_ttl_ms
        self.max_tickets = max_tickets
        self._tickets: dict[str, dict] = {}
        self._lock = threading.Lock()

    def mint_ticket_challenge(self, *, ip: str = "127.0.0.1", user_agent: str = "") -> dict | None:
        with self._lock:
            now = time.time() * 1000.0
            if len(self._tickets) >= self.max_tickets:
                expired = [k for k, rec in self._tickets.items() if rec["exp"] <= now]
                for k in expired:
                    self._tickets.pop(k, None)
                if len(self._tickets) >= self.max_tickets:
                    return None
            tk = secrets.token_hex(16)
            challenge = secrets.token_hex(16)
            self._tickets[tk] = {
                "exp": now + float(self.ticket_ttl_ms),
                "ip": _normalize_ip(ip),
                "ua_hash": _sha256_hex(user_agent),
                "challenge": challenge,
                "difficulty": self.ticket_pow_bits,
            }
            return {"ticket": tk, "challenge": challenge, "difficulty": self.ticket_pow_bits, "mode": self.mode}

    def mint_ticket(self, *, ip: str = "127.0.0.1", user_agent: str = "") -> str | None:
        """Legacy convenience helper returning only the ticket string (challenge/PoW disabled on that entry)."""
        with self._lock:
            now = time.time() * 1000.0
            if len(self._tickets) >= self.max_tickets:
                expired = [k for k, rec in self._tickets.items() if rec["exp"] <= now]
                for k in expired:
                    self._tickets.pop(k, None)
                if len(self._tickets) >= self.max_tickets:
                    return None
            tk = secrets.token_hex(16)
            self._tickets[tk] = {
                "exp": now + float(self.ticket_ttl_ms),
                "ip": _normalize_ip(ip),
                "ua_hash": _sha256_hex(user_agent) if user_agent else "",
                "challenge": "",
                "difficulty": 0,
            }
            return tk

    def consume_ticket(self, ticket: str) -> dict | None:
        if not ticket:
            return None
        with self._lock:
            now = time.time() * 1000.0
            rec = self._tickets.pop(ticket, None)
            if rec is None or rec["exp"] <= now:
                return None
            return rec

    def verify_request(
        self,
        *,
        headers: dict | None,
        ip: str = "127.0.0.1",
        method: str = "",
        path: str = "",
    ) -> VeilBreakVerdict:
        hdr = _normalize_headers(headers)
        ticket = hdr.get("x-vb-ticket", "")
        nonce = hdr.get("x-vb-nonce", "")
        attest = hdr.get("x-vb-attest")
        rec = self.consume_ticket(ticket)
        verdict = verify_attestation(
            mode=self.mode,
            headers=hdr,
            attest=attest,
            ticket=ticket,
            nonce=nonce,
            expected_challenge=rec["challenge"] if rec else "",
            expected_difficulty=rec["difficulty"] if rec else 0,
            expected_method=method if (rec and rec["challenge"]) else "",
            expected_path=path if (rec and rec["challenge"]) else "",
            require_fetch_metadata=self.require_fetch_metadata and bool(rec and rec["challenge"]),
        )
        if self.mode in ("strict", "balanced"):
            if not rec:
                verdict.blocked = True
                verdict.ok = False
                verdict.score += 6
                verdict.reasons.append("TICKET_REPLAYED_OR_INVALID")
            else:
                norm_ip = _normalize_ip(ip)
                ua_hash = _sha256_hex(hdr.get("user-agent", ""))
                ip_bad = self.bind_ip and rec["ip"] and rec["ip"] != norm_ip
                ua_bad = bool(rec["ua_hash"]) and not hmac.compare_digest(rec["ua_hash"], ua_hash)
                if ip_bad or ua_bad:
                    verdict.blocked = True
                    verdict.ok = False
                    verdict.score += 6
                    verdict.reasons.append("TICKET_BINDING_MISMATCH")
        return verdict
