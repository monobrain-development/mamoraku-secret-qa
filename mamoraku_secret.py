#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sys
import time
import unicodedata
import threading
import urllib.error
import urllib.request
from collections import Counter as _Counter
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

APP_DIR = Path(os.environ["MAMORAKU_APP_DIR"]) if os.environ.get("MAMORAKU_APP_DIR") else Path.home() / ".mamoraku-secret"
CLIENT_CONFIG_DIR = APP_DIR
CLIENT_CONFIG_FILE = CLIENT_CONFIG_DIR / "config.json"
FINDINGS_FILE = APP_DIR / "findings.jsonl"
FEEDBACK_FILE = APP_DIR / "feedback.jsonl"
WHITELIST_FILE = APP_DIR / "whitelist.json"
SESSION_ALLOW_FILE = APP_DIR / "session_allow.json"
PENDING_CHOICES_FILE = APP_DIR / "pending_choices.json"
AUTH_PROMPTED_FILE = APP_DIR / "auth_prompted_sessions.json"
PAUSE_FILE = APP_DIR / "pause.json"
DEVICE_SECRET_FILE = APP_DIR / "device_secret"
BUNDLED_RULES_FILE = Path(__file__).resolve().parent / "rules" / "bundled_rules.json"
RULES_CACHE_FILE = APP_DIR / "rules_cache.json"

_bundled_rules_raw: dict[str, Any] | None = None

DEFAULT_TOOL_ACTION = os.environ.get("SP_DEMO_TOOL_ACTION", "deny")  # deny | ask | alert
DEFAULT_PROMPT_ACTION = os.environ.get("SP_DEMO_PROMPT_ACTION", "block")  # block | alert
DEFAULT_API_BASE_URL = os.environ.get("SP_API_BASE_URL", "https://mamoraku-secret-api-954273464710.us-central1.run.app")

DEFAULT_REGEX_RULES = [
    {
        "id": "github_token",
        "name": "GitHub Token",
        "pattern": r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}\b",
        "severity": "high",
        "confidence": "high",
    },
    {
        "id": "aws_access_key_id",
        "name": "AWS Access Key ID",
        "pattern": r"\b(?:A3T[A-Z0-9]|ABIA|ACCA|AKIA|ASIA)[A-Z0-9]{16}\b",
        "severity": "high",
        "confidence": "high",
    },
]


DEFAULT_GLOBAL_SUPPRESSIONS = {
    "value_patterns": [
        {
            "id": "placeholder_angle_brackets",
            "pattern": r"^<[^>]+>$",
            "effect": "suppress",
            "applies_to": ["entropy"],
            "reason": "Placeholder value like <API_KEY>",
        },
        {
            "id": "placeholder_template_var",
            "pattern": r"^\$\{[^}]+\}$",
            "effect": "suppress",
            "applies_to": ["entropy"],
            "reason": "Template variable like ${TOKEN}",
        },
        {
            "id": "placeholder_repeated_x",
            "pattern": r"^x{8,}$",
            "effect": "suppress",
            "applies_to": ["entropy"],
            "reason": "Repeated x placeholder",
        },
        {
            "id": "placeholder_repeated_star",
            "pattern": r"^\*{8,}$",
            "effect": "suppress",
            "applies_to": ["entropy"],
            "reason": "Masked placeholder",
        },
        {
            "id": "placeholder_repeated_zero",
            "pattern": r"^0{8,}$",
            "effect": "suppress",
            "applies_to": ["entropy"],
            "reason": "Repeated zero placeholder",
        },
    ],
    "value_markers": [
        {
            "id": "dummy_marker",
            "marker": "dummy",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains dummy marker",
        },
        {
            "id": "example_marker",
            "marker": "example",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains example marker",
        },
        {
            "id": "sample_marker",
            "marker": "sample",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains sample marker",
        },
        {
            "id": "placeholder_marker",
            "marker": "placeholder",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains placeholder marker",
        },
        {
            "id": "changeme_marker",
            "marker": "changeme",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains changeme marker",
        },
        {
            "id": "fake_secret_marker",
            "marker": "fake_secret",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains fake_secret marker",
        },
        {
            "id": "your_api_key_marker",
            "marker": "your_api_key",
            "effect": "score_delta",
            "score_delta": -50,
            "applies_to": ["entropy"],
            "reason": "Contains your_api_key marker",
        },
    ],
}


def _load_bundled_rules() -> dict[str, Any]:
    """Read rules once per process. Prefer RULES_CACHE_FILE (API-fetched), fallback to BUNDLED_RULES_FILE."""
    global _bundled_rules_raw
    if _bundled_rules_raw is not None:
        return _bundled_rules_raw
    for path in (RULES_CACHE_FILE, BUNDLED_RULES_FILE):
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                _bundled_rules_raw = raw
                return _bundled_rules_raw
        except Exception:
            continue
    _bundled_rules_raw = {}
    return _bundled_rules_raw


def _refresh_rules_from_api() -> None:
    """Fetch /v1/rulesets/current and atomically update RULES_CACHE_FILE. Runs in background thread."""
    try:
        cfg = load_client_config()
        token = cfg.get("device_token") if isinstance(cfg.get("device_token"), str) else None
        if not token:
            return
        req = urllib.request.Request(
            f"{DEFAULT_API_BASE_URL}/v1/rulesets/current",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read().decode("utf-8")
        data = json.loads(body)
        if not isinstance(data, dict):
            return
        if not ("regex_rules" in data or "global_suppressions" in data):
            return
        APP_DIR.mkdir(parents=True, exist_ok=True)
        tmp = RULES_CACHE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        tmp.replace(RULES_CACHE_FILE)
    except Exception:
        pass


def load_regex_rules() -> list[dict[str, str]]:
    raw = _load_bundled_rules()
    rules = raw.get("regex_rules", []) if isinstance(raw, dict) else []
    out = []
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        if not all(k in rule for k in ["id", "name", "pattern", "severity", "confidence"]):
            continue
        out.append(rule)
    return out if out else DEFAULT_REGEX_RULES

TOKEN_RE = re.compile(r"\b[A-Za-z0-9_\-+=]{20,}\b")

@dataclass
class Evidence:
    detector: str
    start: int
    end: int
    line: int
    raw_value: str
    fingerprint: str
    score: int
    reasons: list[str]
    rule_id: str | None = None
    value_left_context: str = ""


@dataclass
class Finding:
    finding_id: str
    source: str
    session_key: str
    line: int
    fingerprint: str
    masked_value: str
    detectors: list[str]
    rule_ids: list[str]
    score: int
    confidence: str
    severity: str
    reasons: list[str]
    suggested_action: str
    value_left_context: str = ""


def ensure_app_dir() -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)


def ensure_client_config_dir() -> None:
    CLIENT_CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def load_client_config() -> dict[str, Any]:
    if not CLIENT_CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CLIENT_CONFIG_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_client_config(cfg: dict[str, Any]) -> None:
    ensure_client_config_dir()
    CLIENT_CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding="utf-8")


def is_authenticated_client() -> bool:
    cfg = load_client_config()
    token = cfg.get("device_token")
    return isinstance(token, str) and bool(token.strip())


def load_auth_prompted_sessions() -> set[str]:
    if not AUTH_PROMPTED_FILE.exists():
        return set()
    try:
        raw = json.loads(AUTH_PROMPTED_FILE.read_text(encoding="utf-8"))
        sessions = raw.get("sessions", []) if isinstance(raw, dict) else []
        return {s for s in sessions if isinstance(s, str) and s.strip()}
    except Exception:
        return set()


def save_auth_prompted_sessions(sessions: set[str]) -> None:
    ensure_app_dir()
    AUTH_PROMPTED_FILE.write_text(
        json.dumps({"sessions": sorted(sessions)}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def is_auth_prompted(session_key: str) -> bool:
    return session_key in load_auth_prompted_sessions()


def mark_auth_prompted(session_key: str) -> None:
    sessions = load_auth_prompted_sessions()
    sessions.add(session_key)
    save_auth_prompted_sessions(sessions)


def auth_prompt_message() -> str:
    return "\n".join([
        "Mamoraku Secret を有効化するにはログインが必要です。",
        "認証前はシークレット検知を実行しません。",
        "この案内はセッション開始時に1回だけ表示します。",
        "",
        "実行コマンド (推奨):",
        "  /mamoraku-secret:login",
        "",
        "unknown になる場合:",
        f"  mamoraku-secret login --max-wait 120",
        "",
        "not found の場合(PATH設定):",
        "  export PATH=\"$PWD/plugin/bin:$PATH\"",
    ])


def resolve_api_base_url(arg_value: str | None = None) -> str:
    if arg_value:
        return arg_value.rstrip("/")
    cfg = load_client_config()
    if isinstance(cfg.get("api_base_url"), str) and cfg["api_base_url"].strip():
        return cfg["api_base_url"].rstrip("/")
    return DEFAULT_API_BASE_URL.rstrip("/")


def platform_name() -> str:
    p = sys.platform.lower()
    if p.startswith("darwin"):
        return "darwin"
    if p.startswith("win"):
        return "windows"
    return "linux"


def api_request(method: str, path: str, payload: dict[str, Any] | None = None, api_base_url: str | None = None, token: str | None = None) -> dict[str, Any]:
    base = resolve_api_base_url(api_base_url)
    url = f"{base}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode("utf-8")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="ignore")
        try:
            msg = json.loads(body)
        except Exception:
            msg = {"error": body or str(e)}
        raise RuntimeError(f"API request failed ({e.code}): {msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"API request failed: {e}") from e


def send_detection_event(findings: list[Finding], hook_input: dict[str, Any]) -> None:
    if not findings:
        return
    cfg = load_client_config()
    token = cfg.get("device_token") if isinstance(cfg.get("device_token"), str) else None

    payload = {
        "event_type": "secret_findings_detected",
        "created_at": int(time.time()),
        "payload": {
            "hook_event_name": hook_input.get("hook_event_name"),
            "tool_name": hook_input.get("tool_name"),
            "session_key": extract_session_key(hook_input),
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "source": f.source,
                    "line": f.line,
                    "masked_value": f.masked_value,
                    "value_left_context": f.value_left_context,
                    "detectors": f.detectors,
                    "rule_ids": f.rule_ids,
                    "score": f.score,
                    "confidence": f.confidence,
                    "severity": f.severity,
                }
                for f in findings
            ],
        },
    }

    # 検知フローを優先し、イベント送信失敗では hook 動作を止めない。
    try:
        api_request("POST", "/v1/events", payload=payload, token=token)
    except Exception:
        return


def get_device_secret() -> bytes:
    ensure_app_dir()
    if not DEVICE_SECRET_FILE.exists():
        DEVICE_SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")
        os.chmod(DEVICE_SECRET_FILE, 0o600)
    return bytes.fromhex(DEVICE_SECRET_FILE.read_text(encoding="utf-8").strip())


def normalize_value(value: str) -> str:
    return value.strip().strip("'\"`").strip()


def fingerprint_value(value: str) -> str:
    digest = hmac.new(
        get_device_secret(),
        normalize_value(value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return "hmac-sha256:" + digest


def mask_secret(value: str) -> str:
    value = normalize_value(value)
    if len(value) <= 10:
        return "*" * len(value)
    return value[:5] + "*" * (len(value) - 10) + value[-5:]


def get_value_left_context(text: str, start: int, width: int = 5) -> str:
    if start <= 0:
        return ""
    raw = text[max(0, start - width):start]
    return raw.replace("\n", " ").replace("\r", " ")


def line_no(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    result = 0.0
    for count in counts.values():
        p = count / len(value)
        result -= p * math.log2(p)
    return result


def looks_like_hex_hash(value: str) -> bool:
    v = normalize_value(value)
    return bool(re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128}", v))


def looks_like_uuid(value: str) -> bool:
    v = normalize_value(value)
    return bool(
        re.fullmatch(
            r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}",
            v,
        )
    )


def looks_like_sri_hash(value: str) -> bool:
    v = normalize_value(value)
    return bool(re.fullmatch(r"sha(?:256|384|512)-[A-Za-z0-9+/=]{20,}", v))


def infer_delimited_prefix(value: str) -> str | None:
    v = normalize_value(value)
    last_sep = max(v.rfind("_"), v.rfind("-"), v.rfind("."))

    if last_sep <= 0:
        return None

    prefix = v[: last_sep + 1]
    tail = v[last_sep + 1 :]

    if not (3 <= len(prefix) <= 32):
        return None
    if len(tail) < 16:
        return None
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*[-_.]", prefix):
        return None

    return prefix


def char_class_count(value: str) -> int:
    return sum(
        [
            bool(re.search(r"[a-z]", value)),
            bool(re.search(r"[A-Z]", value)),
            bool(re.search(r"\d", value)),
            bool(re.search(r"[^A-Za-z0-9]", value)),
        ]
    )


def infer_token_alphabet(value: str) -> str:
    v = normalize_value(value)
    if re.fullmatch(r"[A-Fa-f0-9]+", v):
        return "hex"
    if re.fullmatch(r"[A-Za-z0-9]+", v):
        return "base62"
    if re.fullmatch(r"[A-Za-z0-9_-]+", v):
        return "base64url"
    if re.fullmatch(r"[A-Za-z0-9+/]+=*", v):
        return "base64"
    return "unknown"


def score_token_shape(value: str) -> tuple[int, list[str]]:
    v = normalize_value(value)
    reasons: list[str] = []

    if len(v) < 24:
        return 0, ["shape:too_short"]

    if looks_like_uuid(v):
        return 0, ["shape:uuid"]
    if looks_like_sri_hash(v):
        return 0, ["shape:sri_hash"]
    if looks_like_hex_hash(v):
        return 0, ["shape:hex_hash"]

    if re.fullmatch(r"(.)\1+", v):
        return 0, ["shape:repeated_char"]

    if re.search(r"(example|sample|dummy|placeholder|changeme|your[_-]?key|xxx+)", v, re.I):
        return 0, ["shape:placeholder_marker"]

    prefix = infer_delimited_prefix(v)
    tail = v[len(prefix) :] if prefix else v

    score = 0

    if len(v) >= 24:
        score += 10
        reasons.append("shape:length_24_plus")
    if len(v) >= 32:
        score += 10
        reasons.append("shape:length_32_plus")
    if len(v) >= 48:
        score += 5
        reasons.append("shape:length_48_plus")

    if prefix:
        score += 25
        reasons.append(f"shape:prefix_candidate:{prefix}")

    if len(tail) >= 20:
        score += 10
        reasons.append("shape:tail_length_20_plus")
    if len(tail) >= 32:
        score += 5
        reasons.append("shape:tail_length_32_plus")

    classes = char_class_count(tail)
    if classes >= 2:
        score += 10
        reasons.append("shape:multi_char_class")
    if classes >= 3:
        score += 5
        reasons.append("shape:three_char_classes")

    alphabet = infer_token_alphabet(tail)
    if alphabet in {"base62", "base64url", "base64"}:
        score += 10
        reasons.append(f"shape:alphabet:{alphabet}")

    e = entropy(tail)
    if e >= 4.2:
        score += 8
        reasons.append(f"shape:entropy_tail:{e:.2f}")
    elif e >= 3.8:
        score += 4
        reasons.append(f"shape:entropy_tail:{e:.2f}")

    # prefixなしの単なる高エントロピー文字列は強くしすぎない
    if not prefix:
        score = min(score, 60)
        reasons.append("shape:no_prefix_score_cap")

    return max(0, score), reasons


def load_global_suppressions() -> dict[str, list[dict[str, Any]]]:
    raw = _load_bundled_rules()
    sup = raw.get("global_suppressions", {}) if isinstance(raw, dict) else {}
    if not isinstance(sup, dict):
        sup = {}
    value_patterns = sup.get("value_patterns", [])
    value_markers = sup.get("value_markers", [])
    if not isinstance(value_patterns, list) or not isinstance(value_markers, list):
        return {
            "value_patterns": list(DEFAULT_GLOBAL_SUPPRESSIONS["value_patterns"]),
            "value_markers": list(DEFAULT_GLOBAL_SUPPRESSIONS["value_markers"]),
        }
    return {
        "value_patterns": [x for x in value_patterns if isinstance(x, dict)],
        "value_markers": [x for x in value_markers if isinstance(x, dict)],
    }


def _suppression_applies(rule: dict[str, Any], detector: str) -> bool:
    applies_to = rule.get("applies_to")
    if not isinstance(applies_to, list) or not applies_to:
        return True
    applies = {x for x in applies_to if isinstance(x, str)}
    return detector in applies or "all" in applies


def apply_global_suppressions(value: str, detector: str) -> tuple[bool, int, list[str]]:
    v = normalize_value(value)
    vv = v.lower()
    suppress = False
    score_delta = 0
    reasons: list[str] = []
    sup = load_global_suppressions()

    for rule in sup["value_patterns"]:
        if not _suppression_applies(rule, detector):
            continue
        pattern = rule.get("pattern")
        if not isinstance(pattern, str) or not pattern:
            continue
        try:
            matched = re.search(pattern, v) is not None
        except re.error:
            continue
        if not matched:
            continue

        rid = rule.get("id") if isinstance(rule.get("id"), str) else "pattern_rule"
        effect = rule.get("effect") if isinstance(rule.get("effect"), str) else "suppress"
        if effect == "suppress":
            suppress = True
            reasons.append(f"suppression:{rid}")
        elif effect == "score_delta":
            delta = rule.get("score_delta", 0)
            if isinstance(delta, int):
                score_delta += delta
                reasons.append(f"suppression_delta:{rid}:{delta}")

    for rule in sup["value_markers"]:
        if not _suppression_applies(rule, detector):
            continue
        marker = rule.get("marker")
        if not isinstance(marker, str) or not marker:
            continue
        if marker.lower() not in vv:
            continue

        rid = rule.get("id") if isinstance(rule.get("id"), str) else "marker_rule"
        effect = rule.get("effect") if isinstance(rule.get("effect"), str) else "score_delta"
        if effect == "suppress":
            suppress = True
            reasons.append(f"suppression:{rid}")
        elif effect == "score_delta":
            delta = rule.get("score_delta", 0)
            if isinstance(delta, int):
                score_delta += delta
                reasons.append(f"suppression_delta:{rid}:{delta}")

    return suppress, score_delta, reasons


def load_whitelist() -> set[str]:
    if not WHITELIST_FILE.exists():
        return set()
    try:
        return set(json.loads(WHITELIST_FILE.read_text(encoding="utf-8")).get("fingerprints", []))
    except Exception:
        return set()


def save_whitelist(items: set[str]) -> None:
    ensure_app_dir()
    WHITELIST_FILE.write_text(json.dumps({"fingerprints": sorted(items)}, indent=2), encoding="utf-8")


def load_session_allow() -> dict[str, set[str]]:
    if not SESSION_ALLOW_FILE.exists():
        return {}
    try:
        raw = json.loads(SESSION_ALLOW_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    items = raw.get("sessions", {}) if isinstance(raw, dict) else {}
    if not isinstance(items, dict):
        return {}
    out: dict[str, set[str]] = {}
    for session_key, fps in items.items():
        if not isinstance(session_key, str) or not isinstance(fps, list):
            continue
        out[session_key] = {fp for fp in fps if isinstance(fp, str)}
    return out


def save_session_allow(items: dict[str, set[str]]) -> None:
    ensure_app_dir()
    normalized = {session_key: sorted(fps) for session_key, fps in items.items() if fps}
    SESSION_ALLOW_FILE.write_text(json.dumps({"sessions": normalized}, indent=2), encoding="utf-8")


def grant_session_allow(session_key: str, fingerprint: str) -> None:
    items = load_session_allow()
    fps = items.setdefault(session_key, set())
    fps.add(fingerprint)
    save_session_allow(items)


def is_session_allowed(session_key: str, fingerprint: str) -> bool:
    items = load_session_allow()
    fps = items.get(session_key, set())
    if fingerprint in fps:
        return True
    # 既存データ互換: session_key 未保存の古い finding は global 参照
    if session_key != "global" and fingerprint in items.get("global", set()):
        return True
    return False


def extract_session_key(hook_input: dict[str, Any]) -> str:
    candidate_keys = [
        "session_id",
        "sessionId",
        "conversation_id",
        "conversationId",
        "chat_id",
        "chatId",
        "run_id",
        "runId",
        "transcript_path",
        "transcriptPath",
    ]
    for key in candidate_keys:
        value = hook_input.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    cwd = hook_input.get("cwd")
    if isinstance(cwd, str) and cwd.strip():
        return "cwd:" + cwd.strip()
    return "global"


def session_allow_count() -> tuple[int, int]:
    items = load_session_allow()
    sessions = len(items)
    fingerprints = sum(len(fps) for fps in items.values())
    return sessions, fingerprints


def session_hint_for_finding(finding: dict[str, Any] | Finding) -> str:
    if isinstance(finding, Finding):
        session_key = finding.session_key
    else:
        session_key = finding.get("session_key") or "global"
    if session_key == "global":
        return ""
    return f" --session-key {session_key}"


def ensure_dict_finding_session_key(f: dict[str, Any]) -> str:
    session_key = f.get("session_key")
    if isinstance(session_key, str) and session_key.strip():
        return session_key
    return "global"


def load_pause_state() -> dict[str, Any]:
    if not PAUSE_FILE.exists():
        return {"global": None, "sessions": {}}
    try:
        raw = json.loads(PAUSE_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return {"global": None, "sessions": {}}
        return {
            "global": raw.get("global"),
            "sessions": raw.get("sessions") or {},
        }
    except Exception:
        return {"global": None, "sessions": {}}


def save_pause_state(state: dict[str, Any]) -> None:
    ensure_app_dir()
    PAUSE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")


def _pause_entry_active(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    expires_at = entry.get("expires_at")
    if expires_at is not None and int(time.time()) >= int(expires_at):
        return False
    return True


def is_paused(session_key: str) -> bool:
    state = load_pause_state()
    if _pause_entry_active(state.get("global")):
        return True
    sessions = state.get("sessions") or {}
    return _pause_entry_active(sessions.get(session_key))


def set_pause(session_key: str | None, duration: int | None) -> None:
    state = load_pause_state()
    now = int(time.time())
    entry: dict[str, Any] = {
        "paused_at": now,
        "expires_at": now + duration if duration is not None else None,
    }
    if session_key is None:
        state["global"] = entry
    else:
        if not isinstance(state.get("sessions"), dict):
            state["sessions"] = {}
        state["sessions"][session_key] = entry
    save_pause_state(state)


def clear_pause(session_key: str | None) -> None:
    state = load_pause_state()
    if session_key is None:
        state["global"] = None
    else:
        sessions = state.get("sessions") or {}
        sessions.pop(session_key, None)
        state["sessions"] = sessions
    save_pause_state(state)


def pause_status_summary() -> str:
    state = load_pause_state()
    now = int(time.time())
    lines = []

    g = state.get("global")
    if _pause_entry_active(g):
        exp = g.get("expires_at")
        if exp:
            remaining = max(0, int(exp) - now)
            lines.append(f"グローバル停止中 (残り {remaining}秒)")
        else:
            lines.append("グローバル停止中 (手動再開まで)")

    sessions = state.get("sessions") or {}
    active_sessions = [(k, v) for k, v in sessions.items() if _pause_entry_active(v)]
    for sk, entry in active_sessions:
        exp = entry.get("expires_at")
        if exp:
            remaining = max(0, int(exp) - now)
            lines.append(f"セッション停止中: {sk} (残り {remaining}秒)")
        else:
            lines.append(f"セッション停止中: {sk} (手動再開まで)")

    return "\n".join(lines) if lines else "停止なし (検知有効)"


def load_pending_choices() -> dict[str, dict[str, Any]]:
    if not PENDING_CHOICES_FILE.exists():
        return {}
    try:
        raw = json.loads(PENDING_CHOICES_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    sessions = raw.get("sessions", {}) if isinstance(raw, dict) else {}
    if not isinstance(sessions, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for session_key, item in sessions.items():
        if not isinstance(session_key, str) or not isinstance(item, dict):
            continue
        fid = item.get("finding_id")
        fp = item.get("fingerprint")
        if isinstance(fid, str) and isinstance(fp, str):
            out[session_key] = {
                "finding_id": fid,
                "fingerprint": fp,
                "created_at": int(item.get("created_at") or 0),
            }
    return out


def save_pending_choices(items: dict[str, dict[str, Any]]) -> None:
    ensure_app_dir()
    PENDING_CHOICES_FILE.write_text(json.dumps({"sessions": items}, indent=2), encoding="utf-8")


def set_pending_choice(session_key: str, finding: Finding) -> None:
    items = load_pending_choices()
    items[session_key] = {
        "finding_id": finding.finding_id,
        "fingerprint": finding.fingerprint,
        "created_at": int(time.time()),
    }
    save_pending_choices(items)


def pop_pending_choice(session_key: str) -> dict[str, Any] | None:
    items = load_pending_choices()
    value = items.pop(session_key, None)
    save_pending_choices(items)
    return value


def get_pending_choice(session_key: str) -> dict[str, Any] | None:
    items = load_pending_choices()
    return items.get(session_key)


def handle_user_prompt_choice_input(prompt: str, session_key: str) -> dict[str, Any] | None:
    choice = prompt.strip()
    if choice not in {"1", "2", "3"}:
        return None

    pending = get_pending_choice(session_key)
    if not pending:
        return {
            "decision": "block",
            "reason": "直前の保留中アラートが見つからないため、選択を処理できませんでした。もう一度実行してください。",
            "suppressOriginalPrompt": True,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }

    finding_id = pending["finding_id"]
    fingerprint = pending["fingerprint"]
    pop_pending_choice(session_key)

    if choice == "1":
        grant_session_allow(session_key, fingerprint)
        return {
            "decision": "block",
            "reason": (
                f"選択1を受け付けました: このセッションで承認しました ({finding_id})。\n"
                "元のプロンプトを再送してください。"
            ),
            "suppressOriginalPrompt": True,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }

    if choice == "2":
        items = load_whitelist()
        items.add(fingerprint)
        save_whitelist(items)
        return {
            "decision": "block",
            "reason": (
                f"選択2を受け付けました: この値を今後も承認しました ({finding_id})。\n"
                "元のプロンプトを再送してください。"
            ),
            "suppressOriginalPrompt": True,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
        }

    return {
        "decision": "block",
        "reason": "選択3を受け付けました: キャンセルして修正してください。",
        "suppressOriginalPrompt": True,
        "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
    }


def pending_choice_block_message(session_key: str, pending: dict[str, Any]) -> str:
    finding_id = pending.get("finding_id") or "(unknown)"
    return "\n".join([
        "前回のセキュリティ確認が未完了です。先に次の3つから選択してください:",
        f"1) このセッションで承認: mamoraku-secret continue {finding_id} --session-key {session_key}",
        f"2) この値を今後も承認: mamoraku-secret continue {finding_id} --whitelist",
        "3) キャンセルして修正",
        "",
        "ショートカット: 1 / 2 / 3 だけ送信しても処理できます。",
    ])


def _remove_legacy_temp_allow_file() -> None:
    # 古い一時許可ファイルが残っていてもロジックには影響しないが、混乱防止のため削除を試みる。
    legacy = APP_DIR / "temp_allow.json"
    if legacy.exists():
        try:
            legacy.unlink()
        except Exception:
            pass


def new_id(prefix: str) -> str:
    return prefix + "_" + secrets.token_hex(4)


def save_finding(f: Finding) -> None:
    ensure_app_dir()
    with FINDINGS_FILE.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(asdict(f), ensure_ascii=False) + "\n")


def get_finding(finding_id: str) -> dict[str, Any] | None:
    if not FINDINGS_FILE.exists():
        return None
    for line in FINDINGS_FILE.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if obj.get("finding_id") == finding_id:
            return obj
    return None


class RegexDetector:
    def __init__(self) -> None:
        rules = []
        for r in load_regex_rules():
            try:
                rules.append({**r, "regex": re.compile(r["pattern"])})
            except re.error:
                pass
        self.rules = rules

    def scan(self, text: str) -> list[Evidence]:
        out = []
        for rule in self.rules:
            for m in rule["regex"].finditer(text):
                value = m.group(0)
                out.append(
                    Evidence(
                        detector="regex",
                        start=m.start(),
                        end=m.end(),
                        line=line_no(text, m.start()),
                        raw_value=value,
                        fingerprint=fingerprint_value(value),
                        score=100,
                        reasons=[f"regex:{rule['id']}"],
                        rule_id=rule["id"],
                        value_left_context=get_value_left_context(text, m.start()),
                    )
                )
        return out



class EntropyDetector:
    def scan(self, text: str) -> list[Evidence]:
        out = []
        for m in TOKEN_RE.finditer(text):
            value = normalize_value(m.group(0))
            value_start = m.start()
            shape_score, shape_reasons = score_token_shape(value)
            if shape_score < 55:
                continue

            suppress, delta, suppression_reasons = apply_global_suppressions(value, "entropy")
            if suppress:
                continue

            penalty, penalty_reasons = self._code_structure_penalty(value)
            score = shape_score + delta + penalty
            if score < 55:
                continue

            out.append(
                Evidence(
                    detector="entropy",
                    start=value_start,
                    end=m.end(),
                    line=line_no(text, value_start),
                    raw_value=value,
                    fingerprint=fingerprint_value(value),
                    score=score,
                    reasons=[*shape_reasons, *suppression_reasons, *penalty_reasons],
                    rule_id="heuristic_token_shape",
                    value_left_context=get_value_left_context(text, value_start),
                )
            )
        return out

    @staticmethod
    def _code_structure_penalty(value: str) -> tuple[int, list[str]]:
        """Penalise tokens that look like code identifiers rather than secrets."""
        penalty = 0
        reasons: list[str] = []

        # If this token is KEY=VALUE form, analyze only the value portion.
        # (TOKEN_RE includes '=' so key=value pairs match as one token.)
        eq_pos = value.find("=")
        target = value[eq_pos + 1:] if 0 < eq_pos < len(value) - 2 else value

        # CamelCase penalty: only for digit-free strings.
        # Random API keys almost always contain digits; pure-alpha camelCase strings
        # are far more likely to be class/method names.
        if not re.search(r"\d", target):
            camel_transitions = len(re.findall(r"[a-z][A-Z]", target))
            if camel_transitions >= 2:
                penalty -= 15
                reasons.append(f"shape:camelcase_penalty:{camel_transitions}")

        # Word-segment penalty: 4+ pure-alpha segments of len≥3 separated by _ or -.
        # Threshold is 4 (not 3) so that 3-segment API key prefixes like
        # apify_api_<random> are not penalised even if the tail is all-alpha.
        # Applied regardless of whether other segments contain digits, so test names
        # like test_distinct_for_m2m_in_list_filter are still caught.
        if "_" in target or "-" in target:
            word_segs = [s for s in re.split(r"[_-]", target) if s.isalpha() and len(s) >= 3]
            if len(word_segs) >= 4:
                penalty -= 15
                reasons.append(f"shape:word_segment_penalty:{len(word_segs)}")

        return penalty, reasons


def overlap_ratio(a: Evidence, b: Evidence) -> float:
    overlap = max(0, min(a.end, b.end) - max(a.start, b.start))
    shorter = min(a.end - a.start, b.end - b.start)
    return 0.0 if shorter <= 0 else overlap / shorter


def merge(evidences: list[Evidence], source: str, session_key: str) -> list[Finding]:
    groups: list[list[Evidence]] = []
    for ev in evidences:
        found = None
        for g in groups:
            if any(ev.fingerprint == x.fingerprint or overlap_ratio(ev, x) >= 0.7 for x in g):
                found = g
                break
        if found is None:
            groups.append([ev])
        else:
            found.append(ev)

    whitelist = load_whitelist()
    findings = []

    for g in groups:
        representative = max(g, key=lambda ev: ev.end - ev.start)
        representative_fp = representative.fingerprint

        # ホワイトリスト/セッション承認は、finding に保存される代表 fingerprint に対してのみ適用する。
        if representative_fp in whitelist:
            continue
        if is_session_allowed(session_key, representative_fp):
            continue

        has_regex = any(ev.detector == "regex" for ev in g)
        score = 100 if has_regex else sum(ev.score for ev in g)
        raw = representative.raw_value
        confidence = "high" if has_regex or score >= 85 else "medium" if score >= 55 else "low"
        severity = "high" if has_regex else "medium" if score >= 55 else "low"

        findings.append(
            Finding(
                finding_id=new_id("fnd"),
                source=source,
                session_key=session_key,
                line=min(ev.line for ev in g),
                fingerprint=representative_fp,
                masked_value=mask_secret(raw),
                detectors=sorted({ev.detector for ev in g}),
                rule_ids=sorted({ev.rule_id for ev in g if ev.rule_id}),
                score=score,
                confidence=confidence,
                severity=severity,
                reasons=[r for ev in g for r in ev.reasons],
                suggested_action="confirm" if has_regex else "alert",
                value_left_context=representative.value_left_context,
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Reranker (ML post-filter for entropy detections)
# ---------------------------------------------------------------------------

_RERANKER_THRESHOLD  = 0.7
_RERANKER_MODEL_JSON = Path(__file__).parent / "reranker_model.json"
_reranker_model = None


def _load_reranker():
    global _reranker_model
    if _reranker_model is not None:
        return _reranker_model

    if not _RERANKER_MODEL_JSON.exists():
        return None

    try:
        import xgboost as xgb
    except Exception:
        return None  # ML reranker unavailable; regex/entropy detection continues

    clf = xgb.XGBClassifier()
    clf.load_model(str(_RERANKER_MODEL_JSON))
    _reranker_model = clf
    return _reranker_model


def _reranker_features(raw_value: str, left_ctx: str, score: float) -> list[float]:
    v = normalize_value(raw_value)
    n = max(len(v), 1)
    digits   = sum(c.isdigit()  for c in v)
    uppers   = sum(c.isupper()  for c in v)
    lowers   = sum(c.islower()  for c in v)
    specials = sum(not c.isalnum() for c in v)
    camel = len(re.findall(r"[a-z][A-Z]", v))
    eq_pos = v.find("=")
    has_eq = int(0 < eq_pos < n - 2)
    target = v[eq_pos + 1:] if has_eq else v
    lowercase_key = int(bool(has_eq and re.match(r"^[a-z][a-z0-9_]+=", v)))
    word_segs: list[str] = []
    if "_" in target or "-" in target:
        word_segs = [s for s in re.split(r"[_-]", target) if s.isalpha() and len(s) >= 3]
    hyp_word_segs: list[str] = []
    if "-" in target and "_" not in target:
        hyp_word_segs = [s for s in target.split("-") if s.isalpha() and len(s) >= 3]
    has_double_us = int("__" in v)
    has_short_prefix = int(bool(re.match(r"^[A-Za-z][A-Za-z0-9]{1,8}[_-][A-Za-z0-9]", target)))
    left_ctx_str = 0
    if re.search(r"(?i)(api_key|api_token|secret_key|access_token|client_secret)", left_ctx):
        left_ctx_str = 2
    elif re.search(r"(?i)(key|token|secret|auth|pass|cred)", left_ctx):
        left_ctx_str = 1
    is_all_hex    = int(bool(re.fullmatch(r"[0-9a-fA-F]+", target)))
    is_pure_alpha = int(target.isalpha())
    is_base64url  = int(bool(re.fullmatch(r"[A-Za-z0-9_-]+", target)))
    ent_val = v
    ent_n = max(len(ent_val), 1)
    entropy = -sum(c / ent_n * math.log2(c / ent_n) for c in _Counter(ent_val).values()) if ent_val else 0.0
    unique_ratio = len(set(v)) / n
    has_digit_and_alpha = int(digits > 0 and (uppers + lowers) > 0)
    return [
        score, n, entropy,
        digits / n, uppers / n, lowers / n, specials / n,
        int(digits > 0) + int(uppers > 0) + int(lowers > 0) + int(specials > 0),
        camel, len(word_segs), len(hyp_word_segs),
        has_eq, lowercase_key, has_short_prefix, has_double_us,
        is_all_hex, is_pure_alpha, is_base64url, left_ctx_str,
        unique_ratio, has_digit_and_alpha,
    ]


def _apply_reranker(evidences: list[Evidence]) -> list[Evidence]:
    pipeline = _load_reranker()
    if pipeline is None:
        return evidences

    try:
        import numpy as np
    except Exception:
        return evidences  # numpy unavailable; skip reranking

    entropy_idx = [i for i, e in enumerate(evidences) if e.detector == "entropy"]
    if not entropy_idx:
        return evidences

    X = np.array([
        _reranker_features(
            evidences[i].raw_value,
            evidences[i].value_left_context or "",
            float(evidences[i].score),
        )
        for i in entropy_idx
    ])
    probs = pipeline.predict_proba(X)[:, 1]

    keep = set()
    for idx, prob in zip(entropy_idx, probs):
        if prob >= _RERANKER_THRESHOLD:
            keep.add(idx)

    return [e for i, e in enumerate(evidences) if e.detector != "entropy" or i in keep]


def _apply_path_suppressions(evidences: list[Evidence], source: str) -> list[Evidence]:
    rules = {r["id"]: r for r in load_regex_rules()}
    out = []
    for ev in evidences:
        rule = rules.get(ev.rule_id)
        if rule:
            pat = rule.get("path_suppress")
            if pat and re.search(pat, source, re.IGNORECASE):
                continue
        out.append(ev)
    return out


def scan_text(text: str, source: str, session_key: str) -> list[Finding]:
    evidences = []
    for d in [RegexDetector(), EntropyDetector()]:
        evidences.extend(d.scan(text))
    evidences = _apply_path_suppressions(evidences, source)
    evidences = _apply_reranker(evidences)
    findings = merge(evidences, source, session_key)
    for f in findings:
        save_finding(f)
    return findings


def _dw(s: str) -> int:
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in s)


def _pad(s: str, width: int) -> str:
    return s + " " * (width - _dw(s))


def action_message(findings: list[Finding], mode: str, command: str | None = None) -> str:
    f = findings[0]

    # PreTool は Claude 側で理由文が要約表示されやすいため、3択を先頭に短く固定で返す。
    if mode in {"deny", "ask"}:
        return "\n".join([
            "Secret Protector: 機密の可能性があるため実行を停止しました。",
            f"検出ID: {f.finding_id}  /  マスク: {f.masked_value}",
            "",
            "次の3つから選択してください:",
            f"1) このセッションで承認: mamoraku-secret continue {f.finding_id}{session_hint_for_finding(f)}",
            f"2) この値を今後も承認: mamoraku-secret continue {f.finding_id} --whitelist",
            "3) キャンセルして修正",
            "",
            "ショートカット: 1 / 2 / 3 だけ送信しても処理できます。",
        ])

    rows = [
        ("検出ID",     f.finding_id),
        ("種別",       ", ".join(f.rule_ids) or "APIキー類似シークレット"),
        ("ソース",     f"{f.source}:{f.line}"),
        ("マスク済み", f.masked_value),
        ("信頼度",     f.confidence),
    ]
    if command:
        rows.append(("元コマンド", command))
    kw = max(_dw(k) for k, _ in rows)
    vw = max(_dw(v) for _, v in rows)
    top = f"┌{'─' * (kw + 2)}┬{'─' * (vw + 2)}┐"
    sep = f"├{'─' * (kw + 2)}┼{'─' * (vw + 2)}┤"
    bot = f"└{'─' * (kw + 2)}┴{'─' * (vw + 2)}┘"
    table = [top]
    for i, (k, v) in enumerate(rows):
        table.append(f"│ {_pad(k, kw)} │ {_pad(v, vw)} │")
        if i < len(rows) - 1:
            table.append(sep)
    table.append(bot)

    approval_hint = (
        "次の3つから選択してください:\n"
        f"1) このセッションで承認: mamoraku-secret continue {f.finding_id}{session_hint_for_finding(f)}\n"
        f"2) この値を今後も承認: mamoraku-secret continue {f.finding_id} --whitelist\n"
        "3) キャンセルして修正: 秘密値を削除・マスクして再実行"
    )
    if mode in {"block", "deny", "ask"}:
        approval_hint += "\n\nショートカット: 次の入力で 1 / 2 / 3 だけ送っても処理できます。"
    if command:
        approval_hint += "\n\n承認後に、元コマンドを再実行してください。"

    return "\n".join([
        "Secret Protector がシークレットの可能性があるデータを検出しました。",
        "",
        *table,
        "",
        approval_hint,
    ])


def extract_contexts(hook_input: dict[str, Any]) -> list[tuple[str, str]]:
    event = hook_input.get("hook_event_name")
    tool_name = hook_input.get("tool_name")
    tool_input = hook_input.get("tool_input") or {}
    tool_response = hook_input.get("tool_response") or {}

    if event == "UserPromptSubmit":
        return [("[prompt]", hook_input.get("prompt") or "")]

    if event in {"PreToolUse", "PermissionRequest"}:
        if tool_name == "Bash":
            return [("[bash command]", tool_input.get("command") or "")]
        if tool_name in {"Write", "Edit", "MultiEdit"}:
            content = tool_input.get("content") or tool_input.get("new_string") or ""
            return [(tool_input.get("file_path") or "[write/edit content]", content)]
        if tool_name == "Read":
            path = tool_input.get("file_path")

            def _read_from_candidates(raw_path: str) -> tuple[str, str]:
                candidates: list[Path] = []
                p = Path(raw_path)
                if p.is_absolute():
                    candidates.append(p)
                else:
                    hook_cwd = hook_input.get("cwd")
                    if isinstance(hook_cwd, str) and hook_cwd.strip():
                        candidates.append(Path(hook_cwd.strip()) / raw_path)
                    candidates.append(Path.cwd() / raw_path)

                seen: set[str] = set()
                for candidate in candidates:
                    key = str(candidate)
                    if key in seen:
                        continue
                    seen.add(key)
                    try:
                        text = candidate.read_text(encoding="utf-8", errors="ignore")
                        return str(candidate), text
                    except Exception:
                        continue
                return raw_path, ""

            try:
                source, text = _read_from_candidates(path) if path else ("[read file]", "")
            except Exception:
                source = path or "[read file]"
                text = ""
            return [(source, text)]

    if event == "PostToolUse":
        if tool_name == "Bash":
            return [
                ("[bash stdout]", tool_response.get("stdout") or ""),
                ("[bash stderr]", tool_response.get("stderr") or ""),
            ]

    return []


def run_hook() -> None:
    hook_input = json.load(sys.stdin)
    event = hook_input.get("hook_event_name")
    session_key = extract_session_key(hook_input)
    findings = []
    _remove_legacy_temp_allow_file()

    if event == "UserPromptSubmit" and is_authenticated_client():
        threading.Thread(target=_refresh_rules_from_api, daemon=True).start()

    # 未認証時は検知を実行せず、ログイン案内のみを返す。
    if not is_authenticated_client():
        if event == "UserPromptSubmit":
            # session_id が取れる場合はセッションごとに1回、それ以外は毎回表示。
            show_prompt = session_key == "global" or not is_auth_prompted(session_key)
            if show_prompt and session_key != "global":
                mark_auth_prompted(session_key)
            if show_prompt:
                msg = auth_prompt_message()
                print(json.dumps({
                    "decision": "block",
                    "reason": msg,
                    "suppressOriginalPrompt": True,
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                }, ensure_ascii=False))
            else:
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, ensure_ascii=False))
            return

        if event == "PreToolUse":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}, ensure_ascii=False))
            return

        if event == "PostToolUse":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse"}}, ensure_ascii=False))
            return

    # 一時停止中はスキャンをスキップしてそのまま通過させる。
    if is_paused(session_key):
        if event == "UserPromptSubmit":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, ensure_ascii=False))
        elif event == "PreToolUse":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}, ensure_ascii=False))
        elif event == "PostToolUse":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse"}}, ensure_ascii=False))
        else:
            print(json.dumps({}))
        return

    if event == "UserPromptSubmit":
        raw_prompt = hook_input.get("prompt") or ""
        if isinstance(raw_prompt, str):
            choice_result = handle_user_prompt_choice_input(raw_prompt, session_key)
            if choice_result is not None:
                print(json.dumps(choice_result, ensure_ascii=False))
                return
            pending = get_pending_choice(session_key)
            if pending is not None:
                print(json.dumps({
                    "decision": "block",
                    "reason": pending_choice_block_message(session_key, pending),
                    "suppressOriginalPrompt": True,
                    "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
                }, ensure_ascii=False))
                return

    for source, text in extract_contexts(hook_input):
        if text:
            findings.extend(scan_text(text, source, session_key))

    send_detection_event(findings, hook_input)

    if event == "UserPromptSubmit":
        if findings and DEFAULT_PROMPT_ACTION == "block":
            set_pending_choice(session_key, findings[0])
            print(json.dumps({
                "decision": "block",
                "reason": action_message(findings, "block"),
                "suppressOriginalPrompt": True,
                "hookSpecificOutput": {"hookEventName": "UserPromptSubmit"},
            }, ensure_ascii=False))
        elif findings:
            print(json.dumps({
                "hookSpecificOutput": {
                    "hookEventName": "UserPromptSubmit",
                    "additionalContext": action_message(findings, "alert"),
                }
            }, ensure_ascii=False))
        else:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit"}}, ensure_ascii=False))
        return

    if event == "PreToolUse":
        if not findings:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow"}}, ensure_ascii=False))
            return

        # PreTool でも UserPrompt と同じ 3択ショートカットを使えるように保留状態を作る。
        set_pending_choice(session_key, findings[0])

        if DEFAULT_TOOL_ACTION == "deny":
            decision = "deny"
        elif DEFAULT_TOOL_ACTION == "alert":
            decision = "allow"
        else:
            decision = "ask"

        print(json.dumps({
            "terminalSequence": "\u0007",
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": decision,
                "permissionDecisionReason": action_message(findings, decision),
            }
        }, ensure_ascii=False))
        return

    if event == "PostToolUse":
        if findings:
            bash_command = (hook_input.get("tool_input") or {}).get("command") if hook_input.get("tool_name") == "Bash" else None
            body = {
                "hookEventName": "PostToolUse",
                "additionalContext": action_message(findings, "alert", command=bash_command),
            }
            if hook_input.get("tool_name") == "Bash":
                body["updatedToolOutput"] = {
                    "stdout": "[Secret Protector がシークレットの可能性がある出力を削除しました]\n",
                    "stderr": "",
                    "interrupted": False,
                    "isImage": False,
                }
            print(json.dumps({"hookSpecificOutput": body}, ensure_ascii=False))
        else:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PostToolUse"}}, ensure_ascii=False))
        return

    print(json.dumps({}))


def cmd_feedback(args: argparse.Namespace) -> None:
    f = get_finding(args.finding_id)
    if not f:
        print(f"検出結果が見つかりません: {args.finding_id}", file=sys.stderr)
        sys.exit(1)
    ensure_app_dir()
    event = {
        "created_at": int(time.time()),
        "finding_id": args.finding_id,
        "label": args.label,
        "service": args.service,
        "snapshot": {
            "detectors": f.get("detectors"),
            "rule_ids": f.get("rule_ids"),
            "score": f.get("score"),
            "confidence": f.get("confidence"),
            "severity": f.get("severity"),
            "reasons": f.get("reasons"),
        }
    }
    with FEEDBACK_FILE.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(event, ensure_ascii=False) + "\n")
    print(f"フィードバックを保存しました: {args.finding_id} -> {args.label}")


def cmd_whitelist_add(args: argparse.Namespace) -> None:
    f = get_finding(args.finding_id)
    if not f:
        print(f"検出結果が見つかりません: {args.finding_id}", file=sys.stderr)
        sys.exit(1)
    items = load_whitelist()
    items.add(f["fingerprint"])
    save_whitelist(items)
    print(f"ローカルの完全一致ホワイトリストに追加しました: {args.finding_id}")


def cmd_continue(args: argparse.Namespace) -> None:
    f = get_finding(args.finding_id)
    if not f:
        print(f"検出結果が見つかりません: {args.finding_id}", file=sys.stderr)
        sys.exit(1)

    session_key = args.session_key or ensure_dict_finding_session_key(f)

    if args.whitelist:
        items = load_whitelist()
        items.add(f["fingerprint"])
        save_whitelist(items)
        print(f"ホワイトリストに登録しました: {args.finding_id}")
        return

    grant_session_allow(session_key, f["fingerprint"])
    print(f"このセッションで承認しました: {args.finding_id}")


def cmd_pause(args: argparse.Namespace) -> None:
    session_key = None if args.global_scope else args.session_key
    duration = args.duration
    set_pause(session_key, duration)
    if session_key is None:
        scope = "グローバル (全セッション)"
    else:
        scope = f"セッション ({session_key})"
    if duration:
        print(f"シークレット検知を一時停止しました [{scope}、{duration}秒間]。")
    else:
        print(f"シークレット検知を一時停止しました [{scope}]。")
        print("再開するには: mamoraku-secret resume")


def cmd_resume(args: argparse.Namespace) -> None:
    session_key = None if args.global_scope else args.session_key
    clear_pause(session_key)
    if session_key is None:
        scope = "グローバル"
    else:
        scope = f"セッション ({session_key})"
    print(f"シークレット検知を再開しました [{scope}]。")


def cmd_status(_: argparse.Namespace) -> None:
    print(f"アプリディレクトリ: {APP_DIR}")
    print(f"ツールアクション: {DEFAULT_TOOL_ACTION}")
    print(f"プロンプトアクション: {DEFAULT_PROMPT_ACTION}")
    print(f"ホワイトリスト件数: {len(load_whitelist())}")
    sessions, fingerprints = session_allow_count()
    print(f"セッション承認: {sessions} session(s), {fingerprints} fingerprint(s)")
    print(f"検出結果ファイル: {FINDINGS_FILE if FINDINGS_FILE.exists() else '(なし)'}")
    print(f"一時停止: {pause_status_summary()}")


def cmd_login(args: argparse.Namespace) -> None:
    if args.device_code:
        device_code = args.device_code
        expires_in = 600
        interval = 5
        print("ブラウザで承認後、完了をポーリングします...")
    else:
        start_payload = {
            "client": "claude_code",
            "plugin_version": args.plugin_version,
            "runtime_version": args.runtime_version,
            "os": platform_name(),
        }
        start = api_request("POST", "/v1/auth/device/start", payload=start_payload, api_base_url=args.api_base_url)

        device_code = start.get("device_code")
        user_code = start.get("user_code")
        verification_url = start.get("verification_url")
        expires_in = int(start.get("expires_in", 600))
        interval = int(start.get("interval", 5))

        if not isinstance(device_code, str) or not device_code:
            print("device_code が不正です", file=sys.stderr)
            sys.exit(1)

        print("Device login を開始しました。")
        print(f"- verification_url: {verification_url}")
        print(f"- user_code: {user_code}")
        print(f"- expires_in: {expires_in}s")
        print("ブラウザで承認後、完了をポーリングします...")

    max_wait = args.max_wait if args.max_wait is not None else expires_in
    deadline = time.time() + max_wait
    while time.time() < deadline:
        result = api_request(
            "POST",
            "/v1/auth/device/complete",
            payload={"device_code": device_code},
            api_base_url=args.api_base_url,
        )
        status = result.get("status")
        if status == "pending":
            time.sleep(max(1, interval))
            continue
        if status == "authorized":
            cfg = {
                "api_base_url": resolve_api_base_url(args.api_base_url),
                "device_id": result.get("device_id"),
                "device_token": result.get("device_token"),
                "plan": (result.get("user") or {}).get("plan", "free"),
            }
            save_client_config(cfg)
            print("認証完了。設定を保存しました:")
            print(f"- {CLIENT_CONFIG_FILE}")
            return
        print(f"未対応の status を受信: {status}", file=sys.stderr)
        sys.exit(1)

    print("認証待ちがタイムアウトしました。もう一度 login を実行してください。", file=sys.stderr)
    sys.exit(1)


def cmd_ruleset_current(args: argparse.Namespace) -> None:
    cfg = load_client_config()
    token = cfg.get("device_token") if isinstance(cfg.get("device_token"), str) else None
    result = api_request("GET", "/v1/rulesets/current", api_base_url=args.api_base_url, token=token)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_events_send(args: argparse.Namespace) -> None:
    payload: dict[str, Any]
    if args.file:
        payload = json.loads(Path(args.file).read_text(encoding="utf-8"))
    else:
        payload = {
            "event_type": args.event_type,
            "created_at": int(time.time()),
            "payload": {"note": "stub event from plugin runtime"},
        }

    cfg = load_client_config()
    token = cfg.get("device_token") if isinstance(cfg.get("device_token"), str) else None
    result = api_request("POST", "/v1/events", payload=payload, api_base_url=args.api_base_url, token=token)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def cmd_feedback_send(args: argparse.Namespace) -> None:
    payload: dict[str, Any] = {
        "finding_id": args.finding_id,
        "label": args.label,
        "created_at": int(time.time()),
        "payload": {},
    }
    f = get_finding(args.finding_id)
    if f:
        payload["payload"] = {
            "rule_ids": f.get("rule_ids"),
            "confidence": f.get("confidence"),
            "severity": f.get("severity"),
            "source": f.get("source"),
            "line": f.get("line"),
        }

    cfg = load_client_config()
    token = cfg.get("device_token") if isinstance(cfg.get("device_token"), str) else None
    result = api_request("POST", "/v1/feedback", payload=payload, api_base_url=args.api_base_url, token=token)
    print(json.dumps(result, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("hook")

    feedback = sub.add_parser("feedback")
    feedback.add_argument("finding_id")
    feedback.add_argument("--label", choices=["true_positive", "false_positive", "unknown"], required=True)
    feedback.add_argument("--service", default=None)

    wl = sub.add_parser("whitelist")
    wl_sub = wl.add_subparsers(dest="wl_cmd")
    wl_add = wl_sub.add_parser("add")
    wl_add.add_argument("finding_id")

    ctn = sub.add_parser("continue")
    ctn.add_argument("finding_id")
    ctn.add_argument("--whitelist", action="store_true")
    ctn.add_argument("--session-key", default=None)

    sub.add_parser("status")

    login = sub.add_parser("login")
    login.add_argument("--api-base-url", default=None)
    login.add_argument("--plugin-version", default="0.3.0")
    login.add_argument("--runtime-version", default="0.1.0")
    login.add_argument("--device-code", default=None)
    login.add_argument("--max-wait", type=int, default=None)

    ruleset = sub.add_parser("ruleset-current")
    ruleset.add_argument("--api-base-url", default=None)

    events_send = sub.add_parser("events-send")
    events_send.add_argument("--api-base-url", default=None)
    events_send.add_argument("--event-type", default="hook_runtime_event")
    events_send.add_argument("--file", default=None)

    feedback_send = sub.add_parser("feedback-send")
    feedback_send.add_argument("finding_id")
    feedback_send.add_argument("--label", choices=["true_positive", "false_positive", "unknown"], required=True)
    feedback_send.add_argument("--api-base-url", default=None)

    pause_cmd = sub.add_parser("pause")
    pause_cmd.add_argument("--session-key", default=None)
    pause_cmd.add_argument("--duration", type=int, default=None, help="停止する秒数 (省略すると手動 resume まで継続)")
    pause_cmd.add_argument("--global", dest="global_scope", action="store_true", help="全セッションを停止")

    resume_cmd = sub.add_parser("resume")
    resume_cmd.add_argument("--session-key", default=None)
    resume_cmd.add_argument("--global", dest="global_scope", action="store_true", help="グローバル停止を解除")

    args = parser.parse_args()
    if args.cmd == "hook":
        run_hook()
    elif args.cmd == "feedback":
        cmd_feedback(args)
    elif args.cmd == "whitelist" and args.wl_cmd == "add":
        cmd_whitelist_add(args)
    elif args.cmd == "continue":
        cmd_continue(args)
    elif args.cmd == "status":
        cmd_status(args)
    elif args.cmd == "login":
        cmd_login(args)
    elif args.cmd == "ruleset-current":
        cmd_ruleset_current(args)
    elif args.cmd == "events-send":
        cmd_events_send(args)
    elif args.cmd == "feedback-send":
        cmd_feedback_send(args)
    elif args.cmd == "pause":
        cmd_pause(args)
    elif args.cmd == "resume":
        cmd_resume(args)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
