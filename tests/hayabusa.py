"""Baris Hayabusa JSONL -> bentuk jawaban API ingest (`AlertItem`, `EvidenceItem`) untuk tes tanpa ingest hidup.

Aturan disalin dari `astria_ingest.normalize` (ACCOUNT_KEYS, SRC_IP_KEYS, SEVERITY, kind) dan `render.render_fields`
(Details menang atas ExtraFieldInfo, nilai jadi teks). Sanitasi ingest tidak ditiru (tidak memengaruhi skor).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from astria_triage.katalog import bawaan
from astria_triage.model import Alert, dari_ingest

FIXTURES = Path(__file__).parent / "fixtures" / "samples"
ACCOUNT_KEYS = ("TgtUser", "TargetUserName", "User", "SubjectUserName", "SrcSID")
SRC_IP_KEYS = ("SrcIP", "IpAddress")
SEVERITY = {"info": "informational", "low": "low", "med": "medium", "high": "high", "crit": "critical"}
CHANNEL = {"Sec": "security", "Sys": "system", "App": "application"}


def _first(details: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    for k in keys:
        v = details.get(k)
        if isinstance(v, str) and v.strip() and v != "-":
            return v
    return None


def _teks(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return v if isinstance(v, str) else str(v)


def _ts(value: str) -> str:
    # "2026-11-10 02:14:07.000 +00:00" -> ISO UTC
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f %z").astimezone(UTC).isoformat()


def ingest_items(path: str, source: str) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    hasil = []
    for no, raw in enumerate((FIXTURES / path).read_bytes().splitlines(), start=1):
        if not raw.strip():
            continue
        r = json.loads(raw)
        details = r.get("Details") or {}
        extra = r.get("ExtraFieldInfo") or {}
        ev, al = f"EV-{source}-{no:06d}", f"AL-{source}-{no:06d}"
        account = _first(details, ACCOUNT_KEYS)
        item = {
            "alert_id": al,
            "evidence_ids": [ev],
            "record_no": no,
            "occurred_at": _ts(r["Timestamp"]),
            "host": r["Computer"],
            "account": account,
            "src_ip": _first(details, SRC_IP_KEYS),
            "rule_id": r.get("RuleID"),
            "rule_title": r["RuleTitle"],
            "level": r["Level"],
            "severity": SEVERITY.get(r["Level"], "unknown"),
            "tactics": r.get("MitreTactics") or [],
            "techniques": r.get("MitreTags") or [],
            "other_tags": r.get("OtherTags") or [],
            "kind": f"windows.{CHANNEL.get(r['Channel'], 'unknown')}.{r['EventID']}",
        }
        bukti = {
            "evidence_id": ev,
            "source_id": source,
            "record_no": no,
            "record_sha256": hashlib.sha256(raw).hexdigest(),
            "occurred_at": item["occurred_at"],
            "host": r["Computer"],
            "account": account,
            "kind": item["kind"],
            "fields": {k: _teks(v) for k, v in (extra | details).items()},
            "excerpt": "",
            "injection_suspect": False,
        }
        hasil.append((item, bukti))
    return hasil


def alerts(path: str, source: str = "hb01") -> list[Alert]:
    katalog = bawaan()
    return [dari_ingest(item, bukti, katalog) for item, bukti in ingest_items(path, source)]


def manifest() -> dict[str, Any]:
    return json.loads((FIXTURES / "manifest.json").read_text(encoding="utf-8"))
