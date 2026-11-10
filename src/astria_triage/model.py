"""Alert yang dipakai perhitungan triage: gabungan `AlertItem` (alert per job) dan `EvidenceItem` (bukti) dari ingest.

Semua waktu UTC dari bukti; tidak ada jam sekarang di perhitungan. Nilai teks sudah disanitasi ingest saat keluar.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from astria_triage.attack import normalize_technique
from astria_triage.katalog import Katalog

_TEKNIK = re.compile(r"^T\d{4}(?:\.\d{3})?$", re.IGNORECASE)
_EVENT_DARI_KIND = re.compile(r"\.(\d{1,5})$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_KOSONG = {"", "-"}

# Akun yang menjalankan aksi (pelaku), beda dari `account` ingest yang mengutamakan akun sasaran (TgtUser).
# 4720/4732/1102: SubjectUserName; 4688/4698: User.
AKTOR_KEYS = ("SubjectUserName", "User")
ARTEFAK_KEYS = ("Name",)


class AlertTidakValid(ValueError):
    """Data alert dari ingest tidak lengkap atau tidak cocok dengan buktinya (galat data, permanen)."""


@dataclass(frozen=True, slots=True)
class Alert:
    alert_id: str
    evidence_id: str
    sha256: str
    ts: datetime
    host: str
    akun: str | None
    aktor: str | None
    src_ip: str | None
    event_id: int | None
    rule_title: str
    rule_id: str | None
    severity: str
    taktik: tuple[str, ...]
    teknik: tuple[str, ...]
    tag_lain: tuple[str, ...]
    artefak: str | None = None

    @property
    def kunci_urut(self) -> tuple[datetime, str]:
        return (self.ts, self.alert_id)

    def to_json(self) -> dict[str, Any]:
        d = asdict(self)
        d["ts"] = self.ts.isoformat()
        d["taktik"], d["teknik"], d["tag_lain"] = list(self.taktik), list(self.teknik), list(self.tag_lain)
        return d

    @classmethod
    def from_json(cls, d: Mapping[str, Any]) -> Alert:
        return cls(
            **{
                **d,
                "ts": parse_ts(d["ts"]),
                "taktik": tuple(d["taktik"]),
                "teknik": tuple(d["teknik"]),
                "tag_lain": tuple(d["tag_lain"]),
            }
        )


def parse_ts(value: str) -> datetime:
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if ts.tzinfo is None:
        raise AlertTidakValid(f"waktu tanpa zona: {value!r}")
    return ts.astimezone(UTC)


def _teks(value: Any) -> str | None:
    if isinstance(value, str) and value.strip() not in _KOSONG:
        return value.strip()
    return None


def pisah_tag(tags: list[str]) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """MitreTags -> (teknik kanonik terurut unik, tag lain mis. S0039). Tag non-teknik tidak melempar galat."""
    teknik: set[str] = set()
    lain: set[str] = set()
    for tag in tags:
        if _TEKNIK.match(tag.strip()):
            teknik.add(normalize_technique(tag))
        elif tag.strip():
            lain.add(tag.strip())
    return tuple(sorted(teknik)), tuple(sorted(lain))


def dari_ingest(item: Mapping[str, Any], bukti: Mapping[str, Any], katalog: Katalog) -> Alert:
    """Satu `AlertItem` + `EvidenceItem` miliknya -> `Alert`."""
    ids = item.get("evidence_ids") or []
    if len(ids) != 1 or bukti.get("evidence_id") != ids[0]:
        raise AlertTidakValid(f"bukti tidak cocok untuk {item.get('alert_id')!r}")
    sha = bukti.get("record_sha256")
    if not isinstance(sha, str) or not _SHA256.match(sha):
        raise AlertTidakValid(f"record_sha256 tidak valid untuk {ids[0]!r}")
    fields: Mapping[str, Any] = bukti.get("fields") or {}
    m = _EVENT_DARI_KIND.search(str(item.get("kind", "")))
    taktik = sorted({s for t in item.get("tactics") or [] if (s := katalog.slug_taktik(t))})
    teknik, lain = pisah_tag(list(item.get("techniques") or []) + list(item.get("other_tags") or []))
    return Alert(
        alert_id=str(item["alert_id"]),
        evidence_id=ids[0],
        sha256=sha,
        ts=parse_ts(str(item["occurred_at"])),
        host=str(item["host"]),
        akun=_teks(item.get("account")),
        aktor=next((v for k in AKTOR_KEYS if (v := _teks(fields.get(k)))), None),
        src_ip=_teks(item.get("src_ip")),
        event_id=int(m.group(1)) if m else None,
        rule_title=str(item.get("rule_title") or ""),
        rule_id=_teks(item.get("rule_id")),
        severity=str(item.get("severity") or "unknown"),
        taktik=tuple(taktik),
        teknik=teknik,
        tag_lain=lain,
        artefak=next((v for k in ARTEFAK_KEYS if (v := _teks(fields.get(k)))), None),
    )


def sama(a: str | None, b: str | None) -> bool:
    """Nama akun/host Windows tidak peka huruf besar-kecil."""
    return a is not None and b is not None and a.casefold() == b.casefold()
