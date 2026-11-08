"""ID teknik MITRE ATT&CK: ID kanonik (v19) dan ID lama yang masih keluar dari sumber alert.

Keputusan pemilik (triage#2): kedua ID didukung, T1685.005 dan T1070.001, karena keduanya benar pada
waktu yang berbeda dan sumber data masih memakai yang lama.

Bukti dua kali (diperiksa 2026-11-08):
1. Pencarian web: halaman resmi MITRE T1685.005 "Disable or Modify Tools: Clear Windows Event Logs" muncul sebagai
   hasil teratas, dan ringkasan ATT&CK v19 menyebut T1070.001 dialihkan ke T1685.005.
2. Scrape halaman resmi: `attack.mitre.org/techniques/T1070/001/` dialihkan ke `/techniques/T1685/005/`
   (sub-teknik T1685, taktik Defense Impairment TA0112, dibuat 14 Apr 2026, diubah 12 Mei 2026).
Hayabusa v4.3.1 pada data nyata masih mengeluarkan `T1070.001` dengan taktik `Stealth`
(note 2026-11-07-hayabusa-v4-format-jsonl.md). Jadi ingest menerima keduanya dan triage menyimpan satu ID kanonik.
"""

from __future__ import annotations

import re

ATTACK_VERSION = "v19"

_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# ID lama (ATT&CK <= v18) -> ID kanonik (v19). Tambahkan baris di sini bila ada teknik lain yang berpindah.
LEGACY_TO_CANONICAL: dict[str, str] = {
    "T1070.001": "T1685.005",  # Clear Windows Event Logs: dipindah ke Disable or Modify Tools (Defense Impairment)
}
CANONICAL_TO_LEGACY: dict[str, tuple[str, ...]] = {}
for _old, _new in LEGACY_TO_CANONICAL.items():
    CANONICAL_TO_LEGACY[_new] = (*CANONICAL_TO_LEGACY.get(_new, ()), _old)


class InvalidTechniqueId(ValueError):
    pass


def normalize_technique(technique_id: str) -> str:
    """ID kanonik (v19). ID lama dipetakan; ID lain dikembalikan apa adanya setelah divalidasi bentuknya."""
    tid = technique_id.strip().upper()
    if not _ID.match(tid):
        raise InvalidTechniqueId(f"ID teknik ATT&CK tidak valid: {technique_id!r}")
    return LEGACY_TO_CANONICAL.get(tid, tid)


def same_technique(a: str, b: str) -> bool:
    """T1070.001 dan T1685.005 dianggap teknik yang sama."""
    return normalize_technique(a) == normalize_technique(b)


def accepted_ids(technique_id: str) -> tuple[str, ...]:
    """Semua ID yang sah untuk teknik ini: kanonik dulu, lalu ID lama. Untuk pencocokan aturan dan label uji."""
    canonical = normalize_technique(technique_id)
    return (canonical, *CANONICAL_TO_LEGACY.get(canonical, ()))
