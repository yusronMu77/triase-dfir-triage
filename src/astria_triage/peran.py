"""Peran entitas diturunkan hanya dari temuan (tabel tetap, bukan model). Di antarmuka selalu berlabel "diduga"."""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from astria_triage.korelasi import AKUN_DIBUAT, K_AKUN_BARU, K_BRUTE, K_LOGON, K_PERSISTENSI, Temuan
from astria_triage.model import Alert

DIDUGA_TERBOBOL = "DIDUGA_TERBOBOL"
SUMBER_SERANGAN = "SUMBER_SERANGAN"
TERDAMPAK = "TERDAMPAK"
DIBUAT_DALAM_INSIDEN = "DIBUAT_DALAM_INSIDEN"
ARTEFAK_PERSISTENSI = "ARTEFAK_PERSISTENSI"

TUGAS_TERJADWAL = 4698


@dataclass(frozen=True, slots=True)
class Entitas:
    jenis: str
    nilai: str
    peran: str
    alerts: tuple[Alert, ...]


def host_utama(alerts: Sequence[Alert]) -> str:
    """Host paling sering di klaster; seri dipecah urutan abjad."""
    hitung = Counter(a.host for a in alerts)
    return min(hitung, key=lambda h: (-hitung[h], h))


def turunkan(alerts: Sequence[Alert], temuan: Sequence[Temuan]) -> list[Entitas]:
    """Satu entri per (jenis, nilai); bila satu nilai dapat dua peran, peran dari temuan yang lebih kuat menang."""
    hasil: dict[tuple[str, str], Entitas] = {}

    def pasang(jenis: str, nilai: str | None, peran: str, bukti: Sequence[Alert]) -> None:
        if not nilai or not bukti:
            return
        kunci = (jenis, nilai.casefold())
        if kunci not in hasil:
            hasil[kunci] = Entitas(jenis, nilai, peran, tuple(bukti))

    for t in temuan:
        if t.kode == K_LOGON:
            pasang("akun", t.akun, DIDUGA_TERBOBOL, t.alerts)
            pasang("ip", t.sumber, SUMBER_SERANGAN, t.alerts)
    for t in temuan:
        if t.kode == K_BRUTE:
            pasang("ip", t.sumber, SUMBER_SERANGAN, t.alerts)
            pasang("akun", t.akun, TERDAMPAK, t.alerts)
        elif t.kode == K_AKUN_BARU:
            for a in t.alerts:
                if a.event_id == AKUN_DIBUAT:
                    pasang("akun", a.akun, DIBUAT_DALAM_INSIDEN, [a])
        elif t.kode == K_PERSISTENSI:
            for a in t.alerts:
                if a.event_id == TUGAS_TERJADWAL:
                    pasang("tugas", a.artefak, ARTEFAK_PERSISTENSI, [a])  # satu kata: label templat narrative
    host = host_utama(alerts)
    pasang("host", host, TERDAMPAK, [a for a in alerts if a.host == host])
    return sorted(hasil.values(), key=lambda e: (e.jenis, e.nilai))
