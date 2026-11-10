"""Skor `min(100, L + T + A + K + R)` dan band (note app-triage 5.4 h). Satu-satunya penulis skor; tanpa model.

| Faktor | Isi |
|---|---|
| L level_aturan | Bobot level tertinggi di klaster |
| T taktik_terjauh | Bobot taktik paling lanjut |
| A kritikalitas_aset | Kritikalitas host tertinggi; host tak terdaftar = bawaan katalog + penanda |
| K korelasi_taktik | min(maks, per_taktik x jumlah taktik berbeda) |
| R pengulangan | + bila host/akun sama sudah punya kartu band tertentu dalam N hari sebelum klaster ini |

R memakai kartu lain, jadi alasan R menyebut `card_id` dan versi sumbernya: proses ulang dengan riwayat yang sama
memberi hasil yang sama.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from astria_triage.katalog import Katalog
from astria_triage.model import Alert


@dataclass(frozen=True, slots=True)
class Faktor:
    nama: str
    nilai: int
    alasan: str


@dataclass(frozen=True, slots=True)
class Riwayat:
    """Kartu terbit lain yang bisa memicu faktor R."""

    card_id: str
    version: int
    band: str
    first_ts: datetime
    hosts: tuple[str, ...]
    akun: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class HasilSkor:
    faktor: tuple[Faktor, ...]
    skor: int
    band: str
    sumber_r: Riwayat | None


def band_dari(skor: int, katalog: Katalog) -> str:
    for band in ("KRITIS", "TINGGI", "SEDANG"):
        if skor >= katalog.skor.band[band]:  # type: ignore[index]
            return band
    return "RENDAH"


def _lipat(nilai: Sequence[str]) -> set[str]:
    return {v.casefold() for v in nilai}


def pilih_riwayat(
    riwayat: Sequence[Riwayat], hosts: Sequence[str], akun: Sequence[str], first_ts: datetime, katalog: Katalog
) -> Riwayat | None:
    """Kartu riwayat terbaru yang memenuhi syarat R (seri: card_id terkecil)."""
    sk = katalog.skor
    batas = first_ts - timedelta(days=sk.pengulangan_hari)
    h, k = _lipat(hosts), _lipat(akun)
    calon = [
        r
        for r in riwayat
        if r.band in sk.pengulangan_band
        and batas <= r.first_ts < first_ts
        and (h & _lipat(r.hosts) or k & _lipat(r.akun))
    ]
    return min(calon, key=lambda r: (-r.first_ts.timestamp(), r.card_id)) if calon else None


def hitung(
    alerts: Sequence[Alert],
    hosts: Sequence[str],
    akun: Sequence[str],
    riwayat: Sequence[Riwayat],
    katalog: Katalog,
) -> HasilSkor:
    sk = katalog.skor
    first_ts = min(a.ts for a in alerts)

    # L
    lv = max(alerts, key=lambda a: (sk.level.get(a.severity, 0), a.severity))
    nilai_l = sk.level.get(lv.severity, 0)
    l_ = Faktor("level_aturan", nilai_l, f"level tertinggi: {lv.severity} ({lv.rule_title})")

    # T
    taktik = sorted({t for a in alerts for t in a.taktik})
    if taktik:
        terjauh = max(taktik, key=lambda t: (sk.taktik.get(t, 0), t))
        t_ = Faktor("taktik_terjauh", sk.taktik.get(terjauh, 0), f"taktik terjauh: {terjauh}")
    else:
        t_ = Faktor("taktik_terjauh", 0, "tanpa taktik")

    # A
    def kelas(host: str) -> tuple[str, bool]:
        terdaftar = {k.casefold(): v for k, v in katalog.aset.host.items()}
        return (terdaftar[host.casefold()], True) if host.casefold() in terdaftar else (katalog.aset.bawaan, False)

    host_a = max(sorted(set(hosts)), key=lambda h: sk.aset[kelas(h)[0]])  # type: ignore[index]
    kls, terdaftar = kelas(host_a)
    a_ = Faktor(
        "kritikalitas_aset",
        sk.aset[kls],  # type: ignore[index]
        f"{host_a}: kritikalitas {kls}" + ("" if terdaftar else " (aset tak terdaftar)"),
    )

    # K
    k_ = Faktor(
        "korelasi_taktik",
        min(sk.korelasi_maks, sk.korelasi_per_taktik * len(taktik)),
        f"{len(taktik)} taktik berbeda" + (f": {', '.join(taktik)}" if taktik else ""),
    )

    # R
    sumber = pilih_riwayat(riwayat, hosts, akun, first_ts, katalog)
    if sumber:
        r_ = Faktor(
            "pengulangan",
            sk.pengulangan,
            f"kartu {sumber.card_id} v{sumber.version} ({sumber.band}) dalam {sk.pengulangan_hari} hari sebelumnya",
        )
    else:
        r_ = Faktor("pengulangan", 0, f"tanpa kartu serupa dalam {sk.pengulangan_hari} hari sebelumnya")

    faktor = (l_, t_, a_, k_, r_)
    skor = max(0, min(100, sum(f.nilai for f in faktor)))
    return HasilSkor(faktor, skor, band_dari(skor, katalog), sumber)
