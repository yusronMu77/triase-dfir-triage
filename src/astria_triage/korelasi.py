"""Temuan korelasi `K-*` dari satu klaster terurut (note app-triage 5.4 e). Setiap temuan menyimpan ID bukti.

| Kode | Syarat |
|---|---|
| K-LOGON-SUKSES-SETELAH-GAGAL | Logon sukses (4624) akun sama <= jendela setelah >= N gagal (4625) dari IP yang sama |
| K-BRUTE-TANPA-SUKSES | >= N gagal dari IP sama ke akun sama dalam jendela, tanpa logon sukses dari IP itu sesudahnya |
| K-AKUN-BARU-OLEH-AKUN-DIDUGA | Akun dibuat (4720) atau dimasukkan ke grup (4732) oleh akun yang diduga terbobol |
| K-PERSISTENSI-SETELAH-AKSES | Alert bertaktik persistence di host yang sama setelah logon sukses akun terbobol |
| K-LOG-DIHAPUS-SETELAH-AKSES | Log dihapus (1102) oleh akun terbobol setelah logon sukses |
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from astria_triage.katalog import Korelasi
from astria_triage.model import Alert, sama

LOGON_GAGAL = 4625
LOGON_SUKSES = 4624
AKUN_DIBUAT = 4720
MASUK_GRUP = 4732
LOG_DIHAPUS = 1102

K_LOGON = "K-LOGON-SUKSES-SETELAH-GAGAL"
K_BRUTE = "K-BRUTE-TANPA-SUKSES"
K_AKUN_BARU = "K-AKUN-BARU-OLEH-AKUN-DIDUGA"
K_PERSISTENSI = "K-PERSISTENSI-SETELAH-AKSES"
K_LOG_DIHAPUS = "K-LOG-DIHAPUS-SETELAH-AKSES"


@dataclass(frozen=True, slots=True)
class Temuan:
    kode: str
    alerts: tuple[Alert, ...]
    """Alert pembangun temuan, terurut waktu."""
    akun: str | None = None
    sumber: str | None = None
    host: str | None = None
    sejak: datetime | None = None
    """Waktu logon sukses (akses) untuk temuan K-LOGON."""

    @property
    def bukti(self) -> tuple[str, ...]:
        return tuple(sorted({a.evidence_id for a in self.alerts}))


def _gagal_dalam_jendela(gagal: Sequence[Alert], minimal: int, jendela: timedelta) -> tuple[Alert, ...] | None:
    """Jendela pertama (urut waktu) yang memuat >= `minimal` kegagalan."""
    kiri = 0
    for kanan in range(len(gagal)):
        while gagal[kanan].ts - gagal[kiri].ts > jendela:
            kiri += 1
        if kanan - kiri + 1 >= minimal:
            akhir = kanan
            while akhir + 1 < len(gagal) and gagal[akhir + 1].ts - gagal[kiri].ts <= jendela:
                akhir += 1
            return tuple(gagal[kiri : akhir + 1])
    return None


def temukan(alerts: Sequence[Alert], aturan: Korelasi) -> list[Temuan]:
    urut = sorted(alerts, key=lambda a: a.kunci_urut)
    jendela = timedelta(minutes=aturan.logon_jendela_menit)
    gagal = [a for a in urut if a.event_id == LOGON_GAGAL and a.akun and a.src_ip]
    sukses = [a for a in urut if a.event_id == LOGON_SUKSES and a.akun]
    hasil: list[Temuan] = []

    # Kelompok kegagalan per (akun, sumber), urutan kunci deterministik.
    per_pasangan: dict[tuple[str, str], list[Alert]] = {}
    for a in gagal:
        per_pasangan.setdefault((a.akun.casefold(), a.src_ip), []).append(a)  # type: ignore[union-attr]

    terbobol: list[Temuan] = []
    for (_, sumber), daftar in sorted(per_pasangan.items()):
        akun = daftar[0].akun
        for s in sukses:
            if not sama(s.akun, akun) or s.src_ip != sumber:
                continue
            sebelum = [g for g in daftar if s.ts - jendela <= g.ts <= s.ts]
            if len(sebelum) >= aturan.logon_min_gagal:
                terbobol.append(Temuan(K_LOGON, (*sebelum, s), akun=akun, sumber=sumber, host=s.host, sejak=s.ts))
                break
        else:
            # Sukses dari IP lain (mis. pemilik akun di stasiunnya sendiri) tidak menghapus temuan brute force;
            # sukses dari IP yang sama dalam jendela sudah menjadi K-LOGON di atas.
            blok = _gagal_dalam_jendela(daftar, aturan.logon_min_gagal, jendela)
            if blok and not any(sama(s.akun, akun) and s.src_ip == sumber and s.ts >= blok[0].ts for s in sukses):
                hasil.append(Temuan(K_BRUTE, blok, akun=akun, sumber=sumber, host=blok[-1].host))
    hasil.extend(terbobol)

    for t in terbobol:
        assert t.sejak is not None
        setelah = [a for a in urut if a.ts >= t.sejak]
        akun_baru = [a for a in setelah if a.event_id in (AKUN_DIBUAT, MASUK_GRUP) and sama(a.aktor, t.akun)]
        if akun_baru:
            hasil.append(Temuan(K_AKUN_BARU, tuple(akun_baru), akun=t.akun, host=t.host, sejak=t.sejak))
        persistensi = [a for a in setelah if "persistence" in a.taktik and sama(a.host, t.host)]
        if persistensi:
            hasil.append(Temuan(K_PERSISTENSI, tuple(persistensi), akun=t.akun, host=t.host, sejak=t.sejak))
        hapus_log = [a for a in setelah if a.event_id == LOG_DIHAPUS and sama(a.aktor, t.akun)]
        if hapus_log:
            hasil.append(Temuan(K_LOG_DIHAPUS, tuple(hapus_log), akun=t.akun, host=t.host, sejak=t.sejak))

    return sorted(hasil, key=lambda t: (t.kode, t.akun or "", t.sumber or "", t.bukti))


def kode_temuan(temuan: Sequence[Temuan]) -> list[str]:
    return sorted({t.kode for t in temuan})
