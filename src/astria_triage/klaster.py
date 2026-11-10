"""Klaster alert: sapuan waktu + union-find, lalu pembelahan klaster yang lebih dari N jam (note app-triage 5.4 b-c).

Dua alert satu klaster bila host sama dan selisih <= jendela host, atau akun sama dan selisih <= jendela akun.
Cukup menghubungkan tiap alert dengan alert sebelumnya pada host/akun yang sama: pasangan lain dalam jendela
selalu terhubung lewat rantai pasangan berurutan. Hasil terurut, tidak bergantung urutan input.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import timedelta

from astria_triage.model import Alert


class UnionFind:
    def __init__(self) -> None:
        self._induk: dict[str, str] = {}
        self._ukuran: dict[str, int] = {}

    def tambah(self, x: str) -> None:
        if x not in self._induk:
            self._induk[x] = x
            self._ukuran[x] = 1

    def cari(self, x: str) -> str:
        while self._induk[x] != x:
            self._induk[x] = self._induk[self._induk[x]]  # path halving
            x = self._induk[x]
        return x

    def gabung(self, a: str, b: str) -> None:
        ra, rb = self.cari(a), self.cari(b)
        if ra == rb:
            return
        if self._ukuran[ra] < self._ukuran[rb]:
            ra, rb = rb, ra
        self._induk[rb] = ra
        self._ukuran[ra] += self._ukuran[rb]


def _kunci(nilai: str | None) -> str | None:
    return nilai.casefold() if nilai else None


def klaster(alerts: Iterable[Alert], jendela_host: timedelta, jendela_akun: timedelta) -> list[list[Alert]]:
    urut = sorted({a.alert_id: a for a in alerts}.values(), key=lambda a: a.kunci_urut)
    uf = UnionFind()
    terakhir_host: dict[str, Alert] = {}
    terakhir_akun: dict[str, Alert] = {}
    for a in urut:
        uf.tambah(a.alert_id)
        host, akun = _kunci(a.host), _kunci(a.akun)
        if host and (p := terakhir_host.get(host)) and a.ts - p.ts <= jendela_host:
            uf.gabung(a.alert_id, p.alert_id)
        if akun and (p := terakhir_akun.get(akun)) and a.ts - p.ts <= jendela_akun:
            uf.gabung(a.alert_id, p.alert_id)
        if host:
            terakhir_host[host] = a
        if akun:
            terakhir_akun[akun] = a
    kelompok: dict[str, list[Alert]] = {}
    for a in urut:
        kelompok.setdefault(uf.cari(a.alert_id), []).append(a)
    return sorted(kelompok.values(), key=lambda k: k[0].kunci_urut)


def belah(kelompok: Sequence[Alert], maks: timedelta) -> list[list[Alert]]:
    """Belah pada celah waktu terbesar sampai tiap bagian <= `maks`.

    Seri dipecah oleh celah yang paling dekat ke tengah bagian (lalu yang paling awal). Rancangan menyebut "paling
    awal", tetapi itu mengupas alert berjarak rata satu per satu (banyak kartu satu alert); tengah membagi dua.
    Iteratif dengan tumpukan, jadi tidak ada batas rekursi.
    """
    hasil: list[list[Alert]] = []
    tumpukan = [sorted(kelompok, key=lambda a: a.kunci_urut)]
    while tumpukan:
        urut = tumpukan.pop()
        if len(urut) < 2 or urut[-1].ts - urut[0].ts <= maks:
            hasil.append(urut)
            continue
        tengah = len(urut) / 2
        celah = max(range(1, len(urut)), key=lambda i: (urut[i].ts - urut[i - 1].ts, -abs(i - tengah), -i))
        tumpukan.extend([urut[celah:], urut[:celah]])
    return sorted(hasil, key=lambda k: k[0].kunci_urut)


def klaster_terbelah(
    alerts: Iterable[Alert], jendela_host: timedelta, jendela_akun: timedelta, maks: timedelta
) -> list[list[Alert]]:
    hasil = [b for k in klaster(alerts, jendela_host, jendela_akun) for b in belah(k, maks)]
    return sorted(hasil, key=lambda k: k[0].kunci_urut)
