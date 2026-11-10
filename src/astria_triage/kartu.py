"""Rakit `kode` kartu dari satu klaster dan hitung `paket_hash` (note app-triage 5.4 i, kontrak card.skeleton.created).

Determinisme: semua daftar diurutkan eksplisit, tidak ada waktu cetak atau nomor urut proses di `kode`, dan hash
memakai JSON kanonik (orjson, kunci terurut). `card_id`, `catalog_version`, dan `algo_version` di luar hash.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import orjson

from astria_triage import korelasi, peran, pola, skor
from astria_triage.katalog import Katalog
from astria_triage.model import Alert

ALGO_VERSION = "triage-0.1.0"


@dataclass(frozen=True, slots=True)
class Kartu:
    kode: dict[str, Any]
    paket_hash: str
    skor: int
    band: str
    first_ts: datetime
    last_ts: datetime
    hosts: tuple[str, ...]
    akun: tuple[str, ...]
    sumber_r: skor.Riwayat | None


def paket_hash(kode: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(orjson.dumps(kode, option=orjson.OPT_SORT_KEYS)).hexdigest()


def _unik_lipat(nilai: Sequence[str | None]) -> tuple[str, ...]:
    """Unik tanpa peka huruf (nilai pertama dalam urutan abjad mewakili), lalu terurut."""
    hasil: dict[str, str] = {}
    for v in sorted(x for x in nilai if x):
        hasil.setdefault(v.casefold(), v)
    return tuple(sorted(hasil.values()))


def _rujukan(alerts: Sequence[Alert], n: int) -> list[Alert]:
    """Maks n alert: yang paling awal, ditambah yang terakhir (mis. logon sukses setelah rentetan gagal)."""
    urut = sorted(alerts, key=lambda a: a.kunci_urut)
    return urut if len(urut) <= n else [*urut[: n - 1], urut[-1]]


def _teknik_attack(alerts: Sequence[Alert], katalog: Katalog) -> list[dict[str, str]]:
    peta = katalog.taktik.teknik
    pasangan: set[tuple[str, str]] = set()
    for a in alerts:
        milik_alert = set(a.taktik)
        for tid in a.teknik:
            dari_peta = set(peta.get(tid, ()))
            pilihan = (dari_peta & milik_alert) or dari_peta or ({min(milik_alert)} if milik_alert else set())
            pasangan.update((tid, t) for t in pilihan)
    return [{"id": tid, "taktik": t} for tid, t in sorted(pasangan)]


def rakit(alerts: Sequence[Alert], katalog: Katalog, riwayat: Sequence[skor.Riwayat] = ()) -> Kartu:
    if not alerts:
        raise ValueError("klaster kosong")
    urut = sorted({a.alert_id: a for a in alerts}.values(), key=lambda a: a.kunci_urut)
    aturan = katalog.korelasi
    temuan = korelasi.temukan(urut, aturan)
    kode_temuan = korelasi.kode_temuan(temuan)
    entitas = peran.turunkan(urut, temuan)

    hosts = _unik_lipat([a.host for a in urut])
    akun = _unik_lipat([a.akun for a in urut] + [a.aktor for a in urut])
    hasil_skor = skor.hitung(urut, hosts, akun, riwayat, katalog)

    host = peran.host_utama(urut)
    terpilih = pola.pilih(katalog.pola_insiden, kode_temuan)
    if terpilih:
        akun_judul = next((e.nilai for e in entitas if e.jenis == "akun" and e.peran == peran.DIDUGA_TERBOBOL), None)
        akun_judul = akun_judul or next((e.nilai for e in entitas if e.jenis == "akun"), "-")
        id_pola, judul = terpilih.pola, pola.isi_judul(terpilih.judul, {"akun": akun_judul, "host": host})
    else:
        umum = katalog.pola_insiden.umum
        n_taktik = len({t for a in urut for t in a.taktik})
        id_pola, judul = umum.pola, pola.isi_judul(umum.judul, {"host": host, "n_taktik": str(n_taktik)})

    n = aturan.maks_bukti_rujukan
    entitas_bukti = {(e.jenis, e.nilai): _rujukan(e.alerts, n) for e in entitas}
    if len(urut) <= aturan.maks_bukti_kartu:
        bukti_alert = urut
    else:
        rujukan = {a.alert_id: a for d in entitas_bukti.values() for a in d}
        rujukan |= {a.alert_id: a for t in temuan for a in _rujukan(t.alerts, n)}
        wakil: dict[str, Alert] = {}
        for a in urut:
            wakil.setdefault(a.rule_title, a)
        sisa = sorted((a for a in wakil.values() if a.alert_id not in rujukan), key=lambda a: a.evidence_id)
        bukti_alert = (sorted(rujukan.values(), key=lambda a: a.evidence_id) + sisa)[: aturan.maks_bukti_kartu]
    bukti = sorted({a.evidence_id: a.sha256 for a in bukti_alert}.items())
    ada = {i for i, _ in bukti}

    kode: dict[str, Any] = {
        "judul": judul,
        "pola": id_pola,
        "skor": hasil_skor.skor,
        "band": hasil_skor.band,
        "faktor": [{"nama": f.nama, "nilai": f.nilai, "alasan": f.alasan} for f in hasil_skor.faktor],
        "entitas": [
            {
                "jenis": e.jenis,
                "nilai": e.nilai,
                "peran": e.peran,
                "bukti": ids,
            }
            for e in entitas
            if (ids := sorted({a.evidence_id for a in entitas_bukti[(e.jenis, e.nilai)]} & ada))
        ],
        "bukti": [{"id": i, "sha256": s} for i, s in bukti],
        "teknik_attack": _teknik_attack(urut, katalog),
        "temuan_korelasi": kode_temuan,
    }
    return Kartu(
        kode=kode,
        paket_hash=paket_hash(kode),
        skor=hasil_skor.skor,
        band=hasil_skor.band,
        first_ts=urut[0].ts,
        last_ts=urut[-1].ts,
        hosts=hosts,
        akun=akun,
        sumber_r=hasil_skor.sumber_r,
    )


def data_event(kartu: Kartu, katalog: Katalog) -> dict[str, Any]:
    """`data` event `card.skeleton.created`."""
    return {
        "paket_hash": kartu.paket_hash,
        "catalog_version": katalog.versi,
        "algo_version": ALGO_VERSION,
        "kode": kartu.kode,
    }
