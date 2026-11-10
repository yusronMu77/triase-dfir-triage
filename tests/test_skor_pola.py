from __future__ import annotations

import json
import random
from importlib import resources

import pytest
from hayabusa import alerts, ingest_items
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from astria_triage.kartu import rakit
from astria_triage.katalog import bawaan, muat
from astria_triage.model import dari_ingest, pisah_tag
from astria_triage.pola import cocok, isi_judul, pilih
from astria_triage.skor import band_dari

KAT = bawaan()


def _katalog_json() -> dict:
    return json.loads(resources.files("astria_triage.katalog").joinpath("katalog.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize(
    ("skor", "band"),
    [(0, "RENDAH"), (29, "RENDAH"), (30, "SEDANG"), (49, "SEDANG"), (50, "TINGGI"), (69, "TINGGI"), (70, "KRITIS")],
)
def test_batas_band(skor: int, band: str) -> None:
    assert band_dari(skor, KAT) == band


@given(st.integers(0, 100), st.integers(0, 100))
def test_properti_band_monoton(a: int, b: int) -> None:
    urutan = ["RENDAH", "SEDANG", "TINGGI", "KRITIS"]
    if a <= b:
        assert urutan.index(band_dari(a, KAT)) <= urutan.index(band_dari(b, KAT))


def test_interpreter_syarat() -> None:
    syarat = {"all": [{"temuan": "K-A"}, {"any": [{"temuan": "K-B"}, {"temuan": "K-C"}]}]}
    assert cocok(syarat, {"K-A", "K-C"})
    assert not cocok(syarat, {"K-A"})
    assert not cocok(syarat, {"K-B", "K-C"})


@pytest.mark.parametrize(
    "syarat",
    [
        {"eval": "__import__('os')"},
        {"temuan": "bukan-kode"},
        {"all": []},
        {"all": [{"temuan": "K-A"}], "any": [{"temuan": "K-B"}]},
        {"not": {"temuan": "K-A"}},
    ],
)
def test_katalog_menolak_node_tak_dikenal(syarat: dict) -> None:
    data = _katalog_json()
    data["pola_insiden"]["pola"][0]["syarat"] = syarat
    with pytest.raises(ValidationError):
        muat(json.dumps(data))


def test_katalog_menolak_placeholder_asing_dan_taktik_tanpa_bobot() -> None:
    data = _katalog_json()
    data["pola_insiden"]["pola"][0]["judul"] = "Akun {akun.__class__}"
    with pytest.raises(ValidationError):
        muat(json.dumps(data))
    data = _katalog_json()
    data["taktik"]["singkatan"]["Baru"] = "taktik-baru"
    with pytest.raises(ValidationError):
        muat(json.dumps(data))


def test_pilih_prioritas_lalu_abjad() -> None:
    data = _katalog_json()
    data["pola_insiden"]["pola"].append(
        {"pola": "P-AAA", "prioritas": 5, "syarat": {"temuan": "K-BRUTE-TANPA-SUKSES"}, "judul": "x"}
    )
    kat = muat(json.dumps(data))
    p = pilih(kat.pola_insiden, {"K-BRUTE-TANPA-SUKSES"})
    assert p is not None and p.pola == "P-AAA"
    assert pilih(kat.pola_insiden, set()) is None


def test_isi_judul_satu_lintasan_dan_dipotong() -> None:
    assert isi_judul("{akun} di {host}", {"akun": "{host}", "host": "H"}) == "{host} di H"
    assert isi_judul("{akun}", {"akun": "a\nb   c"}) == "a b c"
    assert len(isi_judul("{akun}", {"akun": "x" * 500})) == 200


def test_tag_non_teknik_dilewati_dan_alias_dipetakan() -> None:
    assert pisah_tag(["T1070.001", "S0039", "t1110.003", "G0016", ""]) == (
        ("T1110.003", "T1685.005"),
        ("G0016", "S0039"),
    )


def test_akun_pelaku_dari_fields() -> None:
    items = {i["alert_id"]: (i, b) for i, b in ingest_items("chains/svc-backup.jsonl", "hb01")}
    by_event = {}
    for item, bukti in items.values():
        a = dari_ingest(item, bukti, KAT)
        by_event.setdefault(a.event_id, a)
    assert by_event[4720].akun == "adm-support" and by_event[4720].aktor == "svc-backup"
    assert by_event[4732].aktor == "svc-backup"
    assert by_event[1102].aktor == "svc-backup"


def test_kestabilan_band_rantai_satu_alert_dibuang() -> None:
    """Rantai tanpa riwayat = 72; membuang satu alert mana pun tidak boleh menurunkan band di bawah TINGGI."""
    semua = alerts("chains/svc-backup.jsonl")
    for i in range(len(semua)):
        k = rakit(semua[:i] + semua[i + 1 :], KAT)
        assert k.band in ("KRITIS", "TINGGI"), (i, k.skor)


def test_properti_urutan_acak_paket_hash_sama() -> None:
    semua = alerts("chains/svc-backup.jsonl")
    acuan = rakit(semua, KAT).paket_hash
    rnd = random.Random(20261110)  # noqa: S311 - acak berbenih untuk uji urutan, bukan kriptografi
    for _ in range(50):
        acak = list(semua)
        rnd.shuffle(acak)
        assert rakit(acak, KAT).paket_hash == acuan


def test_brute_tetap_terdeteksi_walau_pemilik_akun_sukses_dari_ip_lain() -> None:
    from dataclasses import replace

    from astria_triage.korelasi import K_BRUTE, temukan

    riwayat = alerts("history/WS-ADM-04-brute-awal.jsonl")
    contoh = riwayat[0]
    sukses_lain = replace(
        contoh,
        alert_id="AL-hb01-000099",
        evidence_id="EV-hb01-000099",
        event_id=4624,
        src_ip="10.0.0.5",
        ts=contoh.ts.replace(minute=59),
    )
    kode = {t.kode for t in temukan([*riwayat, sukses_lain], KAT.korelasi)}
    assert K_BRUTE in kode
