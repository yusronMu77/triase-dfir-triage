"""Golden: tiga berkas samples menghasilkan skor, band, dan pola sesuai `harapan` di manifest."""

from __future__ import annotations

import hashlib

import pytest
from astria_common.events import new_event
from hayabusa import FIXTURES, alerts, manifest

from astria_triage.kartu import data_event, rakit
from astria_triage.katalog import bawaan
from astria_triage.klaster import klaster_terbelah
from astria_triage.skor import Riwayat

KAT = bawaan()
POLA_UMUM = KAT.pola_insiden.umum.pola


def _klaster(path: str, source: str = "hb01"):
    k = KAT.korelasi
    from datetime import timedelta

    return klaster_terbelah(
        alerts(path, source),
        timedelta(minutes=k.klaster_host_menit),
        timedelta(minutes=k.klaster_akun_menit),
        timedelta(hours=k.klaster_belah_jam),
    )


def _harapan(path: str) -> dict:
    return next(b["harapan"] for b in manifest()["berkas"] if b["path"] == path)


@pytest.mark.parametrize("berkas", manifest()["berkas"], ids=lambda b: b["path"])
def test_fixture_sama_dengan_manifest(berkas: dict) -> None:
    assert hashlib.sha256((FIXTURES / berkas["path"]).read_bytes()).hexdigest() == berkas["sha256"]


def test_riwayat_45_sedang_brute_tanpa_akses() -> None:
    (kl,) = _klaster("history/WS-ADM-04-brute-awal.jsonl")
    kartu = rakit(kl, KAT)
    h = _harapan("history/WS-ADM-04-brute-awal.jsonl")
    assert (kartu.skor, kartu.band, kartu.kode["pola"]) == (h["skor"], h["band"], h["pola"])
    assert kartu.kode["temuan_korelasi"] == ["K-BRUTE-TANPA-SUKSES"]
    assert [f["nilai"] for f in kartu.kode["faktor"]] == [15, 18, 10, 2, 0]
    assert kartu.kode["judul"] == "Percobaan menebak kata sandi terhadap svc-backup di WS-ADM-04 (belum ada akses)"


def _kartu_riwayat() -> Riwayat:
    (kl,) = _klaster("history/WS-ADM-04-brute-awal.jsonl", "hb02")
    k = rakit(kl, KAT)
    return Riwayat("IC-20261108-001", 1, k.band, k.first_ts, k.hosts, k.akun)


def test_rantai_72_tanpa_riwayat_77_dengan_riwayat() -> None:
    (kl,) = _klaster("chains/svc-backup.jsonl")
    tanpa = rakit(kl, KAT)
    assert (tanpa.skor, tanpa.band) == (72, "KRITIS")
    dengan = rakit(kl, KAT, [_kartu_riwayat()])
    h = _harapan("chains/svc-backup.jsonl")
    assert (dengan.skor, dengan.band, dengan.kode["pola"]) == (h["skor"], h["band"], h["pola"])
    assert [f["nilai"] for f in dengan.kode["faktor"]] == [30, 22, 10, 10, 5]
    assert "IC-20261108-001 v1 (SEDANG)" in dengan.kode["faktor"][4]["alasan"]
    assert dengan.kode["judul"] == "Dugaan pengambilalihan akun svc-backup di WS-ADM-04"
    assert dengan.kode["temuan_korelasi"] == [
        "K-AKUN-BARU-OLEH-AKUN-DIDUGA",
        "K-LOG-DIHAPUS-SETELAH-AKSES",
        "K-LOGON-SUKSES-SETELAH-GAGAL",
        "K-PERSISTENSI-SETELAH-AKSES",
    ]
    assert dengan.paket_hash != tanpa.paket_hash


def test_rantai_entitas_teknik_dan_bukti() -> None:
    (kl,) = _klaster("chains/svc-backup.jsonl")
    kode = rakit(kl, KAT).kode
    peran = {(e["jenis"], e["nilai"]): e["peran"] for e in kode["entitas"]}
    assert peran == {
        ("akun", "adm-support"): "DIBUAT_DALAM_INSIDEN",
        ("akun", "svc-backup"): "DIDUGA_TERBOBOL",
        ("host", "WS-ADM-04"): "TERDAMPAK",
        ("ip", "10.20.8.31"): "SUMBER_SERANGAN",
        ("tugas", "\\Microsoft\\Windows\\UpdateCheck"): "ARTEFAK_PERSISTENSI",
    }
    teknik = {t["id"] for t in kode["teknik_attack"]}
    assert {"T1110.003", "T1136.001", "T1098", "T1053.005", "T1685.005", "T1021.002"} <= teknik
    assert "T1070.001" not in teknik  # alias dipetakan ke ID kanonik
    assert not any(t["id"].startswith("S") for t in kode["teknik_attack"])  # S0039 dilewati
    assert {"id": "T1685.005", "taktik": "defense-impairment"} in kode["teknik_attack"]
    assert len(kode["bukti"]) == 31  # klaster kecil: semua bukti masuk
    semua = {b["id"] for b in kode["bukti"]}
    assert all(set(e["bukti"]) <= semua for e in kode["entitas"])


def test_j2_10_rendah_pola_umum() -> None:
    (kl,) = _klaster("benign/J2.jsonl")
    kartu = rakit(kl, KAT)
    h = _harapan("benign/J2.jsonl")
    assert (kartu.skor, kartu.band) == (h["skor"], h["band"])
    assert h["pola"] == "" and kartu.kode["pola"] == POLA_UMUM  # K8: tanpa pola -> pola umum
    assert kartu.kode["temuan_korelasi"] == []
    assert kartu.kode["judul"] == "Aktivitas mencurigakan di WS-KEU-02 (0 taktik)"


@pytest.mark.parametrize("path", ["history/WS-ADM-04-brute-awal.jsonl", "chains/svc-backup.jsonl", "benign/J2.jsonl"])
def test_data_event_lolos_kontrak(path: str) -> None:
    for kl in _klaster(path):
        env = new_event("card.skeleton.created", data_event(rakit(kl, KAT), KAT), event_id="x")
        assert env.data["kode"]["skor"] >= 0
