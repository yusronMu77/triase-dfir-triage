"""Katalog `alert_penjelasan` (triage#4): tiap aturan pada dataset samples punya penjelas yang cocok dengan datanya."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import timedelta
from importlib import resources
from types import SimpleNamespace
from typing import Any

import pytest
from hayabusa import FIXTURES, alerts, ingest_items, manifest
from pydantic import ValidationError

from astria_triage import pipeline
from astria_triage.kartu import data_event, rakit
from astria_triage.katalog import Penjelasan, bawaan, muat
from astria_triage.klaster import klaster_terbelah

KAT = bawaan()
BERKAS = [b["path"] for b in manifest()["berkas"]]
KANAL = {"Sec": "Security", "Sys": "System", "App": "Application"}
KUNCI_CONFIG = {"judul", "penjelasan", "penyebab_jinak", "yang_dicek", "rujukan"}


def _baris(path: str) -> list[dict[str, Any]]:
    return [json.loads(x) for x in (FIXTURES / path).read_bytes().splitlines() if x.strip()]


def _dipakai() -> dict[str, dict[str, set[Any]]]:
    """RuleID -> {judul, event, kanal, berkas_aturan, teknik, path} dari semua berkas dataset."""
    peta: dict[str, dict[str, set[Any]]] = defaultdict(lambda: defaultdict(set))
    for path in BERKAS:
        for r in _baris(path):
            p = peta[r["RuleID"]]
            p["judul"].add(r["RuleTitle"])
            p["event"].add(r["EventID"])
            p["kanal"].add(KANAL[r["Channel"]])
            p["berkas_aturan"].add(r["RuleFile"])
            p["teknik"].update(r.get("MitreTags") or [])
            p["path"].add(path)
    return peta


DIPAKAI = _dipakai()


def test_inventaris_tidak_kosong_dan_mencakup_semua_rantai() -> None:
    rantai = [p for p in BERKAS if p.startswith("chains/")]
    assert len(rantai) >= 8
    dari_rantai = {rid for rid, p in DIPAKAI.items() if any(x.startswith("chains/") for x in p["path"])}
    assert dari_rantai and dari_rantai <= set(KAT.alert_penjelasan.entries)


def test_semua_aturan_dataset_punya_penjelas() -> None:
    assert set(DIPAKAI) - set(KAT.alert_penjelasan.entries) == set()
    assert KAT.tanpa_penjelasan(DIPAKAI) == ()


def test_tidak_ada_entri_yatim() -> None:
    """Katalog hanya memuat aturan yang muncul di dataset; entri baru menuntut sampel yang memakainya."""
    assert set(KAT.alert_penjelasan.entries) - set(DIPAKAI) == set()


@pytest.mark.parametrize("path", BERKAS)
def test_alert_dari_pipeline_menemukan_penjelas(path: str) -> None:
    """Jalur nyata: baris -> bentuk ingest -> `Alert.rule_id` -> katalog."""
    hasil = alerts(path)
    assert hasil
    for a in hasil:
        entri = KAT.penjelasan(a.rule_id)
        assert entri is not None, f"{a.rule_title} ({a.rule_id}) di {path}"


def test_id_aturan_tidak_ganda_di_berkas_katalog() -> None:
    def tolak_ganda(pasangan: list[tuple[str, Any]]) -> dict[str, Any]:
        kunci = [k for k, _ in pasangan]
        assert len(kunci) == len(set(kunci)), f"kunci ganda: {sorted({k for k in kunci if kunci.count(k) > 1})}"
        return dict(pasangan)

    teks = resources.files("astria_triage.katalog").joinpath("katalog.json").read_text(encoding="utf-8")
    json.loads(teks, object_pairs_hook=tolak_ganda)


def test_judul_unik() -> None:
    judul = [e.judul for e in KAT.alert_penjelasan.entries.values()]
    assert len(judul) == len(set(judul))


@pytest.mark.parametrize("rid", sorted(DIPAKAI))
def test_rujukan_sesuai_data_aturan(rid: str) -> None:
    """Tidak ada klaim yang tak didukung data: EventID, kanal, berkas aturan, dan teknik harus ada di dataset."""
    entri = KAT.alert_penjelasan.entries[rid]
    data = DIPAKAI[rid]
    teknik = {r for r in entri.rujukan if re.fullmatch(r"T\d{4}(\.\d{3})?", r)}
    assert teknik <= data["teknik"], f"teknik di luar tag aturan: {sorted(teknik - data['teknik'])}"
    for r in entri.rujukan:
        if m := re.fullmatch(r"Windows (Security|System|Application) (\d+)", r):
            assert m[1] in data["kanal"] and int(m[2]) in data["event"], r
        elif r.startswith("Hayabusa: "):
            assert r.removeprefix("Hayabusa: ") in data["berkas_aturan"], r
        else:
            assert r in teknik, f"rujukan tak dikenal: {r}"
    assert any(r.startswith("Windows ") for r in entri.rujukan)
    assert any(r.startswith("Hayabusa: ") for r in entri.rujukan)
    assert {int(n) for n in re.findall(r"EventID (\d+)", entri.penjelasan)} <= data["event"]


def test_bentuk_entri_sama_dengan_kontrak_config() -> None:
    """Layanan config (`alert_penjelasan`) memakai kunci ini; penambahan kunci harus bersama config."""
    assert set(Penjelasan.model_fields) == KUNCI_CONFIG


def _dokumen() -> dict[str, Any]:
    teks = resources.files("astria_triage.katalog").joinpath("katalog.json").read_text(encoding="utf-8")
    return json.loads(teks)


def _entri_pertama(doc: dict[str, Any]) -> dict[str, Any]:
    return next(iter(doc["alert_penjelasan"]["entries"].values()))


def _rusak_id(doc: dict[str, Any]) -> None:
    e = doc["alert_penjelasan"]["entries"]
    e["bukan-uuid"] = e.pop(next(iter(e)))


def _rusak_kosong(doc: dict[str, Any]) -> None:
    _entri_pertama(doc)["yang_dicek"] = []


def _rusak_judul(doc: dict[str, Any]) -> None:
    _entri_pertama(doc)["judul"] = ""


def _rusak_kunci_asing(doc: dict[str, Any]) -> None:
    _entri_pertama(doc)["skor"] = 99


def _rusak_hilang(doc: dict[str, Any]) -> None:
    del _entri_pertama(doc)["penjelasan"]


def _rusak_tanpa_bagian(doc: dict[str, Any]) -> None:
    del doc["alert_penjelasan"]


def _rusak_versi(doc: dict[str, Any]) -> None:
    doc["alert_penjelasan"]["versi"] = 0


@pytest.mark.parametrize(
    "rusak",
    [_rusak_id, _rusak_kosong, _rusak_judul, _rusak_kunci_asing, _rusak_hilang, _rusak_tanpa_bagian, _rusak_versi],
)
def test_entri_rusak_ditolak_saat_muat(rusak: Any) -> None:
    doc = _dokumen()
    rusak(doc)
    with pytest.raises(ValidationError):
        muat(json.dumps(doc))


def test_katalog_utuh_bisa_dimuat_ulang() -> None:
    assert muat(json.dumps(_dokumen())) == KAT


def test_lookup_aturan_dikenal() -> None:
    rid = "e87bd730-df45-4ae9-85de-6c75369c5d29"
    entri = KAT.penjelasan(rid)
    assert entri is not None
    assert entri.judul == "Logon gagal: kata sandi salah"
    assert KAT.penjelasan(rid.upper()) is entri
    assert KAT.penjelasan(f"  {rid}\n") is entri
    assert KAT.penjelasan(rid) is KAT.penjelasan(rid)


@pytest.mark.parametrize(
    "nilai",
    [None, "", "   ", "tidak-ada", "00000000-0000-0000-0000-000000000000", 4625, ["x"], {"a": 1}, "x" * 10_000],
)
def test_lookup_tak_dikenal_aman(nilai: object) -> None:
    assert KAT.penjelasan(nilai) is None


def test_tanpa_penjelasan_terurut_unik_dan_mengabaikan_kosong() -> None:
    ada = "e87bd730-df45-4ae9-85de-6c75369c5d29"
    hasil = KAT.tanpa_penjelasan([ada, "b-asing", None, "", "a-asing", "b-asing"])
    assert hasil == ("a-asing", "b-asing")


def test_versi_katalog_di_event_memuat_alert_penjelasan() -> None:
    assert KAT.versi["alert_penjelasan"] == KAT.alert_penjelasan.versi
    assert all(isinstance(v, int) and v >= 0 for v in KAT.versi.values())


def test_kartu_tidak_berubah_dan_event_membawa_versi_penjelas() -> None:
    """Penjelas bukan masukan skor: `kode` dan `paket_hash` sama dengan katalog yang penjelasnya dikosongkan."""
    doc = _dokumen()
    doc["alert_penjelasan"]["entries"] = {}
    kosong = muat(json.dumps(doc))
    pasangan: list[tuple[Any, Any]] = []
    for kat in (KAT, kosong):
        k = kat.korelasi
        (kl, *_) = klaster_terbelah(
            alerts("chains/r1-brute-force.jsonl"),
            timedelta(minutes=k.klaster_host_menit),
            timedelta(minutes=k.klaster_akun_menit),
            timedelta(hours=k.klaster_belah_jam),
        )
        pasangan.append((rakit(kl, kat), kat))
    (a, ka), (b, kb) = pasangan
    assert a.paket_hash == b.paket_hash and a.kode == b.kode
    assert data_event(a, ka)["catalog_version"]["alert_penjelasan"] == 1
    assert data_event(b, kb)["catalog_version"]["alert_penjelasan"] == 1


class _Sumber:
    def __init__(self, path: str) -> None:
        pasangan = ingest_items(path, "hb01")
        self._items = [i for i, _ in pasangan]
        self._bukti = {b["evidence_id"]: b for _, b in pasangan}

    async def alerts(self, rentang: object) -> list[dict[str, Any]]:
        return self._items

    async def bukti(self, ids: Any) -> dict[str, dict[str, Any]]:
        return self._bukti


class _Catat:
    def __init__(self) -> None:
        self.baris: list[tuple[str, str, dict[str, Any]]] = []

    def warning(self, event: str, **kw: Any) -> None:
        self.baris.append(("warning", event, kw))

    def info(self, event: str, **kw: Any) -> None:
        self.baris.append(("info", event, kw))


async def _jalankan(monkeypatch: pytest.MonkeyPatch, katalog: Any, path: str) -> list[tuple[str, str, dict[str, Any]]]:
    catat = _Catat()
    monkeypatch.setattr(pipeline, "log", catat)

    async def proses(self: Any, conn: Any, alerts: Any, *, trace_id: Any = None) -> int:
        return 0

    monkeypatch.setattr(pipeline.Triage, "proses", proses)
    triage = pipeline.Triage(_Sumber(path), katalog)  # type: ignore[arg-type]
    data = SimpleNamespace(batch_ref="/svc/v1/jobs/ING-20261111-0000ABCD/alerts?from=1&to=999")
    await triage.on_evidence_ingested(None, SimpleNamespace(trace_id=None), data)  # type: ignore[arg-type]
    return catat.baris


@pytest.mark.anyio
async def test_pipeline_senyap_bila_semua_aturan_berpenjelas(monkeypatch: pytest.MonkeyPatch) -> None:
    baris = await _jalankan(monkeypatch, KAT, "chains/svc-backup.jsonl")
    assert [b[1] for b in baris] == ["batch_diproses"]


@pytest.mark.anyio
async def test_pipeline_melaporkan_aturan_tanpa_penjelas(monkeypatch: pytest.MonkeyPatch) -> None:
    doc = _dokumen()
    ada = doc["alert_penjelasan"]["entries"]
    hilang = "e87bd730-df45-4ae9-85de-6c75369c5d29"
    del ada[hilang]
    baris = await _jalankan(monkeypatch, muat(json.dumps(doc)), "chains/r1-brute-force.jsonl")
    peringatan = [b for b in baris if b[0] == "warning"]
    assert len(peringatan) == 1
    assert peringatan[0][1] == "aturan_tanpa_penjelasan"
    assert peringatan[0][2]["rule_id"] == [hilang] and peringatan[0][2]["jumlah"] == 1
    assert baris[-1][1] == "batch_diproses"  # kartu tetap dihitung
