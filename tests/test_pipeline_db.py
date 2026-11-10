"""Uji integrasi dengan PostgreSQL sungguhan (`ASTRIA_TEST_DATABASE_URL`, tersedia di kontainer py devenv).

Ingest diganti sumber palsu yang membaca fixture samples dalam bentuk jawaban API ingest.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Sequence
from typing import Any

import pytest
from astria_common.db import Database
from astria_common.outbox import outbox
from astria_contracts import Envelope
from hayabusa import ingest_items
from pydantic import SecretStr
from sqlalchemy import func, select, text

from astria_triage import store
from astria_triage.ingest_client import RentangAlert
from astria_triage.katalog import bawaan
from astria_triage.pipeline import Triage

DB_URL = os.environ.get("ASTRIA_TEST_DATABASE_URL")

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.skipif(not DB_URL, reason="ASTRIA_TEST_DATABASE_URL tidak diisi"),
]

JOBS = {
    "ING-20261108-00000001": ("history/WS-ADM-04-brute-awal.jsonl", "hb01"),
    "ING-20261110-00000002": ("chains/svc-backup.jsonl", "hb02"),
    "ING-20261110-00000003": ("benign/J2.jsonl", "hb03"),
}


class SumberPalsu:
    def __init__(self) -> None:
        self.bukti_db: dict[str, dict[str, Any]] = {}
        self.alert_db: dict[str, list[dict[str, Any]]] = {}
        for job, (path, source) in JOBS.items():
            pasangan = ingest_items(path, source)
            self.alert_db[job] = [i for i, _ in pasangan]
            self.bukti_db |= {b["evidence_id"]: b for _, b in pasangan}

    async def alerts(self, rentang: RentangAlert) -> list[dict[str, Any]]:
        return [a for a in self.alert_db[rentang.job_id] if rentang.dari <= a["record_no"] <= rentang.ke]

    async def bukti(self, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        return {i: self.bukti_db[i] for i in ids if i in self.bukti_db}


@pytest.fixture
async def db():
    schema = f"t_{uuid.uuid4().hex[:8]}"
    database = Database(SecretStr(DB_URL or ""), schema=schema, metadata=[outbox.metadata, store.metadata])
    await database.start()
    await database.wait_ready(10)
    yield database
    async with database.engine.begin() as conn:
        await conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
    await database.stop()


def _event(job: str, n: int = 1000) -> tuple[Envelope, Any]:
    from astria_common.events import new_event

    env = new_event(
        "evidence.ingested",
        {
            "source_id": JOBS[job][1],
            "count": n,
            "record_range": {"from": 1, "to": n},
            "batch_ref": f"/svc/v1/jobs/{job}/alerts?from=1&to={n}",
        },
        correlation={"job_id": job},
    )
    from astria_contracts import EVENTS

    return env, EVENTS["evidence.ingested"].model.model_validate(env.data)


async def _jalan(db: Database, triage: Triage, job: str) -> None:
    env, data = _event(job)
    async with db.engine.begin() as conn:
        await triage.on_evidence_ingested(conn, env, data)


async def _kartu(db: Database) -> list[Any]:
    async with db.engine.connect() as conn:
        return list((await conn.execute(select(store.klaster).order_by(store.klaster.c.card_id))).all())


async def _jumlah_outbox(db: Database) -> int:
    async with db.engine.connect() as conn:
        return (await conn.execute(select(func.count()).select_from(outbox))).scalar_one()


async def test_riwayat_lalu_rantai_lalu_jinak_45_77_10(db: Database) -> None:
    triage = Triage(SumberPalsu(), bawaan())
    for job in JOBS:
        await _jalan(db, triage, job)
    kartu = await _kartu(db)
    assert [(k.card_id, k.skor, k.band) for k in kartu] == [
        ("IC-20261108-001", 45, "SEDANG"),
        ("IC-20261110-001", 77, "KRITIS"),
        ("IC-20261110-002", 10, "RENDAH"),
    ]
    async with db.engine.connect() as conn:
        rows = (await conn.execute(select(outbox.c.envelope).order_by(outbox.c.created_at))).all()
        r = (
            await conn.execute(
                select(store.kartu_versi.c.sumber_r).where(store.kartu_versi.c.card_id == "IC-20261110-001")
            )
        ).scalar_one()
    assert len(rows) == 3
    assert r == "IC-20261108-001:1"
    rantai = next(e.envelope for e in rows if e.envelope["correlation"]["card_id"] == "IC-20261110-001")
    assert rantai["data"]["kode"]["pola"] == "P-AKUN-DIAMBILALIH"
    assert rantai["correlation"]["version"] == 1


async def test_event_dan_batch_ulang_tidak_menaikkan_versi(db: Database) -> None:
    triage = Triage(SumberPalsu(), bawaan())
    await _jalan(db, triage, "ING-20261110-00000002")
    await _jalan(db, triage, "ING-20261110-00000002")  # batch sama datang lagi (event id beda)
    kartu = await _kartu(db)
    assert [(k.latest_version, k.skor) for k in kartu] == [(1, 72)]
    assert await _jumlah_outbox(db) == 1


async def test_rantai_dulu_lalu_riwayat_skor_rantai_tetap_72(db: Database) -> None:
    """K11: kartu lama tidak dihitung ulang bila riwayat datang belakangan (urutan impor penting)."""
    triage = Triage(SumberPalsu(), bawaan())
    await _jalan(db, triage, "ING-20261110-00000002")
    await _jalan(db, triage, "ING-20261108-00000001")
    assert sorted((k.skor, k.band) for k in await _kartu(db)) == [(45, "SEDANG"), (72, "KRITIS")]


async def test_batch_terpisah_menyatu_ke_satu_kartu_dengan_versi_baru(db: Database) -> None:
    sumber = SumberPalsu()
    job = "ING-20261110-00000002"
    semua = sumber.alert_db[job]
    sumber.alert_db["ING-20261110-0000000A"] = [a for a in semua if a["record_no"] <= 22]
    sumber.alert_db["ING-20261110-0000000B"] = [a for a in semua if a["record_no"] > 22]
    JOBS["ING-20261110-0000000A"] = JOBS["ING-20261110-0000000B"] = JOBS[job]
    try:
        triage = Triage(sumber, bawaan())
        await _jalan(db, triage, "ING-20261110-0000000A")
        await _jalan(db, triage, "ING-20261110-0000000B")
    finally:
        del JOBS["ING-20261110-0000000A"], JOBS["ING-20261110-0000000B"]
    kartu = await _kartu(db)
    assert [(k.card_id, k.latest_version, k.skor) for k in kartu] == [("IC-20261110-001", 2, 72)]
    assert await _jumlah_outbox(db) == 2


async def test_kartu_lama_terbelah_semua_anggota_tetap_punya_kartu(db: Database) -> None:
    """Kartu 0-4.8 jam; alert baru sampai 7.2 jam membuat klaster > 6 jam lalu dibelah: tiap anggota ada di kartunya."""
    from dataclasses import replace
    from datetime import timedelta

    from hayabusa import alerts as baca

    contoh = baca("benign/J2.jsonl")[0]

    def mk(i: int):
        return replace(
            contoh,
            alert_id=f"AL-zz01-{i:06d}",
            evidence_id=f"EV-zz01-{i:06d}",
            ts=contoh.ts + timedelta(minutes=24 * i),
        )

    triage = Triage(SumberPalsu(), bawaan())
    async with db.engine.begin() as conn:
        await triage.proses(conn, [mk(i) for i in range(13)])
    assert len(await _kartu(db)) == 1
    async with db.engine.begin() as conn:
        await triage.proses(conn, [mk(i) for i in range(13, 19)])
    async with db.engine.connect() as conn:
        anggota = dict(
            (await conn.execute(select(store.klaster_anggota.c.alert_id, store.klaster_anggota.c.card_id))).all()
        )
        versi = (
            await conn.execute(
                select(store.kartu_versi.c.card_id, store.kartu_versi.c.data).order_by(store.kartu_versi.c.version)
            )
        ).all()
    bukti_terakhir = {card_id: {b["id"] for b in data["kode"]["bukti"]} for card_id, data in versi}
    assert len(anggota) == 19
    assert len(bukti_terakhir) == 2  # kartu lama (versi baru) + satu kartu baru
    for alert_id, card_id in anggota.items():
        assert alert_id.replace("AL-", "EV-") in bukti_terakhir[card_id], (alert_id, card_id)
