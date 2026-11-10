"""Tabel milik triage (skema layanan; `create_all`, sama dengan layanan lain sampai Alembic). PostgreSQL.

| Tabel | Isi |
|---|---|
| alert_proyeksi | Salinan alert dari ingest untuk perhitungan (bukan kepemilikan) |
| klaster | Satu baris per kartu: rentang waktu, host, akun, versi dan hash terakhir |
| klaster_anggota | Alert -> kartu (satu alert di satu kartu) |
| kartu_seq | Penomor kartu per tanggal (WIB) |
| kartu_versi | Dokumen kartu per versi; tidak pernah dihapus |
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    Column,
    Date,
    DateTime,
    Index,
    Integer,
    MetaData,
    PrimaryKeyConstraint,
    SmallInteger,
    Table,
    Text,
    func,
    or_,
    select,
    text,
)
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_triage.kartu import Kartu
from astria_triage.model import Alert
from astria_triage.skor import Riwayat

MAKS_BARIS = 1000
WIB = timezone(timedelta(hours=7))  # UTC+7 tetap, tanpa tzdata (keputusan note app-triage)

metadata = MetaData()

alert_proyeksi = Table(
    "alert_proyeksi",
    metadata,
    Column("alert_id", Text, primary_key=True),
    Column("host_key", Text, nullable=False),
    Column("akun_key", Text, nullable=True),
    Column("ts", DateTime(timezone=True), nullable=False),
    Column("data", JSON, nullable=False),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
Index("alert_proyeksi_host_ts", alert_proyeksi.c.host_key, alert_proyeksi.c.ts)
Index("alert_proyeksi_akun_ts", alert_proyeksi.c.akun_key, alert_proyeksi.c.ts)

klaster = Table(
    "klaster",
    metadata,
    Column("card_id", Text, primary_key=True),
    Column("first_ts", DateTime(timezone=True), nullable=False),
    Column("last_ts", DateTime(timezone=True), nullable=False),
    Column("hosts", JSON, nullable=False),
    Column("akun", JSON, nullable=False),
    Column("latest_version", Integer, nullable=False),
    Column("latest_hash", Text, nullable=False),
    Column("skor", SmallInteger, nullable=False),
    Column("band", Text, nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)
Index("klaster_first_ts", klaster.c.first_ts)

klaster_anggota = Table(
    "klaster_anggota",
    metadata,
    Column("alert_id", Text, primary_key=True),
    Column("card_id", Text, nullable=False, index=True),
)

kartu_seq = Table(
    "kartu_seq",
    metadata,
    Column("tanggal", Date, primary_key=True),
    Column("last_no", Integer, nullable=False),
)

kartu_versi = Table(
    "kartu_versi",
    metadata,
    Column("card_id", Text, nullable=False),
    Column("version", Integer, nullable=False),
    Column("data", JSON, nullable=False),
    Column("skor", SmallInteger, nullable=False),
    Column("band", Text, nullable=False),
    Column("catalog_version", JSON, nullable=False),
    Column("algo_version", Text, nullable=False),
    Column("card_hash", Text, nullable=False),
    Column("sumber_r", Text, nullable=True),
    Column("created_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
    PrimaryKeyConstraint("card_id", "version"),
)
Index("kartu_versi_band_waktu", kartu_versi.c.band, kartu_versi.c.created_at.desc())


def _kunci(nilai: str | None) -> str | None:
    return nilai.casefold() if nilai else None


async def simpan_alert(conn: AsyncConnection, alerts: Iterable[Alert]) -> None:
    """Upsert proyeksi: alert yang sama dari pengiriman ulang tidak menggandakan baris."""
    baris = [
        {
            "alert_id": a.alert_id,
            "host_key": a.host.casefold(),
            "akun_key": _kunci(a.akun),
            "ts": a.ts,
            "data": a.to_json(),
        }
        for a in sorted(alerts, key=lambda a: a.alert_id)
    ]
    for i in range(0, len(baris), MAKS_BARIS):  # batas parameter terikat PostgreSQL (32767)
        await conn.execute(
            pg_insert(alert_proyeksi)
            .values(baris[i : i + MAKS_BARIS])
            .on_conflict_do_nothing(index_elements=["alert_id"])
        )


async def alert_sekitar(
    conn: AsyncConnection, hosts: set[str], akun: set[str], dari: datetime, ke: datetime
) -> list[Alert]:
    """Alert tersimpan dengan host atau akun yang sama dalam rentang waktu (bahan hitung ulang klaster)."""
    syarat = [alert_proyeksi.c.host_key.in_(sorted(hosts))]
    if akun:
        syarat.append(alert_proyeksi.c.akun_key.in_(sorted(akun)))
    rows = await conn.execute(
        select(alert_proyeksi.c.data)
        .where(or_(*syarat), alert_proyeksi.c.ts >= dari, alert_proyeksi.c.ts <= ke)
        .order_by(alert_proyeksi.c.ts, alert_proyeksi.c.alert_id)
    )
    return [Alert.from_json(r.data) for r in rows]


async def kunci_kartu(conn: AsyncConnection) -> None:
    """Satu penulis kartu dalam satu waktu (kunci advisory transaksi), aman bila konsumen lebih dari satu replika."""
    await conn.execute(text("SELECT pg_advisory_xact_lock(hashtext('astria-triage-kartu'))"))


async def peta_anggota(conn: AsyncConnection, alert_ids: Sequence[str]) -> dict[str, str]:
    """alert_id -> card_id untuk alert yang sudah menjadi anggota kartu."""
    hasil: dict[str, str] = {}
    unik = sorted(set(alert_ids))
    for i in range(0, len(unik), MAKS_BARIS):
        rows = await conn.execute(
            select(klaster_anggota.c.alert_id, klaster_anggota.c.card_id).where(
                klaster_anggota.c.alert_id.in_(unik[i : i + MAKS_BARIS])
            )
        )
        hasil |= {r.alert_id: r.card_id for r in rows}
    return hasil


async def baca_klaster(conn: AsyncConnection, card_id: str) -> Any:
    return (await conn.execute(select(klaster).where(klaster.c.card_id == card_id))).first()


async def riwayat(conn: AsyncConnection, sebelum: datetime, hari: int, kecuali: set[str]) -> list[Riwayat]:
    """Kartu yang awal klasternya dalam `hari` sebelum `sebelum` (bahan faktor R)."""
    q = select(klaster).where(klaster.c.first_ts >= sebelum - timedelta(days=hari), klaster.c.first_ts < sebelum)
    if kecuali:
        q = q.where(klaster.c.card_id.not_in(sorted(kecuali)))
    rows = await conn.execute(q.order_by(klaster.c.card_id))
    return [Riwayat(r.card_id, r.latest_version, r.band, r.first_ts, tuple(r.hosts), tuple(r.akun)) for r in rows.all()]


async def nomor_kartu_baru(conn: AsyncConnection, waktu: datetime) -> str:
    """`IC-YYYYMMDD-NNN`; tanggal WIB dari awal klaster. Nomor di transaksi yang sama dengan kartu."""
    tanggal: date = waktu.astimezone(WIB).date()
    stmt = pg_insert(kartu_seq).values(tanggal=tanggal, last_no=1)
    stmt = stmt.on_conflict_do_update(index_elements=["tanggal"], set_={"last_no": kartu_seq.c.last_no + 1}).returning(
        kartu_seq.c.last_no
    )
    no = (await conn.execute(stmt)).scalar_one()
    return f"IC-{tanggal:%Y%m%d}-{no:03d}"


async def simpan_versi(
    conn: AsyncConnection, *, card_id: str, version: int, data: dict[str, Any], kartu: Kartu, sumber_r: str | None
) -> None:
    await conn.execute(
        kartu_versi.insert().values(
            card_id=card_id,
            version=version,
            data=data,
            skor=kartu.skor,
            band=kartu.band,
            catalog_version=data["catalog_version"],
            algo_version=data["algo_version"],
            card_hash=kartu.paket_hash,
            sumber_r=sumber_r,
        )
    )


async def simpan_klaster(
    conn: AsyncConnection, card_id: str, kartu: Kartu, version: int, alert_ids: Sequence[str]
) -> None:
    """Baris `klaster` (rentang, host, akun, versi dan hash terakhir) dan keanggotaan alert, juga bila hash sama."""
    nilai = {
        "first_ts": kartu.first_ts,
        "last_ts": kartu.last_ts,
        "hosts": list(kartu.hosts),
        "akun": list(kartu.akun),
        "latest_version": version,
        "latest_hash": kartu.paket_hash,
        "skor": kartu.skor,
        "band": kartu.band,
        "updated_at": func.now(),
    }
    await conn.execute(
        pg_insert(klaster)
        .values(card_id=card_id, **nilai)
        .on_conflict_do_update(index_elements=["card_id"], set_=nilai)
    )
    for i in range(0, len(alert_ids), MAKS_BARIS):
        potong = sorted(alert_ids)[i : i + MAKS_BARIS]
        await conn.execute(
            pg_insert(klaster_anggota)
            .values([{"alert_id": a, "card_id": card_id} for a in potong])
            .on_conflict_do_update(index_elements=["alert_id"], set_={"card_id": card_id})
        )
