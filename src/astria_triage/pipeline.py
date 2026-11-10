"""Satu batch `evidence.ingested` -> nol atau lebih `card.skeleton.created` (note app-triage 5.1-5.2).

Urutan dalam satu transaksi konsumen: ambil alert + bukti dari ingest, simpan proyeksi, hitung ulang klaster yang
tersentuh dari data tersimpan (bukan dari urutan event), lalu untuk tiap klaster: versi baru + outbox hanya bila
`paket_hash` berubah. Ack terjadi setelah COMMIT (Consumer common); event ulang ditahan `processed_events`.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from datetime import timedelta

from astria_common.events import new_event
from astria_common.log import get_logger
from astria_common.outbox import enqueue
from astria_contracts import Envelope
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_triage import store
from astria_triage.ingest_client import SumberIngest, parse_batch_ref
from astria_triage.kartu import Kartu, data_event, rakit
from astria_triage.katalog import Katalog
from astria_triage.klaster import klaster_terbelah
from astria_triage.model import Alert, AlertTidakValid, dari_ingest

log = get_logger(__name__)

_NAMESPACE = uuid.UUID("5b8f2c1e-3d4a-4e6b-9a7c-2f1e0d9c8b7a")
JANGKAUAN = timedelta(hours=24)
"""Rentang waktu di sekitar batch yang dibaca ulang dari proyeksi untuk menyusun klaster (> jendela belah 6 jam)."""
MAKS_PERLUASAN = 4


def event_id_kartu(card_id: str, version: int) -> str:
    """ID event deterministik: relay ulang versi yang sama dibuang JetStream (`Nats-Msg-Id`)."""
    return str(uuid.uuid5(_NAMESPACE, f"card.skeleton.created:{card_id}:{version}"))


class Triage:
    def __init__(self, sumber: SumberIngest, katalog: Katalog) -> None:
        self._sumber = sumber
        self._katalog = katalog
        k = katalog.korelasi
        self._jendela_host = timedelta(minutes=k.klaster_host_menit)
        self._jendela_akun = timedelta(minutes=k.klaster_akun_menit)
        self._belah = timedelta(hours=k.klaster_belah_jam)

    async def ambil(self, batch_ref: str) -> list[Alert]:
        items = await self._sumber.alerts(parse_batch_ref(batch_ref))
        bukti = await self._sumber.bukti([i for item in items for i in item.get("evidence_ids") or []])
        alerts = []
        for item in items:
            ids = item.get("evidence_ids") or []
            if len(ids) != 1 or ids[0] not in bukti:
                raise AlertTidakValid(f"bukti {ids!r} untuk {item.get('alert_id')!r} tidak dikembalikan ingest")
            alerts.append(dari_ingest(item, bukti[ids[0]], self._katalog))
        return alerts

    async def on_evidence_ingested(self, conn: AsyncConnection, envelope: Envelope, data: BaseModel) -> None:
        batch_ref: str = data.batch_ref  # type: ignore[attr-defined]
        alerts = await self.ambil(batch_ref)
        if not alerts:
            log.info("batch_tanpa_alert", batch_ref=batch_ref)
            return
        terbit = await self.proses(conn, alerts, trace_id=envelope.trace_id)
        log.info("batch_diproses", batch_ref=batch_ref, alert=len(alerts), kartu_terbit=terbit)

    async def proses(self, conn: AsyncConnection, alerts: Sequence[Alert], *, trace_id: str | None = None) -> int:
        """Simpan batch, hitung ulang klaster yang memuatnya, terbitkan versi yang berubah. Hasil: jumlah."""
        await store.kunci_kartu(conn)
        await store.simpan_alert(conn, alerts)
        baru = {a.alert_id for a in alerts}
        sekitar = await self._sekitar(conn, alerts)
        bagian = klaster_terbelah(sekitar, self._jendela_host, self._jendela_akun, self._belah)
        peta = await store.peta_anggota(conn, [a.alert_id for a in sekitar])  # alert -> card_id lama

        # Bagian yang diproses: yang memuat alert baru, ditambah bagian lain yang memuat anggota kartu terdampak
        # (mis. kartu lama yang terbelah karena alert baru), supaya tidak ada anggota kartu yang tertinggal.
        terdampak = {
            peta[a.alert_id]
            for k in bagian
            if not baru.isdisjoint(x.alert_id for x in k)
            for a in k
            if a.alert_id in peta
        }
        dipakai: set[str] = set()
        terbit = 0
        for kl in bagian:
            milik = sorted({peta[a.alert_id] for a in kl if a.alert_id in peta})
            if baru.isdisjoint(a.alert_id for a in kl) and not terdampak.intersection(milik):
                continue
            card_id = next((c for c in milik if c not in dipakai), None)  # card_id terkecil yang belum dipakai
            if card_id:
                dipakai.add(card_id)
            terbit += await self._kartu(conn, kl, card_id, set(milik), trace_id)
        return terbit

    async def _sekitar(self, conn: AsyncConnection, alerts: Sequence[Alert]) -> list[Alert]:
        """Alert di sekitar batch; host/akun diperluas sampai stabil (maks 4 putaran), untuk rantai transitif."""
        dari = min(a.ts for a in alerts) - JANGKAUAN
        ke = max(a.ts for a in alerts) + JANGKAUAN
        hosts = {a.host.casefold() for a in alerts}
        akun = {a.akun.casefold() for a in alerts if a.akun}
        sekitar: list[Alert] = []
        for _ in range(MAKS_PERLUASAN):
            sekitar = await store.alert_sekitar(conn, hosts, akun, dari, ke)
            h2 = hosts | {a.host.casefold() for a in sekitar}
            k2 = akun | {a.akun.casefold() for a in sekitar if a.akun}
            if (h2, k2) == (hosts, akun):
                break
            hosts, akun = h2, k2
        return sekitar

    async def _kartu(
        self, conn: AsyncConnection, kl: Sequence[Alert], card_id: str | None, milik: set[str], trace_id: str | None
    ) -> int:
        ids = [a.alert_id for a in kl]
        first_ts = min(a.ts for a in kl)
        # Kartu lama yang menyatu ke klaster ini tidak boleh menjadi sumber R-nya sendiri.
        riwayat = await store.riwayat(conn, first_ts, self._katalog.skor.pengulangan_hari, milik | {card_id or ""})
        kartu = rakit(kl, self._katalog, riwayat)
        sebelumnya = await store.baca_klaster(conn, card_id) if card_id else None
        if sebelumnya is not None and sebelumnya.latest_hash == kartu.paket_hash:
            # Isi kartu sama (mis. alert baru hanya menambah wakil yang sudah ada); keanggotaan tetap dicatat.
            await store.simpan_klaster(conn, card_id or "", kartu, sebelumnya.latest_version, ids)
            return 0
        version = (sebelumnya.latest_version + 1) if sebelumnya is not None else 1
        card_id = card_id or await store.nomor_kartu_baru(conn, first_ts)
        await self._terbitkan(conn, card_id, version, kartu, ids, trace_id)
        return 1

    async def _terbitkan(
        self, conn: AsyncConnection, card_id: str, version: int, kartu: Kartu, ids: Sequence[str], trace_id: str | None
    ) -> None:
        data = data_event(kartu, self._katalog)
        envelope = new_event(
            "card.skeleton.created",
            data,
            correlation={"card_id": card_id, "version": version},
            event_id=event_id_kartu(card_id, version),
            trace_id=trace_id,
        )
        sumber_r = f"{kartu.sumber_r.card_id}:{kartu.sumber_r.version}" if kartu.sumber_r else None
        await store.simpan_versi(conn, card_id=card_id, version=version, data=data, kartu=kartu, sumber_r=sumber_r)
        await store.simpan_klaster(conn, card_id, kartu, version, ids)
        await enqueue(conn, envelope)
        log.info(
            "kartu_terbit", card_id=card_id, version=version, skor=kartu.skor, band=kartu.band, pola=kartu.kode["pola"]
        )
