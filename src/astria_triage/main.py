"""Rakit aplikasi triage.

Tahap 0: konsumen `evidence.ingested` yang hanya mencatat batch yang diterima (konsumen palsu untuk
membuktikan rantai outbox -> JetStream -> konsumen idempoten). Dedup, klaster, skor, dan
`card.skeleton.created` dibangun di Tahap 1.
"""

from astria_common.app import create_app
from astria_common.consumer import Consumer
from astria_common.log import get_logger
from astria_common.service import standard_runtime
from astria_contracts import Envelope
from fastapi import FastAPI
from pydantic import BaseModel
from sqlalchemy import Column, DateTime, Integer, MetaData, Table, Text, func
from sqlalchemy.ext.asyncio import AsyncConnection

from astria_triage import api
from astria_triage.settings import Settings

log = get_logger(__name__)

metadata = MetaData()
received_batches = Table(
    "received_batches",
    metadata,
    Column("event_id", Text, primary_key=True),
    Column("source_id", Text, nullable=False),
    Column("job_id", Text, nullable=True),
    Column("count", Integer, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False, server_default=func.now()),
)


async def on_evidence_ingested(conn: AsyncConnection, envelope: Envelope, data: BaseModel) -> None:
    await conn.execute(
        received_batches.insert().values(
            event_id=envelope.id,
            source_id=data.source_id,  # type: ignore[attr-defined]
            job_id=envelope.correlation.job_id,
            count=data.count,  # type: ignore[attr-defined]
        )
    )
    log.info("batch_bukti_diterima", source_id=data.source_id, count=data.count)  # type: ignore[attr-defined]


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()
    runtime = standard_runtime(settings, metadata=[metadata])
    if runtime.db is not None and runtime.bus is not None:
        runtime.add(
            Consumer(
                runtime.bus, runtime.db, durable="triage", event_type="evidence.ingested", handler=on_evidence_ingested
            )
        )
    return create_app(settings, components=runtime.components, routers=[api.router])
