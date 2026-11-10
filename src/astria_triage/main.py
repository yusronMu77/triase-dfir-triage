"""Rakit aplikasi triage: komponen standar, konsumen `evidence.ingested`, dan router.

Konsumen menghitung klaster, temuan, pola, dan skor secara deterministik, lalu menerbitkan `card.skeleton.created`
lewat outbox (triage#3). Katalog dimuat dan divalidasi saat start; katalog rusak membuat layanan gagal start.
"""

from astria_common.app import create_app
from astria_common.auth import ServiceTokenClient
from astria_common.consumer import Consumer
from astria_common.service import standard_runtime
from fastapi import FastAPI

from astria_triage import api, store
from astria_triage.ingest_client import IngestClient
from astria_triage.katalog import bawaan
from astria_triage.pipeline import Triage
from astria_triage.settings import Settings


def _ingest(settings: Settings) -> IngestClient:
    key = settings.service_key_bytes()
    if key is None:
        raise RuntimeError("triage: ASTRIA_SERVICE_KEY atau _FILE wajib untuk membaca alert dari ingest")
    tokens = ServiceTokenClient(settings.service_name, key, settings.identity_url)
    return IngestClient(tokens, settings.triage_ingest_url)


def build_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()  # pyright: ignore[reportCallIssue]  # field wajib diisi dari env ASTRIA_*
    katalog = bawaan()
    runtime = standard_runtime(settings, metadata=[store.metadata])
    if runtime.db is not None and runtime.bus is not None:
        triage = Triage(_ingest(settings), katalog)
        runtime.add(
            Consumer(
                runtime.bus,
                runtime.db,
                durable="triage",
                event_type="evidence.ingested",
                handler=triage.on_evidence_ingested,
            )
        )
    return create_app(settings, components=runtime.components, routers=[api.router])
