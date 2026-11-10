"""Konfigurasi triage dari env `ASTRIA_*`. Tambahkan field milik layanan ini di sini."""

from astria_common.settings import AstriaSettings


class Settings(AstriaSettings):
    service_name: str = "triage"

    triage_ingest_url: str = "http://ingest:8000"
    """Basis URL ingest untuk alert dan bukti (ASTRIA_TRIAGE_INGEST_URL). Host tidak pernah diambil dari event."""
