"""Klien baca ingest: alert per job (`GET /svc/v1/jobs/{job}/alerts`) dan bukti (`POST /svc/v1/evidence:batch`).

`batch_ref` dari event hanya dipakai setelah cocok pola ketat; host selalu dari setting (`ASTRIA_TRIAGE_INGEST_URL`),
tidak pernah dari event. Galat jaringan atau 5xx dilempar supaya event tidak di-ack dan dikirim ulang.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from astria_common.auth import ServiceTokenClient
from astria_common.http import make_client

AUDIENS = "svc:ingest"
MAKS_HALAMAN = 500
MAKS_ID_BUKTI = 500
MAKS_HALAMAN_DIIKUTI = 10_000
_BATCH_REF = re.compile(
    r"^/svc/v1/jobs/(?P<job>ING-[0-9]{8}-[0-9A-F]{8})/alerts\?from=(?P<dari>[0-9]{1,7})&to=(?P<ke>[0-9]{1,7})$"
)


class BatchRefTidakValid(ValueError):
    """`batch_ref` tidak berbentuk rujukan alert per job dari ingest (galat data, permanen)."""


@dataclass(frozen=True, slots=True)
class RentangAlert:
    job_id: str
    dari: int
    ke: int


def parse_batch_ref(ref: str) -> RentangAlert:
    m = _BATCH_REF.match(ref)
    if m is None:
        raise BatchRefTidakValid(f"batch_ref tidak dikenali: {ref[:120]!r}")
    dari, ke = int(m["dari"]), int(m["ke"])
    if not 1 <= dari <= ke:
        raise BatchRefTidakValid(f"rentang batch_ref tidak sah: {dari}-{ke}")
    return RentangAlert(m["job"], dari, ke)


class SumberIngest(Protocol):
    async def alerts(self, rentang: RentangAlert) -> list[dict[str, Any]]: ...

    async def bukti(self, ids: Sequence[str]) -> dict[str, dict[str, Any]]: ...


class IngestClient:
    def __init__(self, tokens: ServiceTokenClient, base_url: str, *, http: httpx.AsyncClient | None = None) -> None:
        self._tokens = tokens
        self._http = http or make_client(base_url, timeout=15.0)

    async def alerts(self, rentang: RentangAlert) -> list[dict[str, Any]]:
        hasil: list[dict[str, Any]] = []
        cursor: str | None = None
        for _ in range(MAKS_HALAMAN_DIIKUTI):
            params: dict[str, Any] = {"from": rentang.dari, "to": rentang.ke, "limit": MAKS_HALAMAN}
            if cursor is not None:
                params["cursor"] = cursor
            headers = await self._tokens.auth_headers(AUDIENS)
            resp = await self._http.get(f"/svc/v1/jobs/{rentang.job_id}/alerts", params=params, headers=headers)
            resp.raise_for_status()
            halaman = resp.json()
            hasil.extend(halaman.get("items") or [])
            cursor = halaman.get("next_cursor")
            if not cursor:
                return hasil
        raise RuntimeError("paging alert ingest tidak berhenti")

    async def bukti(self, ids: Sequence[str]) -> dict[str, dict[str, Any]]:
        unik = sorted(set(ids))
        hasil: dict[str, dict[str, Any]] = {}
        for i in range(0, len(unik), MAKS_ID_BUKTI):
            headers = await self._tokens.auth_headers(AUDIENS)
            resp = await self._http.post(
                "/svc/v1/evidence:batch", json={"ids": unik[i : i + MAKS_ID_BUKTI]}, headers=headers
            )
            resp.raise_for_status()
            for item in resp.json().get("items") or []:
                hasil[item["evidence_id"]] = item
        return hasil

    async def aclose(self) -> None:
        await self._http.aclose()
