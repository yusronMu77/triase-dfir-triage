from __future__ import annotations

import json

import httpx
import pytest

from astria_triage.ingest_client import BatchRefTidakValid, IngestClient, RentangAlert, parse_batch_ref

pytestmark = pytest.mark.anyio


def test_parse_batch_ref_sah() -> None:
    assert parse_batch_ref("/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=1&to=500") == RentangAlert(
        "ING-20261110-0A1B2C3D", 1, 500
    )


@pytest.mark.parametrize(
    "ref",
    [
        "http://evil.example/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=1&to=5",
        "//evil.example/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=1&to=5",
        "/svc/v1/jobs/../admin/alerts?from=1&to=5",
        "/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=5&to=1",
        "/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=0&to=1",
        "/svc/v1/jobs/ING-20261110-0A1B2C3D/alerts?from=1&to=5&x=1",
        "/internal/v1/evidence?job_id=ING-20261110-0042",
    ],
)
def test_parse_batch_ref_menolak_bentuk_lain(ref: str) -> None:
    with pytest.raises(BatchRefTidakValid):
        parse_batch_ref(ref)


class _Token:
    async def auth_headers(self, audience: str) -> dict[str, str]:
        assert audience == "svc:ingest"
        return {"Authorization": "Bearer t"}


async def test_klien_mengikuti_cursor_dan_memecah_bukti_per_500() -> None:
    panggilan: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        panggilan.append(req)
        assert req.headers["Authorization"] == "Bearer t"
        if req.url.path.endswith("/alerts"):
            cursor = req.url.params.get("cursor")
            items = [{"alert_id": "AL-hb01-000001"}] if cursor is None else [{"alert_id": "AL-hb01-000002"}]
            return httpx.Response(200, json={"items": items, "next_cursor": None if cursor else "1"})
        ids = json.loads(req.content)["ids"]
        assert len(ids) <= 500
        return httpx.Response(200, json={"items": [{"evidence_id": i} for i in ids], "not_found": []})

    http = httpx.AsyncClient(base_url="http://ingest:8000", transport=httpx.MockTransport(handler))
    klien = IngestClient(_Token(), "http://ingest:8000", http=http)  # type: ignore[arg-type]
    alerts = await klien.alerts(RentangAlert("ING-20261110-0A1B2C3D", 1, 2))
    assert [a["alert_id"] for a in alerts] == ["AL-hb01-000001", "AL-hb01-000002"]
    bukti = await klien.bukti([f"EV-hb01-{i:06d}" for i in range(1, 1202)])
    assert len(bukti) == 1201
    assert sum(1 for r in panggilan if r.url.path.endswith("evidence:batch")) == 3
    assert all(r.url.host == "ingest" for r in panggilan)


async def test_klien_melempar_galat_server() -> None:
    http = httpx.AsyncClient(
        base_url="http://ingest:8000", transport=httpx.MockTransport(lambda r: httpx.Response(503))
    )
    klien = IngestClient(_Token(), "http://ingest:8000", http=http)  # type: ignore[arg-type]
    with pytest.raises(httpx.HTTPStatusError):
        await klien.alerts(RentangAlert("ING-20261110-0A1B2C3D", 1, 2))
