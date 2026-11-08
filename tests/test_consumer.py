from astria_contracts import example

from astria_triage.main import build_app, received_batches
from astria_triage.settings import Settings


def test_consumer_is_wired_when_db_and_nats_configured() -> None:
    settings = Settings(
        env="dev",
        database_url="postgresql+psycopg://u:p@postgres:5432/triage_dev",
        nats_url="nats://nats:4222",
    )
    app = build_app(settings)
    assert "consumer:triage" in app.state.components
    assert {"postgres", "nats", "outbox"} <= set(app.state.components)


def test_no_consumer_without_dependencies() -> None:
    app = build_app(Settings(env="test"))
    assert "consumer:triage" not in app.state.components


def test_table_matches_contract_fields() -> None:
    data = example("evidence.ingested")["data"]
    assert {"source_id", "count"} <= set(data)
    assert {"event_id", "source_id", "job_id", "count"} <= set(received_batches.c.keys())
