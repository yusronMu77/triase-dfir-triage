import pytest
from pydantic import SecretStr

from astria_triage.main import build_app
from astria_triage.settings import Settings

KEY = SecretStr("00" * 32)


def test_consumer_is_wired_when_db_and_nats_configured() -> None:
    settings = Settings(
        env="dev",
        database_url=SecretStr("postgresql+psycopg://u:p@postgres:5432/triage_dev"),
        nats_url="nats://nats:4222",
        service_key=KEY,
    )
    app = build_app(settings)
    assert "consumer:triage" in app.state.components
    assert {"postgres", "nats", "outbox"} <= set(app.state.components)


def test_consumer_needs_service_key() -> None:
    settings = Settings(
        env="dev",
        database_url=SecretStr("postgresql+psycopg://u:p@postgres:5432/triage_dev"),
        nats_url="nats://nats:4222",
    )
    with pytest.raises(RuntimeError, match="ASTRIA_SERVICE_KEY"):
        build_app(settings)


def test_no_consumer_without_dependencies() -> None:
    app = build_app(Settings(env="test"))
    assert "consumer:triage" not in app.state.components
