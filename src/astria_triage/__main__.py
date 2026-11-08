"""Jalankan layanan: `astria-triage` atau `python -m astria_triage`."""

from astria_common.app import run

from astria_triage.main import build_app
from astria_triage.settings import Settings


def main() -> None:
    settings = Settings()
    run(build_app(settings), settings)


if __name__ == "__main__":
    main()
