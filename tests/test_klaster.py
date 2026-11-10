from __future__ import annotations

from datetime import UTC, datetime, timedelta

from hypothesis import given, settings
from hypothesis import strategies as st

from astria_triage.klaster import belah, klaster, klaster_terbelah
from astria_triage.model import Alert

T0 = datetime(2026, 11, 10, 2, 0, tzinfo=UTC)
JH, JA, BELAH = timedelta(minutes=30), timedelta(minutes=60), timedelta(hours=6)


def mk(i: int, menit: float, host: str = "H1", akun: str | None = None) -> Alert:
    return Alert(
        alert_id=f"AL-hb01-{i:06d}",
        evidence_id=f"EV-hb01-{i:06d}",
        sha256="0" * 64,
        ts=T0 + timedelta(minutes=menit),
        host=host,
        akun=akun,
        aktor=None,
        src_ip=None,
        event_id=4624,
        rule_title="r",
        rule_id=None,
        severity="low",
        taktik=(),
        teknik=(),
        tag_lain=(),
    )


def ids(kelompok: list[list[Alert]]) -> list[list[str]]:
    return [[a.alert_id for a in k] for k in kelompok]


def test_batas_tepat_30_menit_host_bergabung() -> None:
    assert len(klaster([mk(1, 0), mk(2, 30)], JH, JA)) == 1
    assert len(klaster([mk(1, 0), mk(2, 30.01)], JH, JA)) == 2


def test_batas_tepat_60_menit_akun_bergabung_lintas_host() -> None:
    assert len(klaster([mk(1, 0, "H1", "u"), mk(2, 60, "H2", "U")], JH, JA)) == 1  # akun tidak peka huruf
    assert len(klaster([mk(1, 0, "H1", "u"), mk(2, 60.01, "H2", "u")], JH, JA)) == 2


def test_rantai_transitif() -> None:
    assert len(klaster([mk(i, i * 25) for i in range(10)], JH, JA)) == 1


def test_belah_pada_celah_terbesar_dan_seri_paling_awal() -> None:
    # celah 200 menit di dua tempat: belah di yang pertama
    a = [mk(1, 0), mk(2, 200), mk(3, 400)]
    assert ids(belah(a, timedelta(minutes=300))) == [["AL-hb01-000001"], ["AL-hb01-000002", "AL-hb01-000003"]]


def test_belah_tidak_menyentuh_klaster_pendek() -> None:
    a = [mk(1, 0), mk(2, 100)]
    assert ids(belah(a, BELAH)) == [["AL-hb01-000001", "AL-hb01-000002"]]


def test_klaster_terbelah_rentang_maks_6_jam() -> None:
    a = [mk(i, i * 20) for i in range(40)]  # 13 jam tersambung
    for k in klaster_terbelah(a, JH, JA, BELAH):
        assert k[-1].ts - k[0].ts <= BELAH


def brute(alerts: list[Alert]) -> list[list[str]]:
    """Komponen terhubung O(n^2) sebagai pembanding."""
    induk = {a.alert_id: a.alert_id for a in alerts}

    def cari(x: str) -> str:
        while induk[x] != x:
            x = induk[x]
        return x

    for a in alerts:
        for b in alerts:
            dekat = abs(a.ts - b.ts)
            if (a.host.casefold() == b.host.casefold() and dekat <= JH) or (
                a.akun and b.akun and a.akun.casefold() == b.akun.casefold() and dekat <= JA
            ):
                induk[cari(a.alert_id)] = cari(b.alert_id)
    grup: dict[str, list[Alert]] = {}
    for a in sorted(alerts, key=lambda a: a.kunci_urut):
        grup.setdefault(cari(a.alert_id), []).append(a)
    return sorted(([a.alert_id for a in g] for g in grup.values()), key=lambda g: g[0])


alert_acak = st.lists(
    st.tuples(st.integers(0, 600), st.sampled_from(["H1", "H2", "h1"]), st.sampled_from([None, "u1", "U1", "u2"])),
    max_size=25,
).map(lambda xs: [mk(i, m, h, u) for i, (m, h, u) in enumerate(xs)])


@settings(max_examples=200, deadline=None)
@given(alert_acak)
def test_properti_sapuan_sama_dengan_brute_force(alerts: list[Alert]) -> None:
    hasil = sorted(ids(klaster(alerts, JH, JA)), key=lambda g: g[0])
    assert hasil == brute(alerts)


@settings(max_examples=200, deadline=None)
@given(alert_acak, st.randoms(use_true_random=False))
def test_properti_urutan_input_tidak_berpengaruh_dan_tiap_alert_tepat_satu_klaster(alerts: list[Alert], rnd) -> None:
    acak = list(alerts)
    rnd.shuffle(acak)
    a = ids(klaster_terbelah(alerts, JH, JA, BELAH))
    assert a == ids(klaster_terbelah(acak, JH, JA, BELAH))
    semua = [i for k in a for i in k]
    assert sorted(semua) == sorted(x.alert_id for x in alerts)
