import pytest

from astria_triage.attack import (
    InvalidTechniqueId,
    accepted_ids,
    normalize_technique,
    same_technique,
)


def test_legacy_id_maps_to_canonical() -> None:
    assert normalize_technique("T1070.001") == "T1685.005"


def test_canonical_id_is_unchanged() -> None:
    assert normalize_technique("T1685.005") == "T1685.005"


def test_both_ids_are_the_same_technique() -> None:
    assert same_technique("T1070.001", "T1685.005")
    assert same_technique("t1685.005 ", "T1070.001")
    assert not same_technique("T1070.004", "T1685.005")


def test_other_techniques_pass_through() -> None:
    for tid in ("T1110.001", "T1059.001", "T1053.005", "T1136.001", "T1021.002", "T1070.004", "T1098", "T1110.003"):
        assert normalize_technique(tid) == tid


def test_accepted_ids_lists_canonical_then_legacy() -> None:
    assert accepted_ids("T1070.001") == ("T1685.005", "T1070.001")
    assert accepted_ids("T1685.005") == ("T1685.005", "T1070.001")
    assert accepted_ids("T1110.001") == ("T1110.001",)


@pytest.mark.parametrize("bad", ["", "1070.001", "T107", "T1070.01", "T1070.0011", "TA0005", "T1070-001"])
def test_invalid_ids_rejected(bad: str) -> None:
    with pytest.raises(InvalidTechniqueId):
        normalize_technique(bad)
