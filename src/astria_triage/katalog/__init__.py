"""Katalog berversi (pola, bobot skor, aset, taktik, ambang korelasi), divalidasi Pydantic saat dimuat.

Sementara dibawa triage sendiri (triage#3, K2) karena layanan `config` belum siap. Katalog yang rusak membuat
layanan gagal start, jadi tidak ada kartu yang dihitung dengan katalog setengah jadi.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from functools import cache
from importlib import resources
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

BAND = ("KRITIS", "TINGGI", "SEDANG", "RENDAH")
Band = Literal["KRITIS", "TINGGI", "SEDANG", "RENDAH"]
Kritikalitas = Literal["rendah", "sedang", "tinggi", "kritikal"]

_SLUG = r"^[a-z]+(-[a-z]+)*$"
_TEKNIK = r"^T\d{4}(\.\d{3})?$"
_TEMUAN = r"^K-[A-Z0-9-]+$"
_POLA = r"^P-[A-Z0-9-]+$"
_RULE_ID = r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")
PLACEHOLDER_POLA = frozenset({"akun", "host"})
PLACEHOLDER_UMUM = frozenset({"host", "n_taktik"})


class _Ketat(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Taktik(_Ketat):
    versi: int = Field(ge=1)
    singkatan: dict[str, Annotated[str, Field(pattern=_SLUG)]]
    teknik: dict[Annotated[str, Field(pattern=_TEKNIK)], tuple[Annotated[str, Field(pattern=_SLUG)], ...]]


class Skor(_Ketat):
    versi: int = Field(ge=1)
    level: dict[str, int]
    taktik: dict[Annotated[str, Field(pattern=_SLUG)], Annotated[int, Field(ge=0, le=25)]]
    aset: dict[Kritikalitas, Annotated[int, Field(ge=0, le=15)]]
    korelasi_per_taktik: int = Field(ge=0)
    korelasi_maks: int = Field(ge=0, le=10)
    pengulangan: int = Field(ge=0, le=5)
    pengulangan_hari: int = Field(ge=1)
    pengulangan_band: tuple[Band, ...]
    band: dict[Literal["KRITIS", "TINGGI", "SEDANG"], Annotated[int, Field(ge=1, le=100)]]

    @model_validator(mode="after")
    def _ambang_menurun(self) -> Skor:
        b = self.band
        if set(b) != {"KRITIS", "TINGGI", "SEDANG"} or not b["KRITIS"] > b["TINGGI"] > b["SEDANG"]:
            raise ValueError("ambang band harus KRITIS > TINGGI > SEDANG")
        if set(self.aset) != {"rendah", "sedang", "tinggi", "kritikal"}:
            raise ValueError("bobot aset wajib untuk rendah, sedang, tinggi, kritikal")
        return self


class Aset(_Ketat):
    versi: int = Field(ge=1)
    bawaan: Kritikalitas
    host: dict[str, Kritikalitas]


class Korelasi(_Ketat):
    versi: int = Field(ge=1)
    logon_min_gagal: int = Field(ge=1)
    logon_jendela_menit: int = Field(ge=1)
    klaster_host_menit: int = Field(ge=1)
    klaster_akun_menit: int = Field(ge=1)
    klaster_belah_jam: int = Field(ge=1)
    maks_bukti_kartu: int = Field(ge=1, le=500)
    maks_bukti_rujukan: int = Field(ge=1)


def _cek_syarat(node: Any, kedalaman: int = 0) -> None:
    """Pohon syarat terbatas: {"temuan": K-*}, {"all": [...]}, {"any": [...]}. Node lain ditolak (tanpa eval)."""
    if kedalaman > 8:
        raise ValueError("pohon syarat terlalu dalam")
    if not isinstance(node, dict) or len(node) != 1:
        raise ValueError(f"node syarat harus objek dengan tepat satu kunci: {node!r}")
    ((kunci, isi),) = node.items()
    if kunci == "temuan":
        if not isinstance(isi, str) or not re.match(_TEMUAN, isi):
            raise ValueError(f"temuan tidak valid: {isi!r}")
    elif kunci in ("all", "any"):
        if not isinstance(isi, list) or not isi:
            raise ValueError(f"{kunci} harus daftar tidak kosong")
        for anak in isi:
            _cek_syarat(anak, kedalaman + 1)
    else:
        raise ValueError(f"node syarat tidak dikenal: {kunci!r}")


def _cek_judul(judul: str, boleh: frozenset[str]) -> str:
    asing = set(_PLACEHOLDER.findall(judul)) - boleh
    if asing:
        raise ValueError(f"placeholder judul tidak diizinkan: {sorted(asing)}")
    sisa = _PLACEHOLDER.sub("", judul)
    if "{" in sisa or "}" in sisa:
        raise ValueError("kurung kurawal di judul hanya untuk placeholder yang diizinkan")
    return judul


class Pola(_Ketat):
    pola: str = Field(pattern=_POLA)
    prioritas: int = Field(ge=0)
    syarat: dict[str, Any]
    judul: str = Field(min_length=1, max_length=200)
    langkah: tuple[str, ...] = ()

    @field_validator("syarat")
    @classmethod
    def _syarat(cls, value: dict[str, Any]) -> dict[str, Any]:
        _cek_syarat(value)
        return value

    @field_validator("judul")
    @classmethod
    def _judul(cls, value: str) -> str:
        return _cek_judul(value, PLACEHOLDER_POLA)


class PolaUmum(_Ketat):
    pola: str = Field(pattern=_POLA)
    judul: str = Field(min_length=1, max_length=200)

    @field_validator("judul")
    @classmethod
    def _judul(cls, value: str) -> str:
        return _cek_judul(value, PLACEHOLDER_UMUM)


class PolaInsiden(_Ketat):
    versi: int = Field(ge=1)
    pola: tuple[Pola, ...]
    umum: PolaUmum

    @model_validator(mode="after")
    def _unik(self) -> PolaInsiden:
        ids = [p.pola for p in self.pola] + [self.umum.pola]
        if len(ids) != len(set(ids)):
            raise ValueError("ID pola harus unik")
        return self


_Teks = Annotated[str, Field(min_length=1, max_length=600)]


class Penjelasan(_Ketat):
    """Penjelas satu aturan Hayabusa/Sigma; bentuknya sama dengan entri `alert_penjelasan` di layanan config."""

    judul: str = Field(min_length=1, max_length=120)
    penjelasan: _Teks
    penyebab_jinak: tuple[_Teks, ...] = Field(min_length=1)
    yang_dicek: tuple[_Teks, ...] = Field(min_length=1)
    rujukan: tuple[_Teks, ...] = Field(min_length=1)


class AlertPenjelasan(_Ketat):
    """Katalog `alert_penjelasan`: kunci `entries` adalah `RuleID` Hayabusa (UUID huruf kecil)."""

    versi: int = Field(ge=1)
    entries: dict[Annotated[str, Field(pattern=_RULE_ID)], Penjelasan]


class Katalog(_Ketat):
    catatan: str = Field(default="", alias="_catatan")
    taktik: Taktik
    skor: Skor
    aset: Aset
    korelasi: Korelasi
    pola_insiden: PolaInsiden
    alert_penjelasan: AlertPenjelasan

    @model_validator(mode="after")
    def _taktik_berbobot(self) -> Katalog:
        tanpa_bobot = (
            set(self.taktik.singkatan.values()) | {t for ts in self.taktik.teknik.values() for t in ts}
        ) - set(self.skor.taktik)
        if tanpa_bobot:
            raise ValueError(f"taktik tanpa bobot T: {sorted(tanpa_bobot)}")
        return self

    @property
    def versi(self) -> dict[str, int]:
        """`catalog_version` di event `card.skeleton.created`."""
        return {
            "alert_penjelasan": self.alert_penjelasan.versi,
            "aset": self.aset.versi,
            "korelasi": self.korelasi.versi,
            "pola_insiden": self.pola_insiden.versi,
            "skor": self.skor.versi,
            "taktik": self.taktik.versi,
        }

    def penjelasan(self, rule_id: object) -> Penjelasan | None:
        """Penjelas aturan menurut `RuleID`; ID kosong, bukan teks, atau tak terdaftar -> None (tanpa galat)."""
        if not isinstance(rule_id, str):
            return None
        return self.alert_penjelasan.entries.get(rule_id.strip().lower())

    def tanpa_penjelasan(self, rule_ids: Iterable[str | None]) -> tuple[str, ...]:
        """`RuleID` unik (terurut) yang belum punya penjelas; `None` dan teks kosong diabaikan."""
        return tuple(sorted({r for r in rule_ids if r and self.penjelasan(r) is None}))

    def slug_taktik(self, nilai: str) -> str | None:
        """Singkatan Hayabusa (`CredAccess`) atau slug (`credential-access`) -> slug; tidak dikenal -> None."""
        if nilai in self.taktik.singkatan:
            return self.taktik.singkatan[nilai]
        slug = nilai.strip().lower()
        return slug if slug in self.skor.taktik else None


def muat(teks: str | bytes) -> Katalog:
    return Katalog.model_validate_json(teks)


@cache
def bawaan() -> Katalog:
    """Katalog yang dibawa paket (`katalog.json`)."""
    return muat(resources.files(__package__).joinpath("katalog.json").read_bytes())
