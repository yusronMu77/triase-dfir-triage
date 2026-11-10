"""Pola insiden: interpreter pohon syarat JSON (tanpa eval) dan judul templat (note app-triage 5.4 g).

Pola dengan prioritas terkecil yang cocok dipilih; seri dipecah ID pola secara leksikal. Tanpa pola yang cocok
dipakai pola umum. Placeholder hanya diisi dari nilai peran entitas; teks lain di katalog tidak diinterpolasi.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from typing import Any

from astria_triage.katalog import Pola, PolaInsiden

MAKS_JUDUL = 200
_PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def cocok(node: Mapping[str, Any], temuan: Collection[str]) -> bool:
    ((kunci, isi),) = node.items()
    if kunci == "temuan":
        return isi in temuan
    if kunci == "all":
        return all(cocok(anak, temuan) for anak in isi)
    if kunci == "any":
        return any(cocok(anak, temuan) for anak in isi)
    raise ValueError(f"node syarat tidak dikenal: {kunci!r}")  # katalog sudah divalidasi; penjaga terakhir


def pilih(katalog: PolaInsiden, temuan: Collection[str]) -> Pola | None:
    kandidat = [p for p in katalog.pola if cocok(p.syarat, temuan)]
    return min(kandidat, key=lambda p: (p.prioritas, p.pola)) if kandidat else None


def isi_judul(templat: str, nilai: Mapping[str, str]) -> str:
    """Ganti `{nama}` dengan nilai; tanpa str.format (tidak ada akses atribut atau indeks). Dipotong 200 karakter."""
    # Satu lintasan: nilai yang memuat "{host}" tidak ikut diganti lagi.
    hasil = _PLACEHOLDER.sub(lambda m: " ".join(nilai[m[1]].split()) if m[1] in nilai else m[0], templat)
    if len(hasil) > MAKS_JUDUL:
        hasil = hasil[: MAKS_JUDUL - 1] + "…"
    return hasil
