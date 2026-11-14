# Fixture samples

Salinan apa adanya dari repo `triase-dfir-samples` commit `009afaf7728ee3a38e2057d95843542ac06f2401` (`data/`): 15 berkas sintetis format Hayabusa v4.3.1 JSONL (R1-R7, J1-J6, D1/H1) dan
`manifest.json`. Data sintetis; atribusi aturan Hayabusa (DRL 1.1) ada di `manifest.json`. Jangan diedit: tes golden
membandingkan SHA-256 berkas dengan manifest dan skor dengan `harapan`. Perbarui dengan menyalin ulang dari `samples/data/`.

`tests/hayabusa.py` mengubah tiap baris menjadi bentuk jawaban API ingest (`AlertItem` + `EvidenceItem`) dengan aturan yang
sama dengan `astria_ingest.normalize` dan `render` (akun, IP sumber, severity, `kind`, `fields`). Kebenarannya terhadap ingest
asli diuji ujung ke ujung di devenv.

Kecocokan dengan biner Hayabusa hanya sudah diuji untuk D1/H1/J2 pada 2026-11-08. Skenario baru diuji pada tingkat kontrak; samples#10 tetap terpisah.
