# Fixture samples

Salinan apa adanya dari repo `triase-dfir-samples` commit `beca2c8` (`data/`): tiga berkas Hayabusa v4.3.1 JSONL dan
`manifest.json`. Data sintetis; atribusi aturan Hayabusa (DRL 1.1) ada di `manifest.json`. Jangan diedit: tes golden
membandingkan SHA-256 berkas dengan manifest dan skor dengan `harapan`. Perbarui dengan menyalin ulang dari `samples/data/`.

`tests/hayabusa.py` mengubah tiap baris menjadi bentuk jawaban API ingest (`AlertItem` + `EvidenceItem`) dengan aturan yang
sama dengan `astria_ingest.normalize` dan `render` (akun, IP sumber, severity, `kind`, `fields`). Kebenarannya terhadap ingest
asli diuji ujung ke ujung di devenv.
