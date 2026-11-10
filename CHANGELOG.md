# Changelog

## [Unreleased]

### Added

- Skor dan kartu deterministik (triage#3): klaster (sapuan + union-find, belah > 6 jam), lima temuan `K-*`, peran entitas, pola dari pohon syarat JSON, skor `L+T+A+K+R` dan band, `teknik_attack` (ID kanonik v19) dan `temuan_korelasi`, `paket_hash` kanonik, versi kartu hanya bila hash berubah, event `card.skeleton.created` lewat outbox.
- Konsumen `evidence.ingested` nyata: membaca alert dan bukti dari ingest (`/svc/v1`, token layanan, `batch_ref` divalidasi), tabel `alert_proyeksi`, `klaster`, `klaster_anggota`, `kartu_seq`, `kartu_versi`.
- Katalog sementara berversi (`katalog/katalog.json`, divalidasi Pydantic) sampai layanan `config` siap.
- Uji golden data `samples` (45 SEDANG, 77 KRITIS, 10 RENDAH), uji properti hypothesis, uji DB PostgreSQL, pyright di CI.

### Changed

- `astria-common` v0.2.2 dan `astria-contracts` v0.3.0.

### Removed

- Konsumen palsu Tahap 0 dan tabel `received_batches`.

### Added (Tahap 0)

- Kerangka layanan Tahap 0 dari templat `common` v0.1.0: `/health`, `/ready`, `/metrics`, token layanan, Dockerfile non-root, CI (lint, uji, gitleaks, build image, smoke `/ready`).
- Konsumen palsu Tahap 0 untuk `evidence.ingested` (mencatat batch yang diterima, idempoten).
- Logo Astria di kepala README (`.github/assets/`, dari kit logo di repo `triase-dfir-uiux`).
