# Implementasi — EAP-EDHOC method 4 v2 (tanpa ephemeral X-Wing, tanpa kid)

Instruksi lengkap (integrasi, benchmark, angka yang diharapkan) ada di `../revisi-no-eph.md`.

- `edhoc4/` — `edhoc4.c`, `edhoc4.h`, `selftest.c`, `edhoc03.c`, `edhoc03.h`, `Makefile` versi baru; ganti file yang sama di repo.
- `edhoc4_v2.patch` — diff terhadap `EdhocSecondaryAuth` commit `5eb75075` (`git apply`).
- `aead_link_v2.patch` — tambah `-lmbedcrypto` di FreeRADIUS, UERANSIM, dan `benchmark/Makefile`.
- `benchmark_v2.patch` — op count method 4 di `crypto_bench.c` dan model ukuran di `edhoc_sizes.py`.

Perubahan inti:
- Message1 = (ct_B, AEAD(K_1, PT1)); PT1 kini memuat ID_CRED_I; TH_1 = H(ct_B).
- Message2 = (ct_A, AEAD(K_2, PT2)); TH_2 = H(H(M1), ct_A); PRK_2e = Extract(TH_2, ss_A); PRK_4e3m = PRK_3e2m.
- Record per UE di DN-AAA dipilih dari EAP identity (RADIUS User-Name), lookup (pk_A, VK_I) dari ID_CRED_I via `edhoc4_set_lookup`.
- `edhoc4_commit()` memasang kunci rotasi dan menghapus sk lama.
- AEAD: AES-128-GCM (mbedTLS) untuk method 0–4, menggantikan ChaCha20-Poly1305. Perlu `libmbedtls-dev`.

Selftest: 1141 / 4880 / 4975 / 1232 B (total 12228 B), 2 UE x 3 sesi, PASS; `edhoc03_selftest` ALL PASS.
