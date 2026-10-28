# revisi-no-eph-step7.md — Verifikasi sertifikat ikut dihitung di komputasi EAP-TLS

**Alasan.** Model komputasi EAP-TLS di `crypto-breakdown.csv` / `handshake-compute.csv` hanya menghitung tanda tangan `CertificateVerify`. Padahal EAP-TLS mutual juga memverifikasi tanda tangan CA pada sertifikat peer: `SSL_VERIFY_PEER` di sisi client dan `ca_file` di FreeRADIUS. Proposal tidak memakai sertifikat, karena VK_I dan VK_R di-provision, jadi tidak ada verifikasi rantai sertifikat. Supaya perbandingannya adil, tambahkan **+1 verify per pihak** untuk EAP-TLS.

## 1. Cek algoritma tanda tangan CA

```bash
openssl x509 -in benchmark/certs-pqc/ca.pem -noout -text | grep -m2 "Signature Algorithm"       # harus mldsa44
openssl x509 -in <path cert classic, lihat switch_tls_config.sh> -noout -text | grep -m2 "Signature Algorithm"   # harus ED25519
```

- Rantainya: root CA (trusted, tidak diverifikasi) → sertifikat end-entity. Jadi cukup 1 verify per pihak.
- Jika ternyata ada intermediate CA, tambahkan 1 verify per intermediate.
- Jika algoritma CA berbeda dari yang di atas, pakai primitif yang sesuai dan laporkan.

## 2. Ubah model

- `benchmark/compute_tls_hybrid.py` (method 6): `mldsa_verify=2` untuk initiator **dan** responder (sebelumnya 1). Perbarui komentar model: "CertificateVerify + peer certificate signature".
- `benchmark/rsa_bench.py` (method 5): Ed25519 verify per pihak menjadi 2 (sebelumnya 1).
- Jalankan ulang kedua skrip, lalu perbarui `crypto-breakdown.csv` dan `handshake-compute.csv`.

Hasil yang diharapkan:

| Method | Initiator | Responder | Total |
|---|---:|---:|---:|
| 5 EAP-TLS Classic | 120.646 µs | 120.646 µs | 241.29 µs |
| 6 EAP-TLS Hybrid PQC | 467.442 µs | 426.907 µs | 894.35 µs |

Method 0–4 tidak berubah. Pengukuran E2E juga tidak berubah, karena run live memang sudah melakukan verifikasi sertifikat yang sebenarnya.

## 3. Notebook, gambar, paper

- Salin `EAP_Edhoc_Secondary_Authentication_v2.ipynb` dari lampiran ke `symmetry-rev/notebook/`. Isinya:
  - `compute_initiator[5,6] = 0.120646, 0.467442`;
  - `compute_responder[5,6] = 0.120646, 0.426907`;
  - legend di kiri atas.
- Salin juga `img_handshake_computation_grouped.png` dan `manuscript.tex` dari zip Overleaf lampiran ke `symmetry-rev/paper/`. Teks yang diubah:
  - §Testbed: "EAP-TLS Classic and Hybrid PQC $0.241$ and $0.894$ ms" beserta alasan verifikasi sertifikat;
  - Classical pair: EAP-EDHOC kini lebih murah ($0.152$--$0.182$ vs $0.241$ ms);
  - Hybrid pair: "$0.985$ vs $0.894$ ms", dengan penjelasan KEM dua arah dan pembuatan kunci rotasi vs verifikasi sertifikat.
- `analysis.md`: perbarui bagian 1b (tabel komputasi per method).

Commit: `bench: count peer-certificate verification in the EAP-TLS compute model`