# revisi-no-eph-step19.md: secondary authentication sesuai TS 23.502 dan relay UPF diperbaiki

Kerjakan step 18 (salin paper) lebih dulu jika belum.

Step ini memperbaiki implementasi 5G core di dua hal:
1. Secondary authentication dijalankan **di dalam** PDU session establishment, sebelum Accept, sesuai standar.
2. Relay SMF → UPF → DN-AAA dibuat efisien dan waktunya diukur per bagian.

**Protokol EDHOC, format pesan, kriptografi dan aturan sinkronisasi kunci tidak boleh diubah.**

## Acuan standar

- **TS 23.502 §4.3.2.2.1:** secondary authentication/authorization adalah langkah 6. Langkah ini terjadi setelah `Nsmf_PDUSession_CreateSMContext` Response (langkah 5), sebelum PCF dan pemilihan UPF (langkah 7–8), dan sebelum N1N2MessageTransfer berisi PDU Session Establishment Accept (langkah 11).
- **TS 23.502 §4.3.2.3 dan TS 33.501 §11.1.2:**
  - SMF mengirim EAP-Request/Identity ke UE dalam PDU SESSION AUTHENTICATION COMMAND;
  - UE menjawab dengan EAP-Response/Identity berisi **identitas khusus DN**, bukan SUPI;
  - semua pesan EAP selanjutnya lewat Command/Complete;
  - SMF boleh memakai UPF untuk transport ke DN-AAA.
- **TS 24.501 (PDU EAP authentication saat establishment):**
  - jika EAP sukses, EAP-Success dibawa di IE "EAP message" pada **PDU SESSION ESTABLISHMENT ACCEPT**;
  - jika EAP gagal, SMF mengirim **PDU SESSION ESTABLISHMENT REJECT** dengan cause #29 "user authentication or authorization failed" dan IE EAP message berisi EAP-Failure;
  - PDU SESSION AUTHENTICATION RESULT hanya untuk autentikasi ulang setelah sesi berdiri, jadi tidak dipakai di alur ini.

Cocokkan dulu detail di atas dengan teks TS 24.501 Rel-18 (bagian PDU EAP authentication, PDU session establishment, dan perlakuan T3580 saat autentikasi). Jika ada perbedaan, ikuti teks standarnya dan laporkan.

## 1. SMF (Open5GS): pindahkan secondary authentication ke dalam establishment

1. Tambahkan state baru `smf_gsm_state_wait_5gc_sec_auth`:
   - masuk ke state ini setelah CreateSMContext Response dan data langganan UDM diterima, dan sebelum asosiasi SM policy ke PCF;
   - hanya jika secondary auth aktif untuk DNN tersebut, lewat kunci konfigurasi per DNN di `smf.yaml`, misalnya `secondary_auth: edhoc`;
   - `OPEN5GS_SEC_AUTH=0` tetap ada untuk baseline.
2. Kirim EAP-Request/Identity (Identifier 1) di PDU SESSION AUTHENTICATION COMMAND, lewat N1N2MessageTransfer khusus N1.
   - **Hapus** EAP-Response/Identity buatan SMF yang berasal dari SUPI.
   - Identitas dari UE diteruskan ke DN-AAA sebagai EAP-Response/Identity dan User-Name.
3. Pesan EAP selanjutnya diteruskan seperti sekarang (Command/Complete).
4. **Access-Accept:**
   - simpan EAP-Success;
   - lanjutkan alur normal (PCF, pemilihan UPF, PFCP Session Establishment);
   - sisipkan EAP-Success di IE EAP message pada PDU SESSION ESTABLISHMENT ACCEPT.
5. **Access-Reject:** kirim PDU SESSION ESTABLISHMENT REJECT dengan cause #29, IE EAP message berisi EAP-Failure, lalu lepas SM context.
6. **Timeout atau error relay:** kirim Reject cause #29 **tanpa** EAP-Failure. Akibatnya UE tidak melakukan fallback, sesuai aturan sinkronisasi.
7. **Hapus:**
   - timer `sec_auth.t_start` (100 ms) beserta pemicunya di PDU Session Resource Setup Response;
   - pengiriman Authentication Result pada alur establishment.
8. **AMF:** pastikan Authentication Command tetap dikirim sebagai DL NAS Transport pada sesi yang belum berdiri, dan Complete diteruskan ke SMF lewat `UpdateSMContext`.

## 2. UE (UERANSIM)

1. Terima PDU SESSION AUTHENTICATION COMMAND saat sesi masih dalam status establishment pending (PSI sama, PTI 0).
2. Jawab EAP-Request/Identity dengan identitas DN dari `ue.yaml` (kunci baru, misalnya `secondaryAuth.identity`).
   - Identitas ini yang dipakai DN-AAA untuk memilih record.
   - Provision ulang dengan identitas tersebut.
3. **EAP-Success di ESTABLISHMENT ACCEPT** memicu langkah yang sama dengan EAP-Success sekarang, yaitu verifikasi selesai dan promosi NEXT.
4. **ESTABLISHMENT REJECT #29 berisi EAP-Failure** memicu fallback ke CUR, dengan NEXT tetap disimpan. Pembentukan PDU session berikutnya berjalan dengan CUR.
5. **Reject tanpa EAP-Failure** (timeout atau error) tidak memicu fallback.
6. Ikuti TS 24.501 untuk T3580 selama autentikasi, supaya Establishment Request tidak terkirim ulang di tengah EAP.

## 3. Relay SMF → UPF → DN-AAA

1. **UPF `eap-relay.c`:**
   - satu socket UDP persisten ke RADIUS, dibuka saat start;
   - RADIUS Identifier dinaikkan per request;
   - balasan dicocokkan berdasarkan Identifier dan Response Authenticator; balasan basi dibuang;
   - timeout tetap 2 s.
2. **SMF `radius-client.c`:** satu socket persisten ke relay UPF.
3. **SMF tidak boleh memblokir event loop.** Saat ini `recvfrom` sinkron bisa menahan SMF sampai 2 s dan menghentikan UE lain.
   - Ubah menjadi asinkron: daftarkan socket ke pollset Open5GS, tangani balasan sebagai event, dan pakai timer `ogs_timer` untuk timeout.
   - Jika tidak mungkin dikerjakan di step ini, laporkan alasannya, dan tulis batasan ini di `analisys2.md`.
4. **Tag `E4T` tambahan** supaya selisih 3,9 ms bisa diurai:
   - UPF: `upf_req_rx` (dari SMF), `upf_rad_tx`, `upf_rad_rx`, `upf_resp_tx` (ke SMF);
   - SMF: `smf_relay_tx`, `smf_relay_rx`.
   - Dari tag ini bisa dihitung: hop SMF↔UPF, pemrosesan relay (build/verify RADIUS), dan waktu FreeRADIUS.

## 4. Pengukuran ulang

1. Build ulang semuanya, lalu jalankan `edhoc4_xwing_kat`, `edhoc4_selftest` dan `edhoc4_dbtest`. Semua harus PASS.
2. **Konfigurasi A** (secondary auth) dan **B** (`OPEN5GS_SEC_AUTH=0`): 3 seri × 100 sesi, bergantian A1 B1 A2 B2 A3 B3, 5 sesi pemanasan dibuang.
3. **Konfigurasi C (baru):**
   - `e2e_radius_bench` method 4 langsung ke radiusd, sementara full stack menyala tetapi diam (tanpa sesi);
   - 3 seri × 100, diselipkan setelah setiap pasangan A/B.
   - Tujuannya memisahkan efek berbagi CPU dari efek relay.
4. **Pemulihan:** 10 + 10 drop dengan `E4_DROP_ONCE=msg3|msg4`. Yang diharapkan:
   - drop Message3: sesi berikutnya ditolak dengan Reject #29 + EAP-Failure, lalu fallback, dan pembentukan berikutnya sukses dengan CUR;
   - drop Message4: sesi berikutnya langsung sukses dengan NEXT;
   - desync 0 dan re-provisioning 0.
5. **Capture:**
   - satu `tcpdump -i lo` untuk satu sesi sukses dan satu sesi drop-Message3 (NGAP/SCTP, SBI HTTP/2, RADIUS);
   - simpan sebagai `benchmark-results/fullstack-v2-sample.pcap`;
   - tambahkan ringkasan urutan pesan dari `tshark` (`fullstack-v2-sequence.txt`) yang menunjukkan: Establishment Request → Authentication Command (EAP-Request/Identity) → Complete → … → Establishment Accept (EAP-Success), dan untuk kasus gagal: Establishment Reject #29 (EAP-Failure).

## 5. Output

**`benchmark-results/fullstack-handshake-v2.csv`** dengan kolom yang sama seperti step 17, ditambah:
- `t_hop_smf_upf_ms`, `t_relay_proc_ms`, `t_aaa_ms`;
- `id_identity` (identitas DN yang dipakai);
- `t_pdu_ms` = Request → Accept. Nilai ini sekarang **mencakup** secondary auth;
- `t_secauth_ms` = Command pertama → Accept diterima.

File lain:
- `fullstack-harness-shared.csv`: konfigurasi C;
- `fullstack-recovery-v2.csv`;
- file step 17 jangan dihapus.

**Bagian baru di `analisys2.md` ("Full 5G core path, standard order")** berisi:
- statistik seperti di step 17;
- `t_pdu_ms` A − B. Selisih ini sekarang menjadi biaya secondary auth di dalam establishment;
- uraian waktu relay: hop SMF↔UPF, pemrosesan relay, FreeRADIUS;
- konfigurasi C dibandingkan dengan `responder_ms` harness pada VM yang diam;
- hasil pemulihan;
- urutan pesan dari capture;
- perbandingan dengan step 17.

## Commit

1. `smf: secondary authentication inside PDU session establishment (TS 23.502 4.3.2.2.1 step 6), EAP-Success in Accept, Reject #29 with EAP-Failure`
2. `ue: EAP identity from DN-specific config, EAP result via Establishment Accept/Reject`
3. `relay: persistent sockets, non-blocking SMF relay, per-hop E4T timestamps`
4. `bench: full-stack v2 runs, shared-CPU harness runs, recovery, sample capture`

## Laporan balik

Kirimkan:
- tabel ringkasan dari bagian 5 dan uraian waktu relay;
- `t_pdu_ms` A − B;
- hasil pemulihan;
- urutan pesan dari capture;
- hash commit;
- penyimpangan apa pun dari TS 24.501 yang ditemukan saat implementasi.