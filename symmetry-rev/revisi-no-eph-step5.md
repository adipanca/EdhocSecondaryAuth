# revisi-no-eph-step5.md — Penyempurnaan Performance Evaluation (branch `symmetry-no-eph`)

Tujuan: menutup enam celah yang mungkin ditanyakan reviewer di §Performance. Protokol **tidak perlu** diukur ulang; hanya satu run kecil (high-N method 0–3) yang diulang.

File:
- paper: `symmetry-rev/paper/manuscript.tex`
- notebook: `symmetry-rev/notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb`

Setiap penggantian di bawah memakai teks yang ada di commit `cef60102`. Jika anchor tidak ditemukan persis, cari kalimat yang setara; jangan ubah angka lain.

---

## 1. Hapus panel simulasi dari grafik loss (gunakan E2E live saja)

**Alasan.** Simulasi `lossy_bench.py` selalu memakai 2 round-trip tanpa fragmentasi, sehingga semua method tampak sama dan panel kiri tidak informatif.

**Notebook.**
- `plot_line_pair(...)` dan heatmap sukses saat ini menggambar dua panel: simulasi di kiri dan E2E di kanan. Ubah agar hanya menggambar **satu panel E2E**:
  - tambahkan parameter `show_sim=False`;
  - jika `False`, buat `fig, ax = plt.subplots(1, 1, figsize=(9, 5.5))` dan plot `e2e_data` saja;
  - judul: "End-to-End (Live EAP-over-RADIUS)".
- Heatmap: hanya baris `e2e_success`.
- Data `sim_*` **jangan dihapus** dari notebook. Biarkan, dengan komentar `# not plotted: the simulation does not model EAP fragmentation`.
- Regenerate dan salin ke `symmetry-rev/paper/`:
  - `img_combined_mean_latency_loss.png`
  - `img_combined_mean_retransmissions.png`
  - `img_combined_95th_percentile_latency_loss.png`
  - `img_combined_success_rate_heatmap.png`

Nama file tetap sama, jadi LaTeX tidak perlu diubah selain caption.

**Paper**, caption di sekitar baris 579 dan 588:

```latex
\caption{Mean behaviour under packet loss: (\textbf{a}) end-to-end latency; (\textbf{b}) retransmissions.\label{fig:loss_mean}}
```
→
```latex
\caption{Mean behaviour under packet loss over the live EAP-over-RADIUS path ($120$ trials per cell): (\textbf{a}) end-to-end latency; (\textbf{b}) retransmissions.\label{fig:loss_mean}}
```

```latex
\caption{Tail latency and reliability under packet loss: (\textbf{a}) 95th-percentile latency; (\textbf{b}) success-rate heatmap.\label{fig:loss_tail}}
```
→
```latex
\caption{Tail latency and reliability under packet loss over the live EAP-over-RADIUS path: (\textbf{a}) 95th-percentile latency; (\textbf{b}) success rate.\label{fig:loss_tail}}
```

---

## 2. Ulang run high-N method 0–3 pada mesin idle

Angka "pooled run of 10,000 … medians 0.987–1.033 ms" berasal dari sesi sebelum E2E idle (commit `19e7b456`), sedangkan median di kalimat yang sama (0.840–0.911 ms) berasal dari run idle. Ulangi run stabilitas dalam kondisi idle yang sama: tanpa ProVerif atau proses berat lain, dan radiusd baru di-restart.

```bash
cd benchmark
# perintah yang sama seperti commit 19e7b456 (2 x 5000 handshake per method, urutan berlawanan)
python3 stability_0_3.py            # tulis ulang benchmark-results/stability-0-3.csv dan e2e-handshake-highn.csv
python3 e2e_analyze.py ../benchmark-results
```

Perbarui angka di paper:
- baris ~564: "gives medians of $0.987$--$1.033$~ms";
- Threats to validity (3): "about $\pm3$~\textmu s", "only $45$~\textmu s".

Tambahkan juga frasa "on the same idle machine" setelah "in two opposite orders".

Jika median high-N baru masih berbeda lebih dari 10 % dari median run 100 iterasi, tulis keduanya dan sebutkan bahwa run high-N lebih andal.

---

## 3. Caption grafik handshake: "Responder" bukan kerja DN-AAA murni

Caption sekitar baris 552:

```latex
\caption{Per-method handshake computation cost (\textbf{left}) and end-to-end handshake time (\textbf{right}).\label{fig:handshake_computation_grouped}}
```
→
```latex
\caption{Per-method handshake computation cost (\textbf{left}) and end-to-end handshake time (\textbf{right}). In the right panel, ``Initiator'' is the UE's local processing (including storing its rotated key for the proposal) and ``Responder'' is the time the UE waits for replies, which includes the RADIUS round-trips, the DN-AAA's processing, and its key storage.\label{fig:handshake_computation_grouped}}
```

**Notebook:** ubah label legend panel kanan menjadi `"Initiator (UE local)"` dan `"Responder (wait incl. transport)"`, lalu regenerate `img_handshake_computation_grouped.png`.

---

## 4. Proyeksi terhadap RTT jaringan (tabel baru)

**Alasan.** Testbed memakai loopback (RTT ≈ 0), sehingga fragmentasi tampak murah. Padahal fragmentasi justru tempat proposal unggul. Model linier sederhana dari angka terukur:

T(RTT) ≈ T_loopback + (jumlah RADIUS round-trip) × RTT

Sisipkan setelah paragraf "Two costs drive the gap … well under/much cheaper …" (akhir paragraf baris ~564), sebelum paragraf "The two panels of Figure …":

```latex
Because all components share one VM, the round-trip time (RTT) between the SMF and the DN-AAA is close to zero, which understates the cost of fragmentation. Table~\ref{tab:rtt-projection} projects the measured loss-free means to a non-zero RTT with $T(\mathrm{RTT}) \approx T_{\mathrm{loopback}} + n_{\mathrm{RT}}\cdot \mathrm{RTT}$, where $n_{\mathrm{RT}}$ is the measured number of RADIUS round-trips. The fixed storage cost of the proposal is then quickly outweighed: the proposal overtakes EAP-TLS Hybrid PQC from an RTT of about $0.25$~ms, and at $10$~ms it is $1.9\times$ faster ($153$ vs.\ $290$~ms).

\begin{table}[H]
\caption{Loss-free handshake time projected to a non-zero SMF--DN-AAA round-trip time, $T_{\mathrm{loopback}} + n_{\mathrm{RT}}\cdot\mathrm{RTT}$ (ms), from the measured means and round-trip counts.\label{tab:rtt-projection}}
\footnotesize
\begin{tabular*}{\textwidth}{@{\extracolsep{\fill}}lrrrrrr@{}}
\toprule
\textbf{Method} & $\boldsymbol{n_{\mathrm{RT}}}$ & \textbf{0~ms} & \textbf{1~ms} & \textbf{5~ms} & \textbf{10~ms} & \textbf{20~ms} \\
\midrule
EAP-EDHOC Methods 0--3 (median) & 3  & 0.9  & 3.9  & 15.9  & 30.9  & 60.9  \\
EAP-TLS Classic                 & 6  & 2.7  & 8.7  & 32.7  & 62.7  & 122.7 \\
Proposal (durable key storage)  & 14 & 13.2 & 27.2 & 83.2  & 153.2 & 293.2 \\
EAP-TLS Hybrid PQC              & 28 & 9.7  & 37.7 & 149.7 & 289.7 & 569.7 \\
\bottomrule
\end{tabular*}
\end{table}
```

Catatan:
- Angka 0 ms adalah nilai terukur: median 0.88 ms untuk method 0–3 (pakai median baru dari langkah 2 jika berubah, lalu hitung ulang barisnya), 2.699, 13.223, dan 9.696 ms.
- Titik impas: (13.223 − 9.696) / (28 − 14) = 0.25 ms.
- Rasio pada 10 ms: 289.7 / 153.2 = 1.89.

Hitung ulang semua angka dengan skrip kecil. Jangan diketik manual.

Ubah juga Threats to validity (1):

```latex
(1) All components share one VM over loopback, so the network figures are a lower bound; a smaller path MTU or higher RTT in a distributed deployment would make fragmentation more pronounced.
```
→
```latex
(1) All components share one VM over loopback, so the network figures are a lower bound; a smaller path MTU or a higher RTT in a distributed deployment makes fragmentation more pronounced, which Table~\ref{tab:rtt-projection} quantifies under a linear model that ignores queuing and congestion.
```

---

## 5. Signifikansi statistik di uji loss

Dengan 120 percobaan per sel, interval Wilson 95 % adalah:
- 86.7 % (104/120) → [79.4, 91.6] %;
- 77.5 % (93/120) → [69.2, 84.1] %.

Kedua interval sedikit tumpang tindih. Tambahkan validasi dengan model analitis: hasil terukur cocok dengan model sederhana, dan ini memperkuat kesimpulan tanpa klaim signifikansi berlebih.

**Model analitis.** Satu round-trip berhasil dengan peluang p = (1 − L)², gagal permanen setelah 7 percobaan dengan peluang (1 − p)⁷, sukses handshake = (1 − (1 − p)⁷)^{n_RT}, dan retransmisi ≈ n_RT · (1 − p) / p.

Pada L = 30 %: proposal 88.1 %, ~14.6 retx, ~583 ms; EAP-TLS Hybrid 77.7 %, ~29.1 retx, ~1166 ms; method 0–3 97.3 %. Verifikasi angka ini dengan skrip.

Di paragraf loss (baris ~571), ganti:

```latex
Within each security level EAP-EDHOC is the more loss-tolerant:
```
→
```latex
With $120$ trials per cell the success rates carry Wilson $95\%$ intervals of about $\pm6$ points (e.g., $[79.4, 91.6]\%$ for the proposal and $[69.2, 84.1]\%$ for EAP-TLS Hybrid PQC at $30\%$ loss), so we read the ordering together with a simple model: if one round-trip succeeds with probability $p=(1-L)^2$ and an exchange fails after $7$ attempts, a handshake with $n_{\mathrm{RT}}$ round-trips succeeds with probability $(1-(1-p)^7)^{n_{\mathrm{RT}}}$. At $30\%$ loss this predicts $88.1\%$ for the proposal and $77.7\%$ for EAP-TLS Hybrid PQC, matching the measured $86.7\%$ and $77.5\%$, and about $14.6$ and $29.1$ retransmissions at $40$~ms each ($\approx583$ and $1{,}166$~ms against the measured $598$ and $1{,}207$~ms). The loss behaviour is therefore governed by the number of round-trips. Within each security level EAP-EDHOC is the more loss-tolerant:
```

Tambahan:
- Hitung Wilson CI dan prediksi model dengan skrip, lalu cantumkan di `benchmark-results/analisys2.md`, bagian "Validasi model analitis loss".
- Bila retransmisi terukur yang dikutip adalah rata-rata semua percobaan (11.3), sebutkan itu. Prediksi 14.6 adalah per handshake sukses (terukur 13.1 di antara yang sukses), jadi tulis "13.1 among successful handshakes" agar sebanding.

---

## 6. Framing tmpfs dan klaim flush

Baris ~564, ganti:

```latex
on server storage with power-loss protection a flush typically takes well under $0.1$~ms.
```
→
```latex
storage with a power-loss-protected write cache completes a flush much faster than our virtual disk, so this share is specific to the testbed.
```

Bila ingin mempertahankan angka "< 0.1 ms", tambahkan sitasi ke datasheet SSD enterprise atau ke pengukuran fsync yang terpublikasi. Tanpa sitasi, pakai kalimat di atas.

Baris ~568, ganti:

```latex
with the key directories on \texttt{tmpfs} the proposal is the faster of the two ($5.314$~ms mean, $5.207$~ms median).
```
→
```latex
with the key directories on \texttt{tmpfs} it takes $5.314$~ms (median $5.207$~ms), faster than EAP-TLS Hybrid PQC. \texttt{tmpfs} is not crash-safe and the protocol's forward secrecy relies on durable rotation, so this figure is a lower bound on the storage cost, not a deployment configuration; Table~\ref{tab:rtt-projection} shows that the proposal is faster anyway once the network RTT exceeds about $0.25$~ms.
```

---

## 7. Final check

1. Jalankan notebook dari atas sampai bawah. Semua PNG baru disalin ke `symmetry-rev/paper/`.
2. Kompilasi: `pdflatex`, `bibtex`, `pdflatex` ×2. Pastikan 0 error dan tidak ada reference `??`. Tabel baru `tab:rtt-projection` harus tampil dan dirujuk.
3. Tracked changes: `latexdiff --math-markup=0 old.tex manuscript.tex > diff.tex` → `manuscript_tracked_changes.pdf`.
4. `grep -n "pend\|TODO\|0\.987\|well under"` di `manuscript.tex`: tidak boleh ada sisa yang tidak disengaja.
5. Bersihkan `symmetry-rev/revisi-no-eph-step4.md`: hapus semuanya setelah baris "Commit: …". Salinan `.pv` yang ter-paste di sana tidak diperlukan.

Commit:
- `paper/notebook: live-only loss figures, RTT projection, loss model check`
- `bench: idle high-N re-run for methods 0-3`