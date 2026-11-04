# Paper sources

- **Build:** `pdflatex manuscript && bibtex manuscript && pdflatex manuscript && pdflatex manuscript`. Do not commit `.aux`, `.log`, `.out`, `.blg` or `diff_tc*`.
- **Protocol figure:** `drawio/Symmetry_Journal.drawio`, page "Final v4". Export as PNG with scale 2 to `img_SecondaryAuth2_v4.png`.
- **Other draw.io sources:** `drawio/testbed_architecture.drawio`, `drawio/testbed_architecture_paper.drawio`, `drawio/EAP-TLS_and_KeyGen_comparison.drawio`.
- **Where the E2E and full-stack numbers come from** (`../../benchmark-results/`):
  - `e2e-handshake.csv` (methods 4 and 6 = v4b);
  - `fullstack-handshake-v4b.csv`;
  - `fullstack-recovery-v4b.csv`;
  - `e2e-storage-flush-v4b.csv`.
- **Loss test:** uses the v3 handshake, which has the same number of round-trips (15).
