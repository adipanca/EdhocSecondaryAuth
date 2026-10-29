#!/usr/bin/env python3
"""
render_figures.py — run the code cells of the v2 notebook in a scratch
directory (headless matplotlib) and copy the figures the paper uses to
symmetry-rev/paper/img_<name>.png.

usage: render_figures.py [workdir]
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
NB = os.path.join(ROOT, "symmetry-rev/notebook/EAP_Edhoc_Secondary_Authentication_v2.ipynb")
PAPER = os.path.join(ROOT, "symmetry-rev/paper")
FIGS = {   # produced file (relative to the workdir) -> paper image
    "handshake_computation_grouped.png": "img_handshake_computation_grouped.png",
    "communication_breakdown_methods.png": "img_communication_breakdown_methods.png",
    "combined_mean_latency_loss.png": "img_combined_mean_latency_loss.png",
    "combined_mean_retransmissions.png": "img_combined_mean_retransmissions.png",
    "combined_95th_percentile_latency_loss.png": "img_combined_95th_percentile_latency_loss.png",
    "combined_success_rate_heatmap.png": "img_combined_success_rate_heatmap.png",
    "output/A1_primitive_mean.png": "img_A1_primitive_mean.png",
    "output/A2_compute_breakdown.png": "img_A2_compute_breakdown.png",
    "output/C_throughput.png": "img_C_throughput.png",
    "output/D_baseline_comparison.png": "img_D_baseline_comparison.png",
}

work = sys.argv[1] if len(sys.argv) > 1 else tempfile.mkdtemp(prefix="nbrun-")
os.makedirs(work, exist_ok=True)
cells = [c for c in json.load(open(NB))["cells"] if c["cell_type"] == "code"]
env = dict(os.environ, MPLBACKEND="Agg")
for i, c in enumerate(cells):
    path = os.path.join(work, f"cell{i}.py")
    with open(path, "w") as f:
        f.write("".join(c["source"]))
    with open(path + ".log", "w") as log:
        rc = subprocess.run([sys.executable, path], cwd=work, env=env,
                            stdout=log, stderr=subprocess.STDOUT).returncode
    if rc != 0:
        sys.exit(f"cell {i} failed, see {path}.log")
for src, dst in FIGS.items():
    shutil.copy(os.path.join(work, src), os.path.join(PAPER, dst))
print(f"rendered {len(cells)} cells in {work}; copied {len(FIGS)} figures to {PAPER}")
