from __future__ import annotations
import argparse, json, os, sys, math
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Tuple

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure

from matplotlib.lines import Line2D
import csv

plt.rcParams['pdf.fonttype'] = 42
plt.rcParams['ps.fonttype'] = 42

DEVICE_SUFFIXES = {
    "mobile": "mobile",
    "mobile2": "mobile2",
    "raspberry_pi": "raspberry_pi",
    "raspberrypi": "raspberry_pi",
    "pi": "raspberry_pi",
    "watch": "smartwatch",
}

IMPL_ORDER   = ["jwt-legacy", "json-bbs-plus", "bbs2023-pairing-crypto", "bbs2023-digitalbazaar"]
DEVICE_ORDER = ["desktop", "mobile", "mobile2", "raspberry_pi", "watch"]


def split_impl_name(full: str) -> tuple[str, str]:
    s = (full or "").strip().replace(" ", "").replace("__", "_").replace("--", "-").lower()
    for suf in ["_mobile", "-mobile", "-mobile2", "_mobile2", "_raspberry_pi", "-raspberry_pi", "_raspberrypi", "-raspberrypi", "_pi", "-pi", "_watch", "-watch"]:
        if s.endswith(suf):
            base = s[: -len(suf)]
            dev  = DEVICE_SUFFIXES.get(suf.strip("_-"), "desktop")
            return base, dev
    return s, "desktop"

def normalize_base_impl(base: str) -> str:
    b = base.lower()
    if b in {"legacyjwt", "jwt-legacy", "jwtlegacy"}:
        return "jwt-legacy"
    if b in {"bbsplus", "json-bbs-plus", "jsonbbsplus"}:
        return "json-bbs-plus"
    if b in {"bbsreviseddigitalbazar", "bbs2023-digitalbazaar", "bbs2023-digitalbazar"}:
        return "bbs2023-digitalbazaar"
    if b in {"bbsrevisedrust", "bbs2023-pairing-crypto", "bbs2023-rust", "bbs2023-pairing-crypto2", "bbs2023-rust2" }:
        return "bbs2023-pairing-crypto"
    return b

COLOR_BY_IMPL = {
    "jwt-legacy":             "#d62728", 
    "json-bbs-plus":          "#2ca02c", 
    "bbs2023-pairing-crypto": "#ff7f0e", 
    "bbs2023-digitalbazaar":  "#1f77b4",  
    "bbs-plus":               "#9467bd",
}

# BW-friendly marker per *base implementation*
MARKER_BY_IMPL = {
    "jwt-legacy":             "s",  # square
    "json-bbs-plus":          "^",  # triangle up
    "bbs2023-pairing-crypto": "D",  # diamond
    "bbs2023-digitalbazaar":  "v",  # triangle down
    "bbs-plus":               "X",
}

# Line style by *device*
LINESTYLE_BY_DEVICE = {
    "desktop":      "-",
    "mobile":       "--",
    "mobile2":      (0, (5, 2)),
    "raspberry_pi": ":",
    "smartwatch":   "-.",
}


def find_inputs(args) -> List[Path]:
    paths: List[Path] = []
    if args.inputs:
        paths.extend(Path(p).expanduser().resolve() for p in args.inputs)
    if args.dir:
        d = Path(args.dir).expanduser().resolve()
        paths.extend(sorted(d.glob("*.jsonl")))
    if not paths:
        print("No input files. Use --dir or --inputs.", file=sys.stderr)
        sys.exit(2)
    uniq = []
    seen = set()
    for p in paths:
        if p.exists() and p.suffix.lower() == ".jsonl" and p not in seen:
            uniq.append(p)
            seen.add(p)
    return uniq


def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError as e:
                print(f"[warn] {path.name}:{ln}: bad JSONL line ({e})", file=sys.stderr)
                continue
    return rows


#  Normalization 

KNOWN_METRICS = [
    "issuer_ms", "wallet_ms", "verifier_ms",
    "issuer_cpu_ms", "wallet_cpu_ms", "verifier_cpu_ms",
    "e2e_ms",  # (issuer+wallet+verifier)
    "payload_present_bytes", "vc_size_bytes", "proof_size_bytes",
]

def _stem_impl_name(p: Path) -> str:
    return p.stem.replace("_", "-").replace(".", "-")

def _float(x):
    try:
        return float(x)
    except Exception:
        return np.nan

def flatten_rows(rows: List[Dict[str, Any]], src_file: Path) -> List[Dict[str, Any]]:
    out = []
    default_impl = _stem_impl_name(src_file)

    for r in rows:
        row: Dict[str, Any] = {"src_file": src_file.name}
        row["impl"] = r.get("impl") or default_impl

        attr_count = r.get("attrCount", r.get("attr_count"))
        if attr_count is not None:
            row["attrCount"] = int(attr_count)
        reveal_ratio = r.get("revealRatio")
        if reveal_ratio is None and "revealPct" in r:
            reveal_ratio = _float(r["revealPct"]) / 100.0
        if reveal_ratio is not None:
            row["revealRatio"] = float(reveal_ratio)

        metrics = {}
        if "metrics" in r and isinstance(r["metrics"], dict):
            metrics = r["metrics"]
        else:
            for k in list(r.keys()):
                if k.endswith("_mean"):
                    metrics[k.replace("_mean", "")] = _float(r[k])
                if k in ("payload_present_bytes", "vc_size_bytes", "proof_size_bytes"):
                    metrics[k] = _float(r[k])

        for k, v in list(r.items()):
            if isinstance(k, str) and k.startswith("metrics."):
                metrics[k.split(".", 1)[1]] = v

        for m, v in metrics.items():
            try:
                row[m] = float(v)
            except Exception:
                pass

        if all(m in row for m in ["issuer_ms", "wallet_ms", "verifier_ms"]):
            row["e2e_ms"] = row["issuer_ms"] + row["wallet_ms"] + row["verifier_ms"]

        row["type"] = r.get("type") or "unknown"
        out.append(row)

    return out


def build_dataframe(files: List[Path]) -> pd.DataFrame:
    all_rows = []
    for p in files:
        raw = load_jsonl(p)
        all_rows.extend(flatten_rows(raw, p))
    if not all_rows:
        print("No usable rows from inputs.", file=sys.stderr)
        sys.exit(1)
    df = pd.DataFrame(all_rows)

    if "attrCount" in df:
        df["attrCount"] = pd.to_numeric(df["attrCount"], errors="coerce").astype("Int64")
    if "revealRatio" in df:
        df["revealRatio"] = pd.to_numeric(df["revealRatio"], errors="coerce")
    for m in KNOWN_METRICS:
        if m in df:
            df[m] = pd.to_numeric(df[m], errors="coerce")

    need_cols = [c for c in ["impl", "attrCount", "revealRatio"] if c in df.columns]
    df = df.dropna(subset=need_cols)
    return df


#  Aggregation logic 

def aggregate(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame]:
    have_run = (df.get("type") == "run").fillna(False).any()
    have_sum = (df.get("type") == "summary").fillna(False).any()

    group_cols = ["impl", "attrCount", "revealRatio"]
    metrics_present = [m for m in KNOWN_METRICS if m in df.columns]

    # RUN aggregation
    df_runs = df[df.get("type").eq("run")] if have_run else pd.DataFrame(columns=df.columns)
    agg = {}
    for m in metrics_present:
        agg[m] = ["mean", "std", "count"]
    if have_run and not df_runs.empty:
        g = df_runs.groupby(group_cols, dropna=True).agg(agg)
        g.columns = ["%s_%s" % (m, stat) for m, stat in g.columns]
        df_from_runs = g.reset_index()
    else:
        df_from_runs = pd.DataFrame(columns=group_cols + [f"{m}_{s}" for m in metrics_present for s in ("mean","std","count")])

    # SUMMARY passthrough
    if have_sum:
        df_sum_rows = df[df["type"].eq("summary")].copy()
        for m in metrics_present:
            if m in df_sum_rows.columns:
                df_sum_rows.rename(columns={m: f"{m}_mean"}, inplace=True)
        df_summary = df_sum_rows[group_cols + [c for c in df_sum_rows.columns if c.endswith("_mean")]].drop_duplicates()
    else:
        df_summary = pd.DataFrame(columns=group_cols + [f"{m}_mean" for m in metrics_present])

    if not df_from_runs.empty:
        df_merged = df_from_runs.copy()
    else:
        df_merged = pd.DataFrame(columns=group_cols)

    if not df_summary.empty:
        df_merged = pd.merge(df_merged, df_summary, on=group_cols, how="outer")

    if df_merged.empty:
        print("No aggregatable rows found.", file=sys.stderr)
        sys.exit(1)

    for m in metrics_present:
        if f"{m}_mean" not in df_merged.columns and f"{m}_mean" in df_from_runs.columns:
            df_merged[f"{m}_mean"] = df_from_runs[f"{m}_mean"]
    if have_run:
        for m in metrics_present:
            if f"{m}_mean" not in df_merged.columns and f"{m}_mean" in df_from_runs.columns:
                df_merged = pd.merge(
                    df_merged,
                    df_from_runs[group_cols + [f"{m}_mean"]],
                    on=group_cols, how="left"
                )

    keep_cols = group_cols + sum(([f"{m}_mean", f"{m}_std", f"{m}_count"] for m in metrics_present), [])
    keep_cols = [c for c in keep_cols if c in df_merged.columns]
    df_out = df_merged[keep_cols].copy()

    return df_out, df_runs.copy()


#  Plotting 

def ensure_out_dir(outdir: Path):
    outdir.mkdir(parents=True, exist_ok=True)

def title_metric_name(m: str) -> str:
    return {
        "issuer_ms": "Issuer time (ms)",
        "wallet_ms": "Wallet time (ms)",
        "verifier_ms": "Verifier time (ms)",
        "e2e_ms": "End-to-end time (ms)",
        "issuer_cpu_ms": "Issuer CPU (ms)",
        "wallet_cpu_ms": "Wallet CPU (ms)",
        "verifier_cpu_ms": "Verifier CPU (ms)",
        "payload_present_bytes": "Presentation payload (bytes)",
        "vc_size_bytes": "VC size (bytes)",
        "proof_size_bytes": "Proof size (bytes)",
    }.get(m, m)

def plot_line_with_err(
    df_sum: pd.DataFrame,
    metric: str,
    facet_by: str,
    const_value,
    x: str,
    group: str = "impl",
    show_legend: bool = True,
) -> Tuple[Figure, str] | None:
    m_mean = f"{metric}_mean"
    m_std  = f"{metric}_std"
    if facet_by not in df_sum.columns:
        return None

    sub = df_sum[df_sum[facet_by].eq(const_value)].dropna(subset=[m_mean]).copy()
    if sub.empty:
        return None

    bases, devs = [], []
    for v in sub[group].astype(str):
        raw_base, dev = split_impl_name(v)
        base = normalize_base_impl(raw_base)
        bases.append(base)
        devs.append(dev)
    sub["_base_impl"] = bases
    sub["_device"] = devs

    # deterministic ordering: by base impl then device, then x
    sub.sort_values(by=["_base_impl", "_device", x], inplace=True)

    fig, ax = plt.subplots(figsize=(6.0, 4.0), dpi=150)

    for (base_impl, device), part in sub.groupby(["_base_impl", "_device"], sort=False):
        color  = COLOR_BY_IMPL.get(base_impl, "#7f7f7f")
        marker = MARKER_BY_IMPL.get(base_impl, "o")
        ls     = LINESTYLE_BY_DEVICE.get(device, "-")

        X = part[x].to_numpy(dtype=float)
        Y = part[m_mean].to_numpy(dtype=float)

        yerr = None
        if m_std in part.columns:
            counts = part.get(f"{metric}_count")
            if counts is not None and (counts.fillna(0).astype(int) >= 2).any():
                yerr = part[m_std].to_numpy(dtype=float)

        label = f"{base_impl}_{device}"

        ax.plot(
            X, Y, marker=marker, linestyle=ls,
            label=label, color=color, markersize=5, linewidth=1.5,
        )

    ax.set_xlabel(x if x != "revealRatio" else "Reveal ratio")
    ax.set_ylabel(title_metric_name(metric))

    # log-scale only for time/CPU metrics
    if metric.endswith("_ms") or metric in {"e2e_ms", "issuer_cpu_ms", "wallet_cpu_ms", "verifier_cpu_ms"}:
        ax.set_yscale("log")

    if facet_by == "attrCount":
        ax.set_title(f"{title_metric_name(metric)} vs Reveal — attrCount={const_value}")
    else:
        try:
            ax.set_title(f"{title_metric_name(metric)} vs AttrCount — reveal={float(const_value):.2f}")
        except Exception:
            ax.set_title(f"{title_metric_name(metric)} vs AttrCount — reveal={const_value}")

    if show_legend:
        ax.legend(frameon=False, fontsize=8, ncol=1)

    fig.tight_layout()

    name = f"{metric}_vs_{'reveal' if x=='revealRatio' else 'attrCount'}_{facet_by}{const_value}"
    return fig, name


def plot_all(df_sum: pd.DataFrame, show_legend: bool) -> List[Tuple[Figure, str]]:
    figs: List[Tuple[Figure, str]] = []
    metrics_present = sorted(set(k.split("_mean")[0] for k in df_sum.columns if k.endswith("_mean")))
    have_iwv = all(f"{m}_mean" in df_sum.columns for m in ("issuer_ms","wallet_ms","verifier_ms"))
    if have_iwv and "e2e_ms_mean" not in df_sum.columns:
        df_sum["e2e_ms_mean"] = df_sum["issuer_ms_mean"] + df_sum["wallet_ms_mean"] + df_sum["verifier_ms_mean"]
        metrics_present.append("e2e_ms")

    # 1) Reveal runs for each attrCount
    for m in metrics_present:
        if "revealRatio" not in df_sum.columns: 
            continue
        for ac in sorted(df_sum["attrCount"].dropna().unique().astype(int)):
            res = plot_line_with_err(df_sum, m, facet_by="attrCount", const_value=ac, x="revealRatio", show_legend=show_legend)
            if res:
                figs.append(res)

    # 2) AttrCount runs for each revealRatio
    if "revealRatio" in df_sum.columns:
        reveals = sorted(df_sum["revealRatio"].dropna().unique())
        for m in metrics_present:
            for rv in reveals:
                res = plot_line_with_err(df_sum, m, facet_by="revealRatio", const_value=rv, x="attrCount", show_legend=show_legend)
                if res:
                    figs.append(res)

    return figs


#  Tabular outputs 

def write_csv_tables(df_sum: pd.DataFrame, outdir: Path):
    wide = df_sum.set_index(["impl","attrCount","revealRatio"]).sort_index()
    wide.to_csv(outdir / "summary_means_by_impl_attr_reveal.csv")
    if not wide.empty:
        try:
            max_ac = int(df_sum["attrCount"].max())
            sl = df_sum[(df_sum["attrCount"]==max_ac) & (df_sum["revealRatio"].isin([0.2, 1.0]))]
            sl = sl.sort_values(by=["revealRatio","impl"])
            sl.to_csv(outdir / f"paper_slice_attr{max_ac}_reveal{['0.2','1.0']}.csv", index=False)
        except Exception:
            pass



def _present_impl_device_pairs(df_sum: pd.DataFrame) -> list[tuple[str, str]]:
    pairs: set[tuple[str, str]] = set()
    for impl in df_sum["impl"].astype(str).unique():
        base_raw, dev = split_impl_name(impl)
        base = normalize_base_impl(base_raw)
        pairs.add((base, dev))
    def _impl_rank(b):   return IMPL_ORDER.index(b)   if b in IMPL_ORDER   else 999
    def _dev_rank(d):    return DEVICE_ORDER.index(d) if d in DEVICE_ORDER else 999
    return sorted(pairs, key=lambda t: (_impl_rank(t[0]), _dev_rank(t[1]), t[0], t[1]))

def save_style_legend(outdir: Path, df_sum: pd.DataFrame, ncols: int = 2):
    pairs = _present_impl_device_pairs(df_sum)
    handles, labels = [], []
    for base, dev in pairs:
        color  = COLOR_BY_IMPL.get(base, "#7f7f7f")
        marker = MARKER_BY_IMPL.get(base, "o")
        ls     = LINESTYLE_BY_DEVICE.get(dev, "-")
        handles.append(Line2D([0],[0], color=color, marker=marker, linestyle=ls,
                              linewidth=1.8, markersize=6))
        labels.append(f"{base}_{dev}")

    fig_h = 2 + 0.18 * max(1, (len(handles) + ncols - 1) // ncols)
    fig, ax = plt.subplots(figsize=(7.2, fig_h), dpi=150)
    ax.axis("off")
    ax.legend(handles, labels, loc="center", frameon=False, ncol=ncols, columnspacing=1.2, handletextpad=0.8)
    fig.tight_layout()
    fig.savefig(outdir / "style_legend.pdf", bbox_inches="tight")
    plt.close(fig)

    with open(outdir / "style_legend.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["label", "base_impl", "device", "color_hex", "marker", "linestyle"])
        for base, dev in pairs:
            w.writerow([
                f"{base}_{dev}", base, dev,
                COLOR_BY_IMPL.get(base, "#7f7f7f"),
                MARKER_BY_IMPL.get(base, "o"),
                LINESTYLE_BY_DEVICE.get(dev, "-"),
            ])

#  Main 

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", help="Directory with *.jsonl files")
    ap.add_argument("--inputs", nargs="*", help="Explicit list of JSONL files")
    ap.add_argument("--out", default="paper_plots", help="Output directory for plots & tables")
    ap.add_argument("--save-individual-pdfs", action="store_true",
                    help="Also save each plot as its own vector PDF file")
    ap.add_argument(
        "--legend", choices=["external", "inline", "none"], default="external",
        help="Where to place the legend. 'external' saves a separate legend PDF/CSV; "
            "'inline' draws legends on each plot; 'none' omits legends."
    )

    args = ap.parse_args()

    legend_mode = args.legend
    inputs = find_inputs(args)
    outdir = Path(args.out).resolve()
    ensure_out_dir(outdir)

    print(f"[i] Reading {len(inputs)} files:")
    for p in inputs:
        print(f"    - {p}")

    df = build_dataframe(inputs)
    df_sum, df_runs = aggregate(df)

    df.to_csv(outdir / "all_rows_normalized.csv", index=False)
    df_sum.to_csv(outdir / "summary_aggregated.csv", index=False)
    if not df_runs.empty:
        df_runs.to_csv(outdir / "runs_only.csv", index=False)

    figs = plot_all(df_sum, show_legend=(legend_mode == "inline"))

    print(f"[i] Prepared {len(figs)} plots (vector)")

    # bundle multi-page PDF directly from figures (vector)
    if figs:
        pdf_path = outdir / "all_plots.pdf"
        with PdfPages(pdf_path) as pdf:
            for fig, name in figs:
                pdf.savefig(fig, bbox_inches="tight")
                if args.save_individual_pdfs:
                    fig.savefig(outdir / f"{name}.pdf", bbox_inches="tight")
                plt.close(fig)
        print(f"[i] Wrote combined PDF → {pdf_path}")
    else:
        print("[i] No plots to write.")

    write_csv_tables(df_sum, outdir)
    print(f"[i] Tables saved in {outdir}")
    
    if legend_mode == "external":
        save_style_legend(outdir, df_sum, ncols=2)



if __name__ == "__main__":
    main()
