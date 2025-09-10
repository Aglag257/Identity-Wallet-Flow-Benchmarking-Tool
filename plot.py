from __future__ import annotations
import argparse, json, os, sys, math
from pathlib import Path
from collections import defaultdict
from typing import List, Dict, Any, Tuple

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages



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
        if f"{m}_mean" not in df_merged.columns and f"{m}_mean" in df_summary.columns:
            pass
        if f"{m}_mean" not in df_merged.columns and f"{m}_mean" in df_from_runs.columns:
            pass
        if f"{m}_mean" not in df_merged.columns:
            if f"{m}_mean" in df_summary.columns:
                continue
            if f"{m}_mean" not in df_merged.columns and f"{m}_mean" not in df_summary.columns:
                if f"{m}_mean" in df_from_runs.columns:
                    continue
                if f"{m}_mean" not in df_merged.columns and f"{m}_mean" not in df_from_runs.columns:
                    run_col = f"{m}_mean"
                    if run_col not in df_merged.columns and f"{m}_mean" not in df_merged.columns:
                        if f"{m}_mean" not in df_merged.columns and f"{m}_mean" not in df_merged.columns:
                            pass
    for m in metrics_present:
        run_mean_col = f"{m}_mean"
        if run_mean_col not in df_merged.columns and f"{m}_mean" in df_from_runs.columns:
            df_merged[run_mean_col] = df_from_runs[f"{m}_mean"]
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

def plot_line_with_err(df_sum: pd.DataFrame, metric: str, outdir: Path, facet_by: str, const_value, x: str, group: str = "impl"):
    m_mean = f"{metric}_mean"
    m_std  = f"{metric}_std"
    if facet_by not in df_sum.columns:
        return
    sub = df_sum[df_sum[facet_by].eq(const_value)].dropna(subset=[m_mean])
    if sub.empty:
        return

    sub = sub.sort_values(by=[x, group])

    # Build plot
    plt.figure(figsize=(6.0, 4.0), dpi=150)
    for impl, part in sub.groupby(group):
        X = part[x].to_numpy(dtype=float)
        Y = part[m_mean].to_numpy(dtype=float)
        Yerr = None
        if m_std in part.columns and part.get(f"{metric}_count", pd.Series([0]*len(part))).fillna(0).astype(int).min() >= 2:
            Yerr = part[m_std].to_numpy(dtype=float)
        if Yerr is not None and np.isfinite(Yerr).any():
            plt.errorbar(X, Y, yerr=Yerr, marker='o', capsize=3, label=str(impl))
        else:
            plt.plot(X, Y, marker='o', label=str(impl))

    plt.xlabel(x if x != "revealRatio" else "Reveal ratio")
    plt.ylabel(title_metric_name(metric))
    if facet_by == "attrCount":
        plt.title(f"{title_metric_name(metric)} vs Reveal — attrCount={const_value}")
    else:
        plt.title(f"{title_metric_name(metric)} vs AttrCount — reveal={const_value:.2f}")
    plt.legend()
    fname = f"{metric}_vs_{'reveal' if x=='revealRatio' else 'attrCount'}_{facet_by}{const_value}.png"
    plt.tight_layout()
    plt.savefig(outdir / fname)
    plt.close()
    return outdir / fname


def plot_all(df_sum: pd.DataFrame, outdir: Path) -> List[Path]:
    figs: List[Path] = []
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
            p = plot_line_with_err(df_sum, m, outdir, facet_by="attrCount", const_value=ac, x="revealRatio")
            if p: figs.append(p)

    # 2) AttrCount runs for each revealRatio
    if "revealRatio" in df_sum.columns:
        reveals = sorted(df_sum["revealRatio"].dropna().unique())
        for m in metrics_present:
            for rv in reveals:
                p = plot_line_with_err(df_sum, m, outdir, facet_by="revealRatio", const_value=rv, x="attrCount")
                if p: figs.append(p)

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


#  Main 

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", help="Directory with *.jsonl files")
    ap.add_argument("--inputs", nargs="*", help="Explicit list of JSONL files")
    ap.add_argument("--out", default="paper_plots", help="Output directory for plots & tables")
    args = ap.parse_args()

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

    figs = plot_all(df_sum, outdir)
    print(f"[i] Wrote {len(figs)} plot images → {outdir}")

    # bundle PDF
    if figs:
        pdf_path = outdir / "all_plots.pdf"
        with PdfPages(pdf_path) as pdf:
            for img in figs:
                fig = plt.figure()
                img_arr = plt.imread(str(img))
                plt.imshow(img_arr)
                plt.axis("off")
                pdf.savefig(fig, bbox_inches="tight")
                plt.close(fig)
        print(f"[i] Wrote combined PDF → {pdf_path}")

    write_csv_tables(df_sum, outdir)
    print(f"[i] Tables saved in {outdir}")


if __name__ == "__main__":
    main()
