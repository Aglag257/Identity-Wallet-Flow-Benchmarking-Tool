#!/usr/bin/env python3
"""
Build device-by-metric tables from multi-device benchmark JSONL logs.

Output:
  - times_by_impl_attr_reveal.csv    (wide table across devices/metrics)
  - times_slice_attr{N}_reveal{...}.csv  (optional compact slice for paper)
  - times_slice_attr{N}_reveal{...}.tex  (optional LaTeX tabular)

Usage examples:
  python make_table.py --dir ./multi_device_results --out tables_out
  python make_table.py --dir ./multi_device_results --out tables_out --slice-attr max --slice-reveals 0.2 1.0 --latex
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

# ----------------- naming & style helpers (aligned with your plot script) -----------------
DEVICE_SUFFIXES = {"mobile":"mobile","raspberry_pi":"raspberry_pi","raspberrypi":"raspberry_pi","pi":"raspberry_pi"}

def split_impl_name(full: str) -> tuple[str, str]:
    s = (full or "").strip().replace(" ", "").replace("__", "_").replace("--", "-").lower()
    for suf in ["_mobile","-mobile","_raspberry_pi","-raspberry_pi","_raspberrypi","-raspberrypi","_pi","-pi"]:
        if s.endswith(suf):
            base = s[: -len(suf)]
            dev  = DEVICE_SUFFIXES.get(suf.strip("_-"), "desktop")
            return base, dev
    return s, "desktop"

def normalize_base_impl(base: str) -> str:
    b = (base or "").lower()
    if b in {"legacyjwt","jwt-legacy","jwtlegacy"}:
        return "jwt-legacy"
    if b in {"bbsplus","json-bbs-plus","jsonbbsplus"}:
        return "json-bbs-plus"
    if b in {"bbsreviseddigitalbazar","bbs2023-digitalbazaar","bbs2023-digitalbazar"}:
        return "bbs2023-digitalbazaar"
    if b in {"bbsrevisedrust","bbs2023-pairing-crypto","bbs2023-rust"}:
        return "bbs2023-pairing-crypto"
    return b

# ----------------- IO -----------------
def find_inputs(args) -> List[Path]:
    paths: List[Path] = []
    if args.inputs:
        paths.extend(Path(p).expanduser().resolve() for p in args.inputs)
    if args.dir:
        d = Path(args.dir).expanduser().resolve()
        paths.extend(sorted(d.glob("*.jsonl")))
    uniq = []
    seen = set()
    for p in paths:
        if p.exists() and p.suffix.lower() == ".jsonl" and p not in seen:
            uniq.append(p); seen.add(p)
    if not uniq:
        print("No input files. Use --dir or --inputs.", file=sys.stderr)
        sys.exit(2)
    return uniq

def load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows = []
    with path.open("r", encoding="utf-8") as f:
        for ln, line in enumerate(f, 1):
            s = line.strip()
            if not s: continue
            try:
                rows.append(json.loads(s))
            except json.JSONDecodeError as e:
                print(f"[warn] {path.name}:{ln}: bad JSONL ({e})", file=sys.stderr)
    return rows

# ----------------- normalize rows -----------------
KNOWN_METRICS = ["issuer_ms","wallet_ms","verifier_ms","issuer_cpu_ms","wallet_cpu_ms","verifier_cpu_ms","payload_present_bytes","vc_size_bytes","proof_size_bytes"]

def _stem_impl_name(p: Path) -> str:
    return p.stem.replace("_","-").replace(".","-")

def _float(x):
    try: return float(x)
    except Exception: return np.nan

def flatten_rows(rows: List[Dict[str, Any]], src_file: Path) -> List[Dict[str, Any]]:
    out = []; default_impl = _stem_impl_name(src_file)
    for r in rows:
        row: Dict[str, Any] = {"src_file": src_file.name}
        row["impl"] = r.get("impl") or default_impl

        ac = r.get("attrCount", r.get("attr_count"))
        if ac is not None: row["attrCount"] = int(ac)

        rr = r.get("revealRatio")
        if rr is None and "revealPct" in r: rr = _float(r["revealPct"])/100.0
        if rr is not None: row["revealRatio"] = float(rr)

        # collect metrics
        metrics = {}
        if isinstance(r.get("metrics"), dict):
            metrics = r["metrics"]
        else:
            for k,v in r.items():
                if isinstance(k,str) and k.endswith("_mean"):
                    metrics[k.replace("_mean","")] = _float(v)
                if k in ("payload_present_bytes","vc_size_bytes","proof_size_bytes"):
                    metrics[k] = _float(v)
        for k,v in list(r.items()):
            if isinstance(k,str) and k.startswith("metrics."):
                metrics[k.split(".",1)[1]] = v

        for m,v in metrics.items():
            try: row[m] = float(v)
            except Exception: pass

        row["type"] = r.get("type") or "unknown"
        out.append(row)
    return out

def build_dataframe(files: List[Path]) -> pd.DataFrame:
    all_rows = []
    for p in files:
        all_rows.extend(flatten_rows(load_jsonl(p), p))
    if not all_rows:
        print("No usable rows.", file=sys.stderr); sys.exit(1)

    df = pd.DataFrame(all_rows)
    if "attrCount" in df:   df["attrCount"]   = pd.to_numeric(df["attrCount"], errors="coerce").astype("Int64")
    if "revealRatio" in df: df["revealRatio"] = pd.to_numeric(df["revealRatio"], errors="coerce")
    for m in KNOWN_METRICS:
        if m in df: df[m] = pd.to_numeric(df[m], errors="coerce")

    need = [c for c in ["impl","attrCount","revealRatio"] if c in df.columns]
    df = df.dropna(subset=need)

    # derive base_impl and device from impl
    base_list, dev_list = [], []
    for s in df["impl"].astype(str):
        raw, dev = split_impl_name(s)
        base_list.append(normalize_base_impl(raw))
        dev_list.append(dev)
    df["base_impl"] = base_list
    df["device"]    = dev_list
    return df

# ----------------- aggregation & tables -----------------
def aggregate_means(df: pd.DataFrame) -> pd.DataFrame:
    """Prefer run-level means; fall back to summary means if present."""
    group_cols = ["base_impl","device","attrCount","revealRatio"]
    have_run = (df.get("type")=="run").fillna(False).any()
    have_sum = (df.get("type")=="summary").fillna(False).any()

    if have_run:
        runs = df[df["type"].eq("run")]
        g = runs.groupby(group_cols, dropna=True).agg(
            wallet_ms=("wallet_ms","mean"),
            verifier_ms=("verifier_ms","mean"),
            n=("wallet_ms","count")
        ).reset_index()
    else:
        g = pd.DataFrame(columns=group_cols+["wallet_ms","verifier_ms","n"])

    if have_sum:
        summ = df[df["type"].eq("summary")].copy()
        for c in ["wallet_ms","verifier_ms"]:
            if c in summ.columns:
                summ.rename(columns={c: f"{c}"}, inplace=True)
        s = summ[group_cols+["wallet_ms","verifier_ms"]].drop_duplicates()
        if g.empty:
            g = s.copy()
            g["n"] = 1
        else:
            # outer-merge, prefer run means; fill missing from summary
            g = pd.merge(g, s, on=group_cols, how="outer", suffixes=("","_sum"))
            for c in ["wallet_ms","verifier_ms"]:
                g[c] = g[c].fillna(g[f"{c}_sum"])
            g["n"] = g["n"].fillna(1)
            drop = [f"{c}_sum" for c in ["wallet_ms","verifier_ms"] if f"{c}_sum" in g.columns]
            g = g.drop(columns=drop, errors="ignore")

    # clean types
    for c in ["wallet_ms","verifier_ms"]:
        if c in g: g[c] = pd.to_numeric(g[c], errors="coerce")
    return g

def make_wide_table(g: pd.DataFrame) -> pd.DataFrame:
    """Pivot to columns per device+metric."""
    pivot = g.pivot_table(
        index=["base_impl","attrCount","revealRatio"],
        columns="device",
        values=["wallet_ms","verifier_ms"],
        aggfunc="mean"
    )
    # Flatten columns like ('wallet_ms','mobile') -> 'mobile_wallet_ms'
    pivot.columns = [f"{dev}_{metric}" for metric, dev in pivot.columns]
    pivot = pivot.reset_index().sort_values(by=["base_impl","attrCount","revealRatio"])
    # Order columns nicely
    cols = ["base_impl","attrCount","revealRatio"]
    for metric in ["wallet_ms","verifier_ms"]:
        for dev in ["desktop","mobile","raspberry_pi"]:
            col = f"{dev}_{metric}"
            if col in pivot.columns: cols.append(col)
    # include any extras (just in case)
    for c in pivot.columns:
        if c not in cols: cols.append(c)
    return pivot[cols]

def save_slice_tables(wide: pd.DataFrame, outdir: Path, slice_attr, slice_reveals: List[float], latex: bool):
    # resolve attr selection
    if slice_attr == "max":
        attr_vals = wide["attrCount"].dropna()
        if len(attr_vals)==0: return
        attr_sel = int(attr_vals.max())
    else:
        attr_sel = int(slice_attr)

    sl = wide[wide["attrCount"].eq(attr_sel) & wide["revealRatio"].isin(slice_reveals)].copy()
    if sl.empty: return
    sl = sl.sort_values(by=["revealRatio","base_impl"])

    csv_path = outdir / f"times_slice_attr{attr_sel}_reveal{','.join(map(str, slice_reveals))}.csv"
    sl.to_csv(csv_path, index=False)

    if latex:
        tex_path = outdir / f"times_slice_attr{attr_sel}_reveal{','.join(map(str, slice_reveals))}.tex"
        # Simple LaTeX tabular (adjust columns if you like)
        cols = ["base_impl","revealRatio","desktop_wallet_ms","mobile_wallet_ms","raspberry_pi_wallet_ms",
                "desktop_verifier_ms","mobile_verifier_ms","raspberry_pi_verifier_ms"]
        cols = [c for c in cols if c in sl.columns]
        with tex_path.open("w", encoding="utf-8") as fh:
            fh.write("\\begin{table}[t]\n\\centering\n")
            fh.write("\\caption{Wallet and Verifier times (ms) at attrCount=%d.}\n" % attr_sel)
            fh.write("\\label{tab:times-slice}\n")
            align = "l" * len(cols)
            fh.write("\\begin{tabular}{%s}\\toprule\n" % align)
            fh.write(" & ".join(cols).replace("_","\\_") + " \\\\\\midrule\n")
            for _,row in sl[cols].iterrows():
                vals = [str(row[c] if not pd.isna(row[c]) else "") for c in cols]
                fh.write(" & ".join(vals) + " \\\\\n")
            fh.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", help="Directory with *.jsonl files")
    ap.add_argument("--inputs", nargs="*", help="Explicit list of JSONL files")
    ap.add_argument("--out", required=True, help="Output directory for tables")
    ap.add_argument("--slice-attr", default=None, help="AttrCount slice: integer or 'max'")
    ap.add_argument("--slice-reveals", nargs="*", type=float, default=[], help="RevealRatio values to keep in slice (e.g., 0.2 1.0)")
    ap.add_argument("--latex", action="store_true", help="Also emit a LaTeX tabular for the slice")
    args = ap.parse_args()

    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    files = find_inputs(args)
    print(f"[i] reading {len(files)} files")
    df = build_dataframe(files)
    g  = aggregate_means(df)
    wide = make_wide_table(g)

    out_csv = outdir / "times_by_impl_attr_reveal.csv"
    wide.to_csv(out_csv, index=False)
    print(f"[i] wrote {out_csv}")

    if args.slice_attr and args.slice_reveals:
        save_slice_tables(wide, outdir, args.slice_attr, args.slice_reveals, args.latex)

if __name__ == "__main__":
    main()
