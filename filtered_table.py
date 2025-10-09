#!/usr/bin/env python3
"""
Filter wallet/verifier times for reveal=0.80 and attrCount in [min..max].

Outputs:
  - times_wallet_verifier_attr{min}-{max}_reveal{reveal:.2f}.csv
  - times_wallet_verifier_attr{min}-{max}_reveal{reveal:.2f}.tex  (if --latex)

Usage:
  python make_filtered_table.py --dir ./multi_device_results --out tables_out \
      --reveal 0.80 --attr-min 5 --attr-max 10 --latex
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import List, Dict, Any, Tuple
import pandas as pd
import numpy as np

# -------- naming helpers (same logic as your plot script) ----------
DEVICE_SUFFIXES = {"mobile":"mobile","raspberry_pi":"raspberry_pi","raspberrypi":"raspberry_pi","pi":"raspberry_pi", "watch":"smartwatch"}

def split_impl_name(full: str) -> tuple[str, str]:
    s = (full or "").strip().replace(" ", "").replace("__", "_").replace("--", "-").lower()
    for suf in ["_mobile","-mobile","_raspberry_pi","-raspberry_pi","_raspberrypi","-raspberrypi","_pi","-pi", "_watch", "-watch"]:
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

# -------------------- IO --------------------
def find_inputs(args) -> List[Path]:
    paths: List[Path] = []
    if args.inputs:
        paths.extend(Path(p).expanduser().resolve() for p in args.inputs)
    if args.dir:
        d = Path(args.dir).expanduser().resolve()
        paths.extend(sorted(d.glob("*.jsonl")))
    uniq, seen = [], set()
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

# --------------- normalize rows ----------------
KNOWN_METRICS = ["wallet_ms","verifier_ms"]

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

        metrics = {}
        if isinstance(r.get("metrics"), dict):
            metrics = r["metrics"]
        else:
            for k,v in r.items():
                if isinstance(k,str) and k.endswith("_mean"):
                    metrics[k.replace("_mean","")] = _float(v)

        for k,v in list(r.items()):
            if isinstance(k,str) and k.startswith("metrics."):
                metrics[k.split(".",1)[1]] = v

        for m,v in metrics.items():
            if m in KNOWN_METRICS:
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

# -------------- aggregation ----------------
def aggregate_means(df: pd.DataFrame) -> pd.DataFrame:
    group_cols = ["base_impl","device","attrCount","revealRatio"]
    have_run = (df.get("type")=="run").fillna(False).any()
    have_sum = (df.get("type")=="summary").fillna(False).any()

    if have_run:
        runs = df[df["type"].eq("run")]
        g = runs.groupby(group_cols, dropna=True).agg(
            wallet_ms=("wallet_ms","mean"),
            verifier_ms=("verifier_ms","mean"),
            n=("wallet_ms","count"),
        ).reset_index()
    else:
        g = pd.DataFrame(columns=group_cols+["wallet_ms","verifier_ms","n"])

    if have_sum:
        summ = df[df["type"].eq("summary")].copy()
        s = summ[group_cols+["wallet_ms","verifier_ms"]].drop_duplicates()
        if g.empty:
            g = s.copy(); g["n"] = 1
        else:
            g = pd.merge(g, s, on=group_cols, how="outer", suffixes=("","_sum"))
            for c in ["wallet_ms","verifier_ms"]:
                g[c] = g[c].fillna(g[f"{c}_sum"])
            g["n"] = g["n"].fillna(1)
            g = g.drop(columns=[c for c in g.columns if c.endswith("_sum")])
    return g

def make_wide(g: pd.DataFrame) -> pd.DataFrame:
    pivot = g.pivot_table(
        index=["base_impl","attrCount","revealRatio"],
        columns="device",
        values=["wallet_ms","verifier_ms"],
        aggfunc="mean"
    )
    pivot.columns = [f"{dev}_{metric}" for metric, dev in pivot.columns]
    pivot = pivot.reset_index().sort_values(by=["base_impl","attrCount","revealRatio"])
    # Order columns
    cols = ["base_impl","attrCount","revealRatio"]
    for metric in ["wallet_ms","verifier_ms"]:
        for dev in ["desktop","mobile","raspberry_pi", "smartwatch"]:
            col = f"{dev}_{metric}"
            if col in pivot.columns: cols.append(col)
    for c in pivot.columns:
        if c not in cols: cols.append(c)
    return pivot[cols]

# -------------- filtering & save ----------------
def filter_and_save(wide: pd.DataFrame, outdir: Path, reveal: float, amin: int, amax: int, latex: bool):
    # robust match for reveal (round to 2 decimals)
    rr = wide["revealRatio"].round(2)
    mask = (rr.eq(round(reveal, 2))) & (wide["attrCount"].between(amin, amax, inclusive="both"))
    sl = wide.loc[mask].copy()
    if sl.empty:
        print("[i] No rows match your filters.", file=sys.stderr)
        return

    # Keep only wallet/verifier columns (across devices)
    keep = ["base_impl","attrCount","revealRatio"]
    for metric in ["wallet_ms","verifier_ms"]:
        for dev in ["desktop","mobile","raspberry_pi", "smartwatch"]:
            col = f"{dev}_{metric}"
            if col in sl.columns: keep.append(col)
    sl = sl[keep].sort_values(by=["attrCount","base_impl"])

    out_csv = outdir / f"times_wallet_verifier_attr{amin}-{amax}_reveal{round(reveal,2):.2f}.csv"
    sl.to_csv(out_csv, index=False)
    print(f"[i] wrote {out_csv}")

    if latex:
        cols = list(sl.columns)
        tex_path = outdir / f"times_wallet_verifier_attr{amin}-{amax}_reveal{round(reveal,2):.2f}.tex"
        with tex_path.open("w", encoding="utf-8") as fh:
            fh.write("\\begin{table}[t]\n\\centering\n")
            fh.write("\\caption{Wallet and Verifier times (ms) at reveal=%.2f and attributes %d--%d.}\n" % (round(reveal,2), amin, amax))
            fh.write("\\label{tab:times-filtered}\n")
            align = "l" * len(cols)
            fh.write("\\begin{tabular}{%s}\\toprule\n" % align)
            fh.write(" & ".join(c.replace("_","\\_") for c in cols) + " \\\\\\midrule\n")
            for _,row in sl.iterrows():
                vals = [("" if pd.isna(row[c]) else f"{row[c]:.3f}" if isinstance(row[c], float) else str(row[c])) for c in cols]
                fh.write(" & ".join(vals) + " \\\\\n")
            fh.write("\\bottomrule\n\\end{tabular}\n\\end{table}\n")
        print(f"[i] wrote {tex_path}")

# -------------------- main --------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", help="Directory with *.jsonl files")
    ap.add_argument("--inputs", nargs="*", help="Explicit list of JSONL files")
    ap.add_argument("--out", required=True, help="Output directory for tables")
    ap.add_argument("--reveal", type=float, required=True, help="Reveal ratio to filter (e.g., 0.80)")
    ap.add_argument("--attr-min", type=int, required=True, help="Minimum attrCount (inclusive)")
    ap.add_argument("--attr-max", type=int, required=True, help="Maximum attrCount (inclusive)")
    ap.add_argument("--latex", action="store_true", help="Also emit a LaTeX table")
    args = ap.parse_args()

    outdir = Path(args.out).resolve()
    outdir.mkdir(parents=True, exist_ok=True)

    files = find_inputs(args)
    print(f"[i] reading {len(files)} files")
    df = build_dataframe(files)
    g  = aggregate_means(df)
    wide = make_wide(g)
    filter_and_save(wide, outdir, reveal=args.reveal, amin=args.attr_min, amax=args.attr_max, latex=args.latex)

if __name__ == "__main__":
    main()
