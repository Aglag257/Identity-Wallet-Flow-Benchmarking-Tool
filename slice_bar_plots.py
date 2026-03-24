#!/usr/bin/env python3
from __future__ import annotations

import argparse
import math
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure
from matplotlib.patches import Patch

plt.rcParams["pdf.fonttype"] = 42
plt.rcParams["ps.fonttype"] = 42

IMPL_ORDER = ["sd-jwt", "bbs+(Rust)", "bbs2023(Rust)", "bbs2023(JS)"]
DEVICE_ORDER = ["desktop", "mobile", "raspberry_pi", "smartwatch"]

IMPL_DISPLAY = {
    "sd-jwt": "sd-jwt",
    "bbs+(Rust)": "bbs+(Rust)",
    "bbs2023(Rust)": "bbs2023\n(Rust)",
    "bbs2023(JS)": "bbs2023\n(JS)",
}

PANEL_DISPLAY = {
    "sd-jwt": "sd-jwt",
    "bbs+(Rust)": "bbs+(Rust)",
    "bbs2023(Rust)": "bbs2023(Rust)",
    "bbs2023(JS)": "bbs2023(JS)",
}

DEVICE_DISPLAY = {
    "desktop": "Desktop",
    "mobile": "Mobile",
    "raspberry_pi": "Raspberry Pi",
    "smartwatch": "Smartwatch",
}

DEVICE_SHORT = {
    "desktop": "Desktop",
    "mobile": "Mobile",
    "raspberry_pi": "Pi",
    "smartwatch": "Watch",
}

DEVICE_COLORS = {
    "desktop": "#d62728",
    "mobile": "#ff7f0e",
    "raspberry_pi": "#1f77b4",
    "smartwatch": "#2ca02c",
}

DEVICE_HATCHES = {
    "desktop": "",
    "mobile": "//",
    "raspberry_pi": "..",
    "smartwatch": "xx",
}

DEVICE_SUFFIXES = {
    "mobile": "mobile",
    "mobile2": "mobile2",
    "raspberry_pi": "raspberry_pi",
    "raspberrypi": "raspberry_pi",
    "pi": "raspberry_pi",
    "watch": "smartwatch",
}


def split_impl_name(full: str) -> tuple[str, str]:
    s = (full or "").strip().replace(" ", "").replace("__", "_").replace("--", "-").lower()
    for suf in [
        "_mobile",
        "-mobile",
        "-mobile2",
        "_mobile2",
        "_raspberry_pi",
        "-raspberry_pi",
        "_raspberrypi",
        "-raspberrypi",
        "_pi",
        "-pi",
        "_watch",
        "-watch",
    ]:
        if s.endswith(suf):
            base = s[: -len(suf)]
            dev = DEVICE_SUFFIXES.get(suf.strip("_-"), "desktop")
            return base, dev
    return s, "desktop"


def normalize_base_impl(base: str) -> str:
    b = base.lower()
    if b in {"legacyjwt", "jwt-legacy", "jwtlegacy", "jwt legacy"}:
        return "sd-jwt"
    if b in {"bbsplus", "json-bbs-plus", "jsonbbsplus"}:
        return "bbs+(Rust)"
    if b in {"bbsreviseddigitalbazar", "bbs2023-digitalbazaar", "bbs2023-digitalbazar"}:
        return "bbs2023(JS)"
    if b in {
        "bbsrevisedrust",
        "bbs2023-pairing-crypto",
        "bbs2023-rust",
        "bbs2023-pairing-crypto2",
        "bbs2023-rust2",
    }:
        return "bbs2023(Rust)"
    return b


def title_metric_name(metric: str) -> str:
    return {
        "wallet_ms": "Wallet time (ms)",
        "verifier_ms": "Verifier time (ms)",
        "issuer_ms": "Issuer time (ms)",
    }.get(metric, metric)


def _ordered(values: list[str], preferred: list[str]) -> list[str]:
    extras = [v for v in values if v not in preferred]
    return [v for v in preferred if v in values] + sorted(extras)


def load_runs(path: Path) -> pd.DataFrame:
    df = pd.read_csv(path)
    need = {"impl", "attrCount", "revealRatio"}
    missing = need - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns in {path}: {sorted(missing)}")
    return df


def build_slice(df: pd.DataFrame, attr_count: int, reveal_ratio: float, metric: str) -> pd.DataFrame:
    if metric not in df.columns:
        raise ValueError(f"Metric '{metric}' is not present in the input CSV.")

    sub = df[
        df["attrCount"].eq(attr_count)
        & df["revealRatio"].round(2).eq(round(reveal_ratio, 2))
    ].copy()
    if sub.empty:
        raise ValueError(
            f"No rows found for attrCount={attr_count}, revealRatio={round(reveal_ratio, 2):.2f}."
        )

    bases, devices = [], []
    for raw_impl in sub["impl"].astype(str):
        raw_base, device = split_impl_name(raw_impl)
        bases.append(normalize_base_impl(raw_base))
        devices.append(device)
    sub["base_impl"] = bases
    sub["device"] = devices

    agg = (
        sub.groupby(["base_impl", "device"], dropna=False)[metric]
        .agg(["mean", "std", "count"])
        .reset_index()
        .rename(columns={"mean": "metric_mean", "std": "metric_std", "count": "metric_count"})
    )

    impls = _ordered(agg["base_impl"].astype(str).unique().tolist(), IMPL_ORDER)
    devices = DEVICE_ORDER.copy()

    full_index = pd.MultiIndex.from_product([impls, devices], names=["base_impl", "device"])
    full = agg.set_index(["base_impl", "device"]).reindex(full_index).reset_index()
    full["status"] = np.where(full["metric_mean"].isna(), "missing", "present")
    full["attrCount"] = attr_count
    full["revealRatio"] = round(reveal_ratio, 2)
    return full


def format_value(value: float) -> str:
    if pd.isna(value):
        return "N/A"
    if value >= 1000:
        return f"{value:,.0f}"
    if value >= 100:
        return f"{value:.1f}"
    if value >= 10:
        return f"{value:.2f}"
    return f"{value:.3f}"


def axis_limits(values: pd.Series) -> tuple[float, float]:
    positive = values.dropna()
    positive = positive[positive > 0]
    if positive.empty:
        return 1.0, 10.0

    ymin = float(positive.min())
    ymax = float(positive.max())
    lower = 10 ** math.floor(math.log10(ymin))
    upper = 10 ** math.ceil(math.log10(ymax))
    if lower == upper:
        upper *= 10
    return lower / 1.25, upper * 1.4


def legend_handles() -> list[Patch]:
    return [
        Patch(
            facecolor=DEVICE_COLORS[device],
            edgecolor="black",
            hatch=DEVICE_HATCHES[device],
            label=DEVICE_DISPLAY[device],
        )
        for device in DEVICE_ORDER
    ]


def missing_note(grid: pd.DataFrame) -> str | None:
    missing = grid[grid["status"].eq("missing")]
    if missing.empty:
        return None
    labels = [
        f"{row.base_impl} / {DEVICE_DISPLAY.get(row.device, row.device)}"
        for row in missing.itertuples()
    ]
    return "Missing in source runs: " + "; ".join(labels)


def slice_title(metric: str, attr_count: int, reveal_ratio: float) -> str:
    metric_label = title_metric_name(metric).replace(" (ms)", "")
    return f"{metric_label} Slice: reveal={round(reveal_ratio, 2):.2f}, attrCount={attr_count}"


def plot_grouped_vertical(grid: pd.DataFrame, metric: str, attr_count: int, reveal_ratio: float) -> Figure:
    impls = grid["base_impl"].drop_duplicates().tolist()
    y_min, y_max = axis_limits(grid["metric_mean"])

    fig, ax = plt.subplots(figsize=(9.4, 5.4), dpi=150)
    centers = np.arange(len(impls))
    width = 0.18
    offsets = np.linspace(-1.5 * width, 1.5 * width, len(DEVICE_ORDER))

    for device, offset in zip(DEVICE_ORDER, offsets):
        part = (
            grid[grid["device"].eq(device)]
            .set_index("base_impl")
            .reindex(impls)
            .reset_index()
        )
        xs = centers + offset
        present = part["status"].eq("present")

        if present.any():
            values = part.loc[present, "metric_mean"].to_numpy(dtype=float)
            errors = part.loc[present, "metric_std"].fillna(0).to_numpy(dtype=float)
            ax.bar(
                xs[present.to_numpy()],
                values,
                width=width,
                color=DEVICE_COLORS[device],
                edgecolor="black",
                linewidth=0.6,
                hatch=DEVICE_HATCHES[device],
                yerr=errors,
                capsize=2,
                label=DEVICE_DISPLAY[device],
                zorder=3,
            )

            for x, value in zip(xs[present.to_numpy()], values):
                ax.text(
                    x,
                    value * 1.06,
                    format_value(value),
                    rotation=90,
                    ha="center",
                    va="bottom",
                    fontsize=7,
                )

        for row, x in zip(part.itertuples(), xs):
            if row.status == "missing":
                ax.text(
                    x,
                    y_min * 1.1,
                    "N/A",
                    rotation=90,
                    ha="center",
                    va="bottom",
                    fontsize=7,
                    color=DEVICE_COLORS[device],
                    fontweight="bold",
                )

    ax.set_yscale("log")
    ax.set_ylim(y_min, y_max)
    ax.set_ylabel(title_metric_name(metric))
    ax.set_xticks(centers)
    ax.set_xticklabels([IMPL_DISPLAY.get(impl, impl) for impl in impls])
    ax.set_title(slice_title(metric, attr_count, reveal_ratio))
    ax.grid(axis="y", which="both", linestyle=":", linewidth=0.6, alpha=0.55, zorder=0)
    ax.legend(handles=legend_handles(), frameon=False, ncol=4, loc="upper left")

    note = missing_note(grid)
    if note:
        fig.text(0.01, 0.01, note, ha="left", va="bottom", fontsize=8)

    fig.tight_layout(rect=(0, 0.04 if note else 0, 1, 1))
    return fig


def plot_grouped_horizontal(grid: pd.DataFrame, metric: str, attr_count: int, reveal_ratio: float) -> Figure:
    impls = grid["base_impl"].drop_duplicates().tolist()
    x_min, x_max = axis_limits(grid["metric_mean"])

    fig, ax = plt.subplots(figsize=(10.0, 5.8), dpi=150)
    centers = np.arange(len(impls))
    height = 0.18
    offsets = np.linspace(-1.5 * height, 1.5 * height, len(DEVICE_ORDER))

    for device, offset in zip(DEVICE_ORDER, offsets):
        part = (
            grid[grid["device"].eq(device)]
            .set_index("base_impl")
            .reindex(impls)
            .reset_index()
        )
        ys = centers + offset
        present = part["status"].eq("present")

        if present.any():
            values = part.loc[present, "metric_mean"].to_numpy(dtype=float)
            errors = part.loc[present, "metric_std"].fillna(0).to_numpy(dtype=float)
            ax.barh(
                ys[present.to_numpy()],
                values,
                height=height,
                color=DEVICE_COLORS[device],
                edgecolor="black",
                linewidth=0.6,
                hatch=DEVICE_HATCHES[device],
                xerr=errors,
                capsize=2,
                label=DEVICE_DISPLAY[device],
                zorder=3,
            )

            for y, value in zip(ys[present.to_numpy()], values):
                ax.text(
                    value * 1.03,
                    y,
                    format_value(value),
                    ha="left",
                    va="center",
                    fontsize=7,
                )

        for row, y in zip(part.itertuples(), ys):
            if row.status == "missing":
                ax.text(
                    x_min * 1.08,
                    y,
                    "N/A",
                    ha="left",
                    va="center",
                    fontsize=7,
                    color=DEVICE_COLORS[device],
                    fontweight="bold",
                )

    ax.set_xscale("log")
    ax.set_xlim(x_min, x_max)
    ax.set_xlabel(title_metric_name(metric))
    ax.set_yticks(centers)
    ax.set_yticklabels([PANEL_DISPLAY.get(impl, impl) for impl in impls])
    ax.set_title(slice_title(metric, attr_count, reveal_ratio))
    ax.grid(axis="x", which="both", linestyle=":", linewidth=0.6, alpha=0.55, zorder=0)
    ax.legend(handles=legend_handles(), frameon=False, ncol=4, loc="lower right")

    note = missing_note(grid)
    if note:
        fig.text(0.01, 0.01, note, ha="left", va="bottom", fontsize=8)

    fig.tight_layout(rect=(0, 0.04 if note else 0, 1, 1))
    return fig


def plot_small_multiples(grid: pd.DataFrame, metric: str, attr_count: int, reveal_ratio: float) -> Figure:
    impls = grid["base_impl"].drop_duplicates().tolist()
    y_min, y_max = axis_limits(grid["metric_mean"])

    fig, axes = plt.subplots(2, 2, figsize=(10.0, 7.2), dpi=150, sharey=True)
    axes = axes.flatten()

    for ax, impl in zip(axes, impls):
        part = (
            grid[grid["base_impl"].eq(impl)]
            .set_index("device")
            .reindex(DEVICE_ORDER)
            .reset_index()
        )
        xs = np.arange(len(DEVICE_ORDER))

        for row, x in zip(part.itertuples(), xs):
            if row.status == "present":
                ax.bar(
                    x,
                    row.metric_mean,
                    width=0.65,
                    color=DEVICE_COLORS[row.device],
                    edgecolor="black",
                    linewidth=0.6,
                    hatch=DEVICE_HATCHES[row.device],
                    yerr=0 if pd.isna(row.metric_std) else row.metric_std,
                    capsize=2,
                    zorder=3,
                )
                ax.text(
                    x,
                    row.metric_mean * 1.06,
                    format_value(row.metric_mean),
                    rotation=90,
                    ha="center",
                    va="bottom",
                    fontsize=7,
                )
            else:
                ax.text(
                    x,
                    y_min * 1.12,
                    "N/A",
                    rotation=90,
                    ha="center",
                    va="bottom",
                    fontsize=8,
                    color=DEVICE_COLORS[row.device],
                    fontweight="bold",
                )

        ax.set_title(PANEL_DISPLAY.get(impl, impl))
        ax.set_xticks(xs)
        ax.set_xticklabels([DEVICE_SHORT[d] for d in DEVICE_ORDER], rotation=20)
        ax.set_yscale("log")
        ax.set_ylim(y_min, y_max)
        ax.grid(axis="y", which="both", linestyle=":", linewidth=0.6, alpha=0.55, zorder=0)

    for ax in axes[: len(impls)]:
        ax.set_ylabel(title_metric_name(metric))

    for ax in axes[len(impls) :]:
        ax.axis("off")

    fig.suptitle(slice_title(metric, attr_count, reveal_ratio), y=0.98)
    fig.legend(handles=legend_handles(), loc="upper center", ncol=4, frameon=False, bbox_to_anchor=(0.5, 0.94))

    note = missing_note(grid)
    if note:
        fig.text(0.01, 0.01, note, ha="left", va="bottom", fontsize=8)

    fig.tight_layout(rect=(0, 0.04 if note else 0, 1, 0.91))
    return fig


def save_outputs(
    grid: pd.DataFrame,
    outdir: Path,
    attr_count: int,
    reveal_ratio: float,
    metric: str,
) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)

    prefix = f"{metric}_attr{attr_count}_reveal{round(reveal_ratio, 2):.2f}"
    csv_path = outdir / f"{prefix}_values.csv"
    grid.to_csv(csv_path, index=False)

    figures = [
        ("grouped_vertical", plot_grouped_vertical(grid, metric, attr_count, reveal_ratio)),
        ("grouped_horizontal", plot_grouped_horizontal(grid, metric, attr_count, reveal_ratio)),
        ("small_multiples", plot_small_multiples(grid, metric, attr_count, reveal_ratio)),
    ]

    combined_path = outdir / f"{prefix}_bar_variations.pdf"
    with PdfPages(combined_path) as pdf:
        for _, fig in figures:
            pdf.savefig(fig, bbox_inches="tight")

    written = [csv_path, combined_path]
    for suffix, fig in figures:
        pdf_path = outdir / f"{prefix}_{suffix}.pdf"
        fig.savefig(pdf_path, bbox_inches="tight")
        written.append(pdf_path)
        plt.close(fig)

    return written


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--runs-csv",
        default="multi_device_plots_paper/runs_only.csv",
        help="Normalized runs CSV previously written by plot.py",
    )
    ap.add_argument("--out", default=None, help="Output directory for the bar-chart slice")
    ap.add_argument("--attr-count", type=int, default=7, help="attrCount slice to plot")
    ap.add_argument("--reveal", type=float, default=0.80, help="revealRatio slice to plot")
    ap.add_argument("--metric", default="wallet_ms", help="Metric column to plot")
    args = ap.parse_args()

    runs_path = Path(args.runs_csv).resolve()
    outdir = (
        Path(args.out).resolve()
        if args.out
        else runs_path.parent / f"bar_slice_attr{args.attr_count}_reveal{round(args.reveal, 2):.2f}"
    )

    df = load_runs(runs_path)
    grid = build_slice(df, attr_count=args.attr_count, reveal_ratio=args.reveal, metric=args.metric)
    written = save_outputs(
        grid=grid,
        outdir=outdir,
        attr_count=args.attr_count,
        reveal_ratio=args.reveal,
        metric=args.metric,
    )

    print(f"[i] Wrote {len(written)} files to {outdir}")
    for path in written:
        print(f"    - {path}")


if __name__ == "__main__":
    main()
