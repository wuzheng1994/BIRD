#!/usr/bin/env python3
"""Plot attribution CDFs from misattribution score tables."""

from __future__ import annotations

import argparse
import csv
import math
from pathlib import Path
from typing import Any


ERROR_DISTANCES = (1, 2, 3, 4, 5)
CATEGORY_ORDER = (
    "origin_hijack",
    "leak",
    "type1_hijack",
)
CATEGORY_TITLES = {
    "origin_hijack": "Prefix Hijack",
    "leak": "Route Leak",
    "type1_hijack": "Forged Origin Hijack",
}
PANEL_LETTERS = ("a", "b", "c", "d")
DISTANCE_COLORS = {
    0: "#222222",
    1: "#1B4F72",
    2: "#2E86AB",
    3: "#28A745",
    4: "#E67E22",
    5: "#C0392B",
}
SMOOTH_CDF_POINTS = 400
TIMES_FONT_FILES = (
    Path("/usr/share/fonts/timesnewroman/TIMES.TTF"),
    Path("/usr/share/fonts/timesnewroman/TIMESBD.TTF"),
    Path("/usr/share/fonts/timesnewroman/TIMESI.TTF"),
    Path("/usr/share/fonts/timesnewroman/TIMESBI.TTF"),
)


def configure_matplotlib() -> Any:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib import font_manager

    registered = False
    for font_path in TIMES_FONT_FILES:
        if not font_path.exists():
            continue
        font_manager.fontManager.addfont(str(font_path))
        registered = True

    if not registered:
        raise FileNotFoundError(
            "Times New Roman TTF not found under "
            "/usr/share/fonts/timesnewroman/"
        )

    family = font_manager.FontProperties(
        fname=str(TIMES_FONT_FILES[0])
    ).get_name()
    plt.rcParams.update({
        "font.family": family,
        "font.serif": [family],
        "mathtext.fontset": "stix",
        "axes.unicode_minus": False,
        "font.size": 18,
        "axes.titlesize": 22,
        "axes.labelsize": 20,
        "xtick.labelsize": 17,
        "ytick.labelsize": 17,
        "legend.fontsize": 16,
    })
    return plt


def category_delta_values(
    rows: list[dict[str, Any]],
    category: str | None,
    distance: int,
) -> list[float]:
    values: list[float] = []
    for row in rows:
        if (
            category is not None
            and row.get("event_category") != category
        ):
            continue
        label = row.get("label")
        level = int(
            row.get("topology_distance")
            or row.get("error_level")
            or -1
        )
        delta = row.get("delta_c")
        if delta in (None, ""):
            continue
        if distance == 0:
            if label == "correct" or level == 0:
                values.append(float(delta))
            continue
        if level != distance:
            continue
        if label not in (None, "wrong"):
            continue
        values.append(float(delta))
    return values


def smoothed_cdf(
    values: list[float],
    grid: list[float],
) -> list[float]:
    """Gaussian-kernel CDF: densify sparse samples into a fitted curve."""

    count = len(values)
    if count == 0:
        return [0.0 for _ in grid]
    ordered = sorted(values)
    if count == 1:
        spread = 0.03
    elif count == 2:
        spread = max((ordered[1] - ordered[0]) / 2.0, 0.03)
    else:
        q1 = ordered[(count - 1) // 4]
        q3 = ordered[(3 * (count - 1)) // 4]
        iqr = q3 - q1
        spread = (iqr / 1.349) if iqr > 1e-9 else 0.02
    silverman = 1.06 * spread * (count ** -0.2)
    cap = 0.05 if count <= 5 else 0.06
    bandwidth = min(max(silverman, 0.018), cap)
    scale = 1.0 / (bandwidth * math.sqrt(2.0))
    fitted: list[float] = []
    for point in grid:
        total = 0.0
        for value in values:
            total += 0.5 * (1.0 + math.erf((point - value) * scale))
        fitted.append(total / count)
    return fitted


def plot_cdf(
    rows: list[dict[str, Any]],
    threshold: float,
    output_root: Path,
) -> None:
    plt = configure_matplotlib()

    correct = sorted(
        row["score"] for row in rows
        if row["label"] == "correct"
    )
    wrong = sorted(
        row["score"] for row in rows
        if row["label"] == "wrong"
    )

    figure, axis = plt.subplots(
        figsize=(8.0, 5.2)
    )

    for values, label, color, style in (
        (
            wrong,
            f"Wrong attribution (n={len(wrong)})",
            "#C44E52",
            "--",
        ),
        (
            correct,
            f"Correct attribution (n={len(correct)})",
            "#2A6F97",
            "-",
        ),
    ):
        x = [0.0, *values, 1.0]
        y = [
            0.0,
            *[
                (index + 1) / len(values)
                for index in range(len(values))
            ],
            1.0,
        ]
        axis.step(
            x,
            y,
            where="post",
            label=label,
            color=color,
            linestyle=style,
            linewidth=2.2,
        )

    axis.axvline(
        threshold,
        color="#333333",
        linestyle=":",
        linewidth=1.3,
        label=f"Threshold = {threshold:.3f}",
    )
    axis.set_xlim(0, 1)
    axis.set_ylim(0, 1.02)
    axis.set_xlabel(
        "Coverage-adjusted path similarity M",
        fontsize=20,
    )
    axis.set_ylabel(
        "Empirical cumulative probability",
        fontsize=20,
    )
    axis.tick_params(labelsize=17)
    axis.grid(
        True,
        color="#D9D9D9",
        linewidth=0.6,
    )
    axis.legend(
        loc="lower right",
        frameon=False,
        fontsize=16,
    )
    figure.tight_layout()
    figure.savefig(
        output_root
        / "attribution_score_cdf.png",
        dpi=220,
    )
    figure.savefig(
        output_root
        / "attribution_score_cdf.pdf"
    )
    plt.close(figure)


def plot_delta_c_cdf(
    rows: list[dict[str, Any]],
    output_root: Path,
) -> None:
    plt = configure_matplotlib()

    series = ((0, "Correct"),) + tuple(
        (distance, f"{distance}-hop")
        for distance in ERROR_DISTANCES
    )
    panels = tuple(
        (category, CATEGORY_TITLES[category])
        for category in CATEGORY_ORDER
    ) + ((None, "Overall"),)
    all_values = [
        value
        for category, _title in panels
        for distance, _label in series
        for value in category_delta_values(
            rows, category, distance
        )
    ]
    if all_values:
        left = min(-0.02, min(all_values) - 0.06)
        right = max(1.02, max(all_values) + 0.06)
    else:
        left, right = -0.02, 1.02
    step = (right - left) / (SMOOTH_CDF_POINTS - 1)
    grid = [left + index * step for index in range(SMOOTH_CDF_POINTS)]

    figure, axes = plt.subplots(
        2,
        2,
        figsize=(10.4, 9.2),
        sharey=True,
        sharex=True,
    )
    plotted = False
    handles = []
    labels = []

    for index, (axis, (category, title)) in enumerate(
        zip(axes.ravel(), panels)
    ):
        letter = PANEL_LETTERS[index]
        axis.set_ylim(0, 1.02)
        axis.set_xlim(left, right)
        axis.tick_params(labelsize=17, labelbottom=True)
        axis.grid(True, color="#D9D9D9", linewidth=0.6)
        axis.set_xlabel(
            r"$\Delta C$" + "\n" + f"({letter}) {title}",
            fontsize=20,
            labelpad=6,
        )

        for distance, label in series:
            values = category_delta_values(
                rows, category, distance
            )
            if not values:
                continue
            plotted = True
            fitted = smoothed_cdf(values, grid)
            line = axis.plot(
                grid,
                fitted,
                label=label,
                color=DISTANCE_COLORS[distance],
                linewidth=2.3 if distance == 0 else 2.0,
                linestyle="--" if distance == 0 else "-",
            )[0]
            if category == CATEGORY_ORDER[0]:
                handles.append(line)
                labels.append(label)

    axes[0, 0].set_ylabel("CDF", fontsize=20)
    axes[1, 0].set_ylabel("CDF", fontsize=20)
    if handles:
        figure.legend(
            handles,
            labels,
            loc="lower center",
            ncol=len(series),
            frameon=False,
            fontsize=16,
            bbox_to_anchor=(0.5, -0.02),
        )

    if not plotted:
        plt.close(figure)
        return

    figure.tight_layout()
    figure.subplots_adjust(bottom=0.14, hspace=0.38, wspace=0.16)
    for stem in (
        "attribution_delta_c_cdfv1",
        "attribution_delta_c_cdf",
    ):
        figure.savefig(
            output_root / f"{stem}.png",
            dpi=220,
            bbox_inches="tight",
        )
        figure.savefig(
            output_root / f"{stem}.pdf",
            bbox_inches="tight",
        )
    plt.close(figure)


def load_score_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8", newline="") as file:
        for row in csv.DictReader(file):
            score = row.get("score")
            row["score"] = (
                None if score in (None, "") else float(score)
            )
            delta = row.get("delta_c")
            row["delta_c"] = (
                None if delta in (None, "") else float(delta)
            )
            row["topology_distance"] = int(
                float(
                    row.get("topology_distance")
                    or row.get("error_level")
                    or 0
                )
            )
            row["error_level"] = int(
                float(row.get("error_level") or 0)
            )
            rows.append(row)
    return rows


def choose_threshold_from_rows(
    rows: list[dict[str, Any]],
) -> float:
    correct = [
        row["score"] for row in rows
        if row["label"] == "correct"
        and row.get("score") is not None
    ]
    wrong = [
        row["score"] for row in rows
        if row["label"] == "wrong"
        and row.get("score") is not None
    ]
    if not correct or not wrong:
        return 0.0
    candidates = sorted(set(correct + wrong))
    best = (float("-inf"), 0.0)
    for threshold in candidates:
        true_pos = sum(score >= threshold for score in correct)
        true_neg = sum(score < threshold for score in wrong)
        tpr = true_pos / len(correct)
        tnr = true_neg / len(wrong)
        youden = tpr + tnr - 1.0
        if youden > best[0]:
            best = (youden, threshold)
    return best[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Redraw misattribution CDF figures from an "
            "existing attribution_scores.csv"
        )
    )
    parser.add_argument(
        "--scores",
        type=Path,
        default=Path("outputs/misattribution/attribution_scores.csv"),
    )
    parser.add_argument(
        "--output-root",
        type=Path,
        default=None,
    )
    args = parser.parse_args(argv)
    output_root = (
        args.output_root
        if args.output_root is not None
        else args.scores.resolve().parent
    )
    rows = load_score_rows(args.scores)
    if not rows:
        raise SystemExit(f"No score rows in {args.scores}")
    output_root.mkdir(parents=True, exist_ok=True)
    plot_cdf(rows, choose_threshold_from_rows(rows), output_root)
    plot_delta_c_cdf(rows, output_root)
    print(f"[+] Saved: {output_root / 'attribution_delta_c_cdf.png'}")
    print(f"[+] Saved: {output_root / 'attribution_score_cdf.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
