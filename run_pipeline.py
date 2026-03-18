"""
run_pipeline.py -- CLI Entry Point for the Security Log Analyzer
=================================================================
This script provides a single command-line interface to run all (or
individual) stages of the Security Log Analyzer pipeline, instead of
having to remember the correct order and run each script manually.

Pipeline stages (in execution order):
    1. generate   - Create synthetic login data with injected attacks
    2. preprocess - Parse timestamps & extract temporal features
    3. features   - Engineer behavioural features for the ML model
    4. train      - Train the Isolation Forest anomaly-detection model
    5. detect     - Run the model and write anomaly reports
    6. alerts     - Run ML + rule engine, store alerts in SQLite/JSON
    7. evaluate   - Measure model accuracy against ground-truth labels
    8. visualize  - Generate the anomalies-by-date bar chart
    9. dashboard  - Launch the Django web dashboard (interactive)

Usage examples:
    python run_pipeline.py                  # run the full pipeline (stages 1-8)
    python run_pipeline.py all              # same as above
    python run_pipeline.py generate         # run only stage 1
    python run_pipeline.py train detect     # run stages 4 and 5
    python run_pipeline.py dashboard        # launch the web dashboard
    python run_pipeline.py --list           # show available stages
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Project root directory (where this script lives)
# ---------------------------------------------------------------------------
# All file paths in the pipeline are relative to the project root,
# so we need to know where that is. Path(__file__).resolve().parent
# gives us the directory containing this script.
PROJECT_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Stage definitions
# ---------------------------------------------------------------------------
# Each stage is a tuple of (name, script_path, description).
# The order here IS the execution order for the full pipeline.
# "script_path" is relative to PROJECT_ROOT.

STAGES = [
    (
        "generate",
        "src/generate_sample_data.py",
        "Generate synthetic login data with attack scenarios",
    ),
    (
        "preprocess",
        "src/preprocess.py",
        "Parse timestamps and extract temporal features",
    ),
    (
        "features",
        "src/feature_engineering.py",
        "Engineer behavioural features for the ML model",
    ),
    (
        "train",
        "src/train_model.py",
        "Train the Isolation Forest anomaly-detection model",
    ),
    (
        "detect",
        "src/detect_anomalies.py",
        "Run anomaly detection and write reports to output/",
    ),
    (
        "alerts",
        "src/alert_manager.py",
        "Run ML + rule engine, store alerts in SQLite and JSON",
    ),
    (
        "evaluate",
        "src/evaluate.py",
        "Evaluate model accuracy against ground-truth labels",
    ),
    (
        "visualize",
        "src/visualize_anomalies.py",
        "Generate the anomalies-by-date bar chart",
    ),
]

# Dashboard is special -- it launches a long-running server rather than
# a batch script, so it's handled separately from the pipeline stages.
DASHBOARD_SCRIPT = "dashboard/manage.py"

# Build a lookup dict so we can find a stage by name quickly.
# e.g. STAGE_MAP["train"] -> ("train", "src/train_model.py", "Train the ...")
STAGE_MAP = {name: (name, path, desc) for name, path, desc in STAGES}

# Valid stage names the user can type on the command line.
VALID_NAMES = [name for name, _, _ in STAGES] + ["dashboard", "all"]


# ---------------------------------------------------------------------------
# Runner helpers
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    """Print a prominent section header to make output easy to scan."""
    width = 60
    print()
    print("=" * width)
    print(f"  {title}")
    print("=" * width)


def run_stage(name: str, script_path: str, description: str) -> bool:
    """Execute a single pipeline stage as a subprocess.

    Each stage is run as a separate Python process so that it behaves
    exactly the same as running it manually (same __name__ == '__main__'
    guard, same working directory, same Python interpreter).

    Args:
        name:        Short name of the stage (e.g. "train").
        script_path: Path to the Python script, relative to PROJECT_ROOT.
        description: Human-readable description for the log output.

    Returns:
        True if the stage succeeded (exit code 0), False otherwise.
    """
    full_path = PROJECT_ROOT / script_path

    # Make sure the script actually exists before trying to run it
    if not full_path.exists():
        print(f"  ERROR: Script not found: {full_path}")
        return False

    print(f"\n  [{name}] {description}")
    print(f"  Running: python {script_path}")
    print("-" * 60)

    # Record the start time so we can report how long each stage took
    start = time.time()

    # subprocess.run executes the script in a child process.
    # - sys.executable ensures we use the same Python interpreter
    #   (important when a virtualenv is active).
    # - cwd=PROJECT_ROOT ensures relative paths inside the scripts
    #   (like "data/raw/login_data.csv") resolve correctly.
    result = subprocess.run(
        [sys.executable, str(full_path)],
        cwd=str(PROJECT_ROOT),
    )

    elapsed = time.time() - start

    if result.returncode == 0:
        print(f"\n  [{name}] Completed in {elapsed:.1f}s")
        return True
    else:
        print(f"\n  [{name}] FAILED (exit code {result.returncode})")
        return False


def run_dashboard() -> None:
    """Launch the Django development server.

    This is an interactive/long-running process, so it runs until the
    user presses Ctrl+C.  It is NOT part of the batch pipeline -- you
    run it separately after the pipeline has finished.
    """
    manage_py = PROJECT_ROOT / DASHBOARD_SCRIPT

    if not manage_py.exists():
        print(f"  ERROR: Dashboard not found: {manage_py}")
        return

    print_header("Launching Django Dashboard")
    print("  URL: http://127.0.0.1:8000")
    print("  Press Ctrl+C to stop the server.\n")

    try:
        # Run the Django dev server. This blocks until Ctrl+C.
        subprocess.run(
            [sys.executable, str(manage_py), "runserver"],
            cwd=str(PROJECT_ROOT),
        )
    except KeyboardInterrupt:
        # Catch Ctrl+C so we exit cleanly instead of printing a traceback
        print("\n  Dashboard stopped.")


def list_stages() -> None:
    """Print a table of all available pipeline stages."""
    print_header("Available Pipeline Stages")
    print(f"\n  {'#':<4} {'Name':<14} Description")
    print(f"  {'-'*4} {'-'*14} {'-'*38}")

    for i, (name, _, desc) in enumerate(STAGES, start=1):
        print(f"  {i:<4} {name:<14} {desc}")

    print(f"\n  {'+':<4} {'dashboard':<14} Launch the Django web dashboard")
    print(f"  {'*':<4} {'all':<14} Run stages 1-{len(STAGES)} in order")
    print()


# ---------------------------------------------------------------------------
# Main pipeline orchestration
# ---------------------------------------------------------------------------

def run_pipeline(stage_names: list[str]) -> None:
    """Run one or more pipeline stages in the given order.

    If "all" is in the list, every stage (1-8) is run sequentially.
    Otherwise, only the explicitly named stages are run, in the order
    they appear in the STAGES list (not the order the user typed them).

    Args:
        stage_names: List of stage names from the command line.
    """
    # If "all" is requested, run every stage in order
    if "all" in stage_names:
        stages_to_run = list(STAGES)
    else:
        # Preserve the canonical pipeline order even if the user typed
        # them in a different order. This prevents issues like running
        # "detect" before "train".
        stages_to_run = [
            (name, path, desc)
            for name, path, desc in STAGES
            if name in stage_names
        ]

    if not stages_to_run:
        print("  No valid stages to run. Use --list to see available stages.")
        return

    total = len(stages_to_run)
    print_header(
        f"Security Log Analyzer Pipeline ({total} stage{'s' if total != 1 else ''})"
    )

    # Track results so we can print a summary at the end
    results: list[tuple[str, bool]] = []
    pipeline_start = time.time()

    for name, path, desc in stages_to_run:
        success = run_stage(name, path, desc)
        results.append((name, success))

        # If a stage fails, stop the pipeline -- later stages depend
        # on the output of earlier ones, so continuing would just
        # produce more errors.
        if not success:
            print(f"\n  Pipeline stopped due to failure in '{name}'.")
            break

    # ---- Print summary ----
    total_time = time.time() - pipeline_start
    print_header("Pipeline Summary")

    for name, success in results:
        status = "OK" if success else "FAILED"
        print(f"  {name:<14} {status}")

    passed = sum(1 for _, s in results if s)
    failed = sum(1 for _, s in results if not s)
    print(f"\n  {passed} passed, {failed} failed, {total_time:.1f}s total")

    if failed == 0:
        print("\n  All stages completed successfully.")
        print("  Run 'python run_pipeline.py dashboard' to view results.")
    print()


# ---------------------------------------------------------------------------
# Argument parsing and entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        A configured ArgumentParser instance.
    """
    parser = argparse.ArgumentParser(
        description="Security Log Analyzer -- Pipeline Runner",
        # Override the default formatter to preserve our usage examples
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  python run_pipeline.py              run the full pipeline\n"
            "  python run_pipeline.py generate      run only data generation\n"
            "  python run_pipeline.py train detect   run training then detection\n"
            "  python run_pipeline.py dashboard     launch the web dashboard\n"
            "  python run_pipeline.py --list        show available stages\n"
        ),
    )

    # --list flag: show stages and exit
    parser.add_argument(
        "--list", "-l",
        action="store_true",
        help="List all available pipeline stages and exit",
    )

    # Positional arguments: zero or more stage names.
    # If none are given, "all" is the default.
    parser.add_argument(
        "stages",
        nargs="*",
        default=["all"],
        metavar="STAGE",
        help=(
            f"Stage(s) to run. Choose from: {', '.join(VALID_NAMES)}. "
            f"Defaults to 'all' if omitted."
        ),
    )

    return parser


def main() -> None:
    """Parse arguments and dispatch to the appropriate action."""
    parser = build_parser()
    args = parser.parse_args()

    # If --list was passed, show stages and exit
    if args.list:
        list_stages()
        return

    # Validate that every stage name the user typed is recognised
    invalid = [s for s in args.stages if s not in VALID_NAMES]
    if invalid:
        print(f"  Unknown stage(s): {', '.join(invalid)}")
        print(f"  Valid stages: {', '.join(VALID_NAMES)}")
        print("  Use --list for details.")
        sys.exit(1)

    # Dashboard is handled separately since it's a long-running server
    if "dashboard" in args.stages:
        run_dashboard()
        return

    # Run the requested pipeline stages
    run_pipeline(args.stages)


if __name__ == "__main__":
    main()
