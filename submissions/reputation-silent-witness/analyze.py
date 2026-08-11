# SPDX-License-Identifier: Apache-2.0
"""Reproduce every table in this submission's README.

Runs the `reputation` task at two values of `task.config.rounds` (5 and 20)
across 12 seeds, and reports three things per trace:

  * ``scoring``  -- the built-in ``reputation_scoring`` validator verdict
  * ``warned``   -- how many of the 4 malicious agents the observer actually
                    broadcast a ``warning:`` about (the outcome we care about)
  * ``silent``   -- cheat messages whose only witness was another malicious
                    agent, and which therefore can never be reported

Usage::

    pip install "nest-core[plugins]"
    python analyze.py
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import tempfile
from typing import NamedTuple

from nest_core.validators import validate_trace

SEEDS = [42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]
BASELINE_ROUNDS = 5
CHANGED_ROUNDS = 20


class RunResult(NamedTuple):
    """The three measures pulled off one trace.

    Example::

        result = run(tmpl, 20, 42, workdir)
    """

    cheats: int
    silent: int
    warned: int
    scoring: bool

    @property
    def verdict(self) -> str:
        """Return the validator verdict as a printable string."""
        return "PASS" if self.scoring else "FAIL"


def load_template() -> str:
    """Return the built-in `reputation` scenario YAML as text.

    Example::

        tmpl = load_template()
    """
    out = subprocess.run(
        ["nest", "scenarios", "show", "reputation"],
        capture_output=True,
        text=True,
        check=True,
    )
    return out.stdout


def run(tmpl: str, rounds: int, seed: int, workdir: pathlib.Path) -> RunResult:
    """Run one (rounds, seed) config and measure detection on its trace.

    Example::

        result = run(load_template(), 20, 42, pathlib.Path("/tmp/x"))
    """
    trace = workdir / f"s{seed}_r{rounds}.jsonl"
    yaml_text = (
        tmpl.replace("rounds: 5", f"rounds: {rounds}")
        .replace("seed: 42", f"seed: {seed}")
        .replace("./traces/reputation.jsonl", str(trace))
    )
    scenario = workdir / f"s{seed}_r{rounds}.yaml"
    scenario.write_text(yaml_text)
    subprocess.run(["nest", "run", str(scenario)], capture_output=True, check=True)

    cheats = 0
    silent = 0
    warned: set[str] = set()
    for line in trace.read_text().splitlines():
        ev: dict[str, object] = json.loads(line)
        if ev.get("kind") not in ("send", "broadcast"):
            continue
        msg = str(ev.get("msg", ""))
        if msg.startswith("cheat:"):
            cheats += 1
            # A cheat delivered to another malicious agent is never reported:
            # MaliciousAgent.on_message has no `report:` branch.
            if str(ev.get("to", "")).startswith("malicious"):
                silent += 1
        elif msg.startswith("warning:"):
            warned.add(msg.split(":")[2])

    results = {r.name: r for r in validate_trace(trace, "reputation")}
    return RunResult(
        cheats=cheats,
        silent=silent,
        warned=len(warned),
        scoring=results["reputation_scoring"].passed,
    )


def main() -> None:
    """Print the before/after comparison table.

    Example::

        main()
    """
    tmpl = load_template()
    with tempfile.TemporaryDirectory() as td:
        workdir = pathlib.Path(td)
        print(f"{'seed':>5} | {'r=5 warned':>10} {'valid':>6} | {'r=20 warned':>11} {'valid':>6}")

        base: list[RunResult] = []
        changed: list[RunResult] = []
        for seed in SEEDS:
            a = run(tmpl, BASELINE_ROUNDS, seed, workdir)
            b = run(tmpl, CHANGED_ROUNDS, seed, workdir)
            base.append(a)
            changed.append(b)
            print(f"{seed:>5} | {a.warned:>8}/4 {a.verdict:>6} | {b.warned:>9}/4 {b.verdict:>6}")

        total = 4 * len(SEEDS)
        w_base = sum(r.warned for r in base)
        w_changed = sum(r.warned for r in changed)
        s_base, c_base = sum(r.silent for r in base), sum(r.cheats for r in base)
        s_changed, c_changed = sum(r.silent for r in changed), sum(r.cheats for r in changed)

        print(
            f"\ncheaters warned: {w_base}/{total} at rounds={BASELINE_ROUNDS} "
            f"-> {w_changed}/{total} at rounds={CHANGED_ROUNDS}"
        )
        print(
            f"silent cheats:   {s_base}/{c_base} ({100 * s_base / c_base:.1f}%) "
            f"at rounds={BASELINE_ROUNDS} -> {s_changed}/{c_changed} "
            f"({100 * s_changed / c_changed:.1f}%) at rounds={CHANGED_ROUNDS}"
        )


if __name__ == "__main__":
    main()
