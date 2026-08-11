# Reputation: the silent-witness blind spot

**Scenario run:** `reputation`
**Setting changed:** `task.config.rounds`, `5` to `20`. That is the only behavioural change; seed, agent counts and roles, all 12 layers, failures, duration and metrics are untouched.
**Files:** [`reputation_rounds20.yaml`](reputation_rounds20.yaml) (the scenario), [`analyze.py`](analyze.py) (reproduces every number below)

```bash
pip install "nest-core[plugins]"
nest run reputation                                   # baseline
nest run submissions/reputation-silent-witness/reputation_rounds20.yaml
python submissions/reputation-silent-witness/analyze.py
```

---

## Part A: running the baseline

`nest run reputation` on the shipped defaults, then the validators from the quickstart:

```
FAIL reputation_scoring   - cheaters not reported: {'malicious-3'}
PASS reputation_warnings  - 3 warnings issued, 3 needed
```

A built-in scenario failing its own validator out of the box seemed like the
most interesting thing in the run, so I started there rather than moving on.

Grepping the trace for who cheated and who received each cheat:

| cheater | who its `cheat:` messages went to |
|---|---|
| malicious-0 | honest-15, honest-11, **malicious-2**, honest-0 |
| malicious-1 | **malicious-0**, honest-9, honest-15 ×2, honest-6 |
| malicious-2 | honest-11, honest-8, honest-3 |
| malicious-3 | **malicious-1** |

malicious-3 cheated exactly once in 5 rounds, and its victim was malicious-1.
Reading [`reputation.py`](../../packages/nest-core/nest_core/scenarios_builtin/reputation.py):
`HonestAgent.on_message` has a `cheat:` branch that sends `report:...:bad` to the
observer. `MaliciousAgent.on_message` has no such branch, it just advances its
round counter. So **a cheat whose only witness is another cheater is structurally
invisible**. Nothing detected malicious-3 because nobody who could report was
looking.

## Part B: the experiment

**Setting:** `task.config.rounds: 5 -> 20`.

**Why this one:** the failure looked like a sampling problem rather than a broken
detector. Each of the 20 traders picks a random peer per round, so 4/20 = 20% of
any cheat's witnesses are fellow cheaters. Over 5 rounds a cheater makes roughly
3 trades; the chance every one lands on a silent witness is small but not
negligible, and it is exactly what happened to malicious-3. `rounds` is the one
knob that raises the number of independent draws without touching the population
mix, the threshold, or the RNG's job.

**Hypothesis:** at 20 rounds every cheater cheats at an honest agent at least
once, so `reputation_scoring` passes. But the blind spot itself is a property of
the population mix rather than of trade volume, so the *fraction* of silent
cheats should stay flat near 20%. More rounds should hide the bug, not fix it.

**Result (12 seeds, `analyze.py`):**

| seed | r=5 warned | validator | r=20 warned | validator |
|---:|---:|:--|---:|:--|
| 42 | 3/4 | **FAIL** | 4/4 | PASS |
| 1 | **0/4** | PASS | 2/4 | PASS |
| 2 | 2/4 | PASS | 3/4 | PASS |
| 3 | 2/4 | PASS | 3/4 | PASS |
| 4 | 3/4 | **FAIL** | 4/4 | PASS |
| 5 | 3/4 | PASS | 4/4 | PASS |
| 6 | 2/4 | PASS | 4/4 | PASS |
| 7 | 2/4 | PASS | 3/4 | PASS |
| 8 | 2/4 | PASS | 4/4 | PASS |
| 9 | 3/4 | PASS | 4/4 | PASS |
| 10 | 2/4 | PASS | 4/4 | PASS |
| 11 | 3/4 | PASS | 4/4 | PASS |

- **Validator:** `reputation_scoring` flips FAIL to PASS on both seeds that failed. Hypothesis confirmed
- **Actual detection:** cheaters the observer broadcast a `warning:` about went from **27/48 to 43/48** (56% to 90%)
- **Blind spot:** silent cheats went **15/133 (11.3%) to 72/494 (14.6%)**. Slightly worse as a fraction, and 4× larger in absolute terms. Confirmed masked rather than fixed

Sweeping `rounds` further on seed 42 shows the same thing. The silent share sits
near its 20% structural floor no matter how long you run:

| rounds | cheats | silent | silent % | warned | scoring |
|---:|---:|---:|---:|---:|:--|
| 5 | 13 | 3 | 23.1% | 3/4 | FAIL |
| 10 | 24 | 4 | 16.7% | 3/4 | PASS |
| 20 | 47 | 8 | 17.0% | 4/4 | PASS |
| 50 | 106 | 14 | 13.2% | 4/4 | PASS |
| 100 | 213 | 33 | 15.5% | 4/4 | PASS |

## Part C: what surprised me

**The baseline FAIL was close to a coin flip.** Before trusting it I re-ran the
*unchanged* scenario on 12 seeds. It fails on only 2 of 12 (seeds 42 and 4). So
the shipped `seed: 42` is not exposing a stable defect; it happens to be one of
the roughly 17% of seeds where a cheater's whole cheating career lands on silent
witnesses. I nearly wrote this up as "the reputation scenario is broken", and the
seed control is the only reason I did not.

**The validator and the outcome disagree.** This is the part I did not expect. At
seed 1, `reputation_scoring` **passes with 0 of 4 cheaters warned**. Reading
[`validators.py:840-892`](../../packages/nest-core/nest_core/validators.py), the
check is `unreported = agents_who_sent_cheat - agents_who_got_a_bad_report`. It
only asks whether *at least one* bad report exists per cheater. It never checks
the observer's score threshold, and never checks that a `warning:` was
broadcast. Volume clears that bar trivially, which is why my change turned it
green. Counting warnings instead of trusting the validator is what showed the
change was a real 56% to 90% improvement rather than just a validator flip. This
matches the repo's own caveat that validators are "regression signals, not formal
proofs". I now read a green validator as "nothing obviously regressed", not "the
protocol works".

**What I checked, in order:** grepped the trace for `cheat:` senders vs `report:`
subjects, found the recipient pattern, read `reputation.py` to confirm
`MaliciousAgent` has no report branch, swept `rounds`, added the 12-seed control
to test whether the baseline failure was even real, then added a
warnings-issued metric when the validator stopped tracking what I cared about.

**The honest limit of this experiment:** `rounds` reshapes the entire RNG stream,
so r=5 and r=20 are not "the same trades plus more trades". That is why every
claim above is over 12 seeds rather than a single before/after diff.

## What I would build next

A `witness_quorum` trust plugin. The blind spot exists because a single
counterparty is the only witness to a trade, and that counterparty may be
adversarial. Requiring *k* independent attestations per trade outcome before it
moves a reputation score would close it, and the same scenario would then be a
direct A/B of `score_average` vs `witness_quorum` under a rising malicious
fraction.

## Tools and help

Claude Code (Opus 5) as a pair programmer: it cloned the repo, ran `nest doctor`,
`nest run` and the validators, and wrote the trace-parsing and sweep scripts I
specified. The seed control and the warnings-issued metric came out of pushing
back on the first result, since the initial single-seed FAIL looked like a
finding and was not. Also used: NANDA Town's `docs/quickstart.md` and
`docs/writing-a-scenario.md`, and the `nest-core` source for `reputation.py` and
`validators.py`. No other human help.
