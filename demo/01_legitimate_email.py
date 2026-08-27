"""Demo: a clean, legitimate email — control case showing the pipeline lets
non-malicious mail through as LEGITIMATE / DELIVERED."""
from demo.common import print_banner, run_scenario
from demo.emails import legitimate_baseline

if __name__ == "__main__":
    print_banner("DEMO 1 — Legitimate email (control case)")
    raw = legitimate_baseline()
    run_scenario("[DEMO] Your monthly Microsoft 365 usage summary", raw)
