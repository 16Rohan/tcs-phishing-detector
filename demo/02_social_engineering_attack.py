"""Demo: social engineering — urgency, fear of account suspension, authority
impersonation, and an implicit credential request, with no malicious URL at all.
Shows the content_analyzer's social-engineering scoring in isolation."""
from demo.common import print_banner, run_scenario
from demo.emails import social_engineering_urgency

if __name__ == "__main__":
    print_banner("DEMO 2 — Social engineering (urgency + fear + credential request)")
    raw = social_engineering_urgency()
    run_scenario("[DEMO] URGENT: Your account will be suspended within 24 hours", raw)
