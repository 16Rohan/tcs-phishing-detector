"""Demo: display-name spoofing — the friendly "From" name claims "Apple
Support" while the actual sending domain is an unrelated bulk-mailer domain.
Shows the sender_analyzer's display-name-vs-domain mismatch detection."""
from demo.common import print_banner, run_scenario
from demo.emails import display_name_brand_impersonation

if __name__ == "__main__":
    print_banner("DEMO 7 — Display-name brand impersonation")
    raw = display_name_brand_impersonation()
    run_scenario("[DEMO] Your Apple ID has been locked for security reasons", raw)
