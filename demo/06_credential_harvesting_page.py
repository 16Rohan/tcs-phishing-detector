"""Demo: link to a page expected to host a live credential-harvesting login
form. Shows the dynamic_analyzer's bounded HTTP fetch + HTML inspection path
(password-field / login-form detection) alongside the static threat-intel hit."""
from demo.common import print_banner, run_scenario
from demo.emails import credential_harvesting_page

if __name__ == "__main__":
    print_banner("DEMO 6 — Credential-harvesting landing page")
    raw = credential_harvesting_page()
    run_scenario("[DEMO] Mailbox storage limit reached - Increase storage now", raw)
