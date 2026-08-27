"""Demo: link/anchor-text mismatch — the visible link text claims paypal.com
while the real href points to an unrelated attacker domain. Shows the
url_analyzer's anchor-text-vs-href mismatch detection."""
from demo.common import print_banner, run_scenario
from demo.emails import link_domain_mismatch

if __name__ == "__main__":
    print_banner("DEMO 5 — Link/anchor-text domain mismatch")
    raw = link_domain_mismatch()
    run_scenario("[DEMO] Your PayPal account statement is ready", raw)
