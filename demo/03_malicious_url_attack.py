"""Demo: known-malicious URL — the embedded link's domain is already present in
the local threat-intel lookup table (and would also match Google Safe Browsing
for a real-world malicious URL). Shows the deterministic-override path in the
risk engine driving an instant CRITICAL PHISHING verdict."""
from demo.common import print_banner, run_scenario
from demo.emails import malicious_url_threat_intel

if __name__ == "__main__":
    print_banner("DEMO 3 — Known-malicious URL (threat intelligence match)")
    raw = malicious_url_threat_intel()
    run_scenario("[DEMO] Delivery Failed - Action Required", raw)
