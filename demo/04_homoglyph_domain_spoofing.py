"""Demo: Unicode/homoglyph domain spoofing — the sender domain visually mimics
"microsoft.com" using a confusable Cyrillic character. Shows the unicode
analyzer flagging brand impersonation even though the domain isn't in any LUT."""
from demo.common import print_banner, run_scenario
from demo.emails import homoglyph_domain_spoofing

if __name__ == "__main__":
    print_banner("DEMO 4 — Homoglyph / Unicode domain spoofing")
    raw = homoglyph_domain_spoofing()
    run_scenario("[DEMO] Security alert for your Microsoft account", raw)
