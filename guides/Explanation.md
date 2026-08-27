# Component Explanation

This document explains what every folder/file under `app/` does, in the order
data actually flows through the pipeline: an email arrives, gets parsed,
statically screened, dynamically screened, scored by ML, scored for social
engineering, given a final risk verdict, explained by an LLM, and finally
turned into an incident + simulated user-facing alert.

For the full requirements this implements, see `guides/PRD.md`.

---

## `app/config.py`

Single source of truth for configuration. Loads `.env` (via `python-dotenv`)
and exposes a `config` object used everywhere else: API keys, Mailpit
connection details, risk thresholds (`SUSPICIOUS_THRESHOLD`,
`PHISHING_THRESHOLD`, `CRITICAL_THRESHOLD`), the risk-engine signal weights,
HTTP safety limits for dynamic analysis (timeout, redirect cap, max response
size), and the list of simulated organization users. Nothing else in the app
reads `os.environ` directly.

## `app/db.py`

The entire persistence layer, using plain `sqlite3` (no ORM). Creates
`data/phishing_detector.db` and defines the schema for `emails`, `urls`,
`domains`, `iocs`, `incidents`, `users`, and a `safe_browsing_cache` table.
Seeds a starter domain lookup table (a few trusted brands, a few "known
malicious" demo domains) and the simulated organization users on first run.
Provides `get_conn()` / `cursor()` helpers used by every other module that
touches the database — nobody opens a raw `sqlite3.connect()` outside this file.

---

## `app/email/` — receiving and understanding a message

This is the front door: turning a raw SMTP message sitting in Mailpit into a
structured object the rest of the pipeline can reason about.

- **`mailpit.py`** — `MailpitClient`, a thin wrapper around Mailpit's HTTP API
  (`/api/v1/messages`, `/api/v1/message/<id>/raw`, mark-as-read). This is the
  only place that talks to Mailpit. If Mailpit isn't reachable, `is_available()`
  returns `False` and the poller simply skips a cycle instead of crashing.

- **`parser.py`** — `parse_email(raw_email) -> ParsedEmail`. Uses Python's
  standard `email` package (`email.message_from_string` with the modern
  `policy.default`, which also handles MIME-encoded headers — e.g. a
  homoglyph-laden display name encoded as `=?utf-8?q?...?=` gets decoded back
  to real Unicode before analysis). Extracts From/Reply-To/Return-Path/To,
  subject, plain-text body, HTML body, attachments, and every URL found in the
  text body, `<a href>`, `<img src>`, and `<link>/<area>/<base>` tags — each
  URL recorded with its domain, scheme, anchor text, and where it was found.
  Never throws on malformed MIME/HTML; parse failures are recorded in
  `parse_errors` and processing continues.

- **`interceptor.py`** — the central orchestrator / state machine
  (`RECEIVED → PARSED → STATIC_ANALYSIS → [DYNAMIC_ANALYSIS] → ML_ANALYSIS →
  SOCIAL_ENGINEERING_ANALYSIS → RISK_CALCULATED → LLM_EXPLANATION →
  FINAL_VERDICT → INCIDENT_CREATED → POST_DETECTION`). Every stage is logged
  with a per-email processing ID (`EMAIL-000123`). `process_raw_email()` runs
  one email through the entire pipeline end to end and is called both by the
  Mailpit poller and by the `/api/process-raw` demo endpoint. A background
  thread (`start_background_poller`) polls Mailpit every
  `POLL_INTERVAL_SECONDS` for unseen messages and feeds them in.

---

## `app/detection/` — is this email/URL/sender suspicious?

All the "no external side effects on the target" analysis lives here — static
signal collection plus the local threat-intelligence tables.

- **`lut.py`** — the local domain/IOC **L**ook**U**p **T**able. Pure-SQLite
  lookups (`lookup_domain`, `lookup_ioc`) and writers (`upsert_domain`,
  `upsert_ioc`) so previously-seen malicious domains/URLs are recognized
  instantly without ever re-querying an external API for something already
  known.

- **`unicode_analyzer.py`** — homoglyph/Unicode/punycode detection for a
  domain. Flags punycode labels (`xn--...`), mixed-script domains (Latin mixed
  with Cyrillic/Greek), and a small table of visually-confusable characters
  (e.g. Cyrillic `о` vs Latin `o`). This is explicitly an **indicator**, not an
  automatic verdict — it returns `anomaly_detected` plus human-readable
  `reasons`, and callers decide how much weight to give it.

- **`sender_analyzer.py`** — From/Reply-To/Return-Path mismatch detection,
  display-name brand-impersonation ("From: Apple Support
  <noreply@some-other-domain.top>"), sender-domain LUT classification, and
  Unicode analysis of the sender's domain. Returns a structured result with a
  signal list and a 0–100 risk contribution.

- **`safe_browsing.py`** — direct HTTP client for Google Safe Browsing's
  `threatMatches:find` endpoint (no SDK). Every result is cached in
  `safe_browsing_cache` so the same URL is never re-queried. If
  `GOOGLE_API_KEY` is missing or the API errors/times out, it degrades to
  `{"checked": False, "source": "unavailable_..."}` rather than throwing.

- **`url_analyzer.py`** — static URL heuristics: HTTP vs HTTPS, IP-literal
  URLs, known shorteners, excessive subdomains/hyphens, suspicious TLDs
  (`.xyz`, `.top`, `.click`, …), long URLs, credential-related paths
  (login/verify/secure/…), anchor-text-vs-href mismatch, sender-vs-link domain
  mismatch, plus the Unicode analyzer and the domain LUT. Only queries Safe
  Browsing when the domain is `UNKNOWN` in the local LUT (LUT hits short-circuit
  the external call entirely, per the "avoid repeated API calls" goal).

- **`static_analyzer.py`** — coordinates `sender_analyzer` + `url_analyzer`
  into one structured verdict (`pass` / `suspicious` / `flagged`). A small set
  of very strong deterministic signals (known-malicious LUT hit, Safe Browsing
  match) combined with a high combined score short-circuits straight to
  `flagged`, skipping dynamic analysis entirely — matching the PRD's "static
  screening should immediately flag when there is sufficiently strong
  evidence" rule.

- **`dynamic_analyzer.py`** — bounded, safe HTTP inspection of URLs the static
  layer marked as needing a closer look. Hard safety rules enforced here:
  scheme validation, a private/loopback/link-local network block (via
  `socket.getaddrinfo` + `ipaddress`), a request timeout, a redirect-count
  limit, and a response-size limit — and it **never** executes JavaScript,
  submits forms, or sends credentials. Uses BeautifulSoup to look for password
  fields, login forms, form actions pointing at a different domain than the
  page itself, and external links. Every failure mode (timeout, unreachable,
  malformed HTML, blocked target) becomes a structured signal instead of an
  exception.

- **`content_analyzer.py`** — two responsibilities:
  1. **Social-engineering scoring** (`analyze_social_engineering`): keyword-family
     detection for urgency, fear/threat, authority impersonation, financial
     pressure, credential requests, reward/prize claims, and artificial
     deadlines (regex), combined into a single `social_engineering_confidence`
     (0–1). This is a signal, not a taxonomy — the PRD explicitly doesn't
     require classifying *which* social-engineering category applies.
  2. **Phish_Byte ML integration** — see the dedicated section below.

---

## `app/risk/risk_engine.py` — the final decision-maker

Takes the four independent signal bundles (static, dynamic, Phish_Byte,
social-engineering) and combines them into one verdict. It is the **only**
place that computes the numerical risk score, and it deliberately **never
calls the LLM** — the LLM only explains a decision this module already made.

- Applies the configured weights from `config.RISK_WEIGHTS` (threat intel 30%,
  URL/domain 20%, sender/header 15%, dynamic HTML 15%, Phish_Byte 15%, social
  engineering 5%).
- Enforces a **deterministic override**: a confirmed Safe Browsing match or a
  known-malicious LUT hit forces the score to at least 95, so a strong
  threat-intel signal can never get diluted into a "safe" result just because
  the ML model or social-engineering score disagrees. Domain/display-name
  brand impersonation (homoglyph spoofing or a spoofed display name) gets a
  similar, slightly softer floor, since it's strong evidence even without an
  external API/LUT hit.
- Maps the final 0–100 score to a classification: `LEGITIMATE` (0–29),
  `SUSPICIOUS` (30–69), `PHISHING` (70–89), `CRITICAL PHISHING` (90–100),
  using the thresholds from `config.py`.
- Returns one normalized JSON object: classification, risk score, Phish_Byte
  confidence, social-engineering confidence, the full signal list, and a
  breakdown of each weighted component (useful for the dashboard/debugging).

## `app/llm/nim_client.py` — explaining the decision, not making it

Direct HTTP calls to NVIDIA NIM's OpenAI-compatible
`POST /chat/completions` endpoint (`requests`, no LangChain/agent framework).
A hardcoded system prompt instructs the model to explain — in plain language
suitable for an end-user alert popup — a verdict and signal list it is *given*,
never to invent its own score. If `NVIDIA_API_KEY` is missing, the request
times out, or the response comes back empty, `generate_explanation()` falls
back to a deterministic templated explanation built directly from the signal
list, so detection is never blocked on the LLM being available.

## `app/incident/` — turning a verdict into a persisted, actionable record

- **`incident_manager.py`** — writes the processed email + verdict to the
  `emails` table, writes each analyzed URL to `urls`, creates a row in
  `incidents` for anything that isn't clean, and can search prior email
  records for other recipients who received mail from/about the same sender
  (`find_affected_users`) — the "organization-wide response" simulation.

- **`ioc_extractor.py`** — for anything classified `PHISHING` or
  `CRITICAL PHISHING`, promotes the sender domain, sender address, and any
  high-risk URLs/domains into the local IOC table (`app/detection/lut.py`), so
  the *next* email carrying the same indicator is caught instantly by the
  static layer without needing to repeat dynamic analysis or an external API
  call.

## `app/containment/` — simulated post-detection response

Nothing here touches a real account or identity provider — it exists purely
to demonstrate what a production integration would do.

- **`identity_service.py`** — an in-memory/SQLite-backed stand-in for an
  identity provider: simulated login/session tracking, `restrict`/`unrestrict`
  a user, `revoke_sessions`, `flag_device`.
- **`containment_engine.py`** — decides which containment "stage" applies
  (`RECEIVED_ONLY` → `USER_CLICKED` → `CREDENTIAL_SUBMISSION_DETECTED`, based
  on the verdict and whether dynamic analysis found a live password field) and
  drives the corresponding simulated identity-service actions for every
  affected user.

## `app/web.py` + `main.py` — the operator/end-user surface

`app/web.py` is a small Flask app (server-rendered Jinja2 templates in
`frontend/`, no SPA framework) exposing:
- `/` — the security dashboard (processed emails, domain/IOC table, simulated
  users),
- `/alert/<email_id>` — the simulated end-user security popup for one email,
- `/login` — the simulated identity-service login demo,
- a small JSON API (`/api/poll-now`, `/api/process-raw`, `/api/recent`,
  `/api/incidents/<id>/report|delete`, `/api/login`) used by the dashboard's
  JS and by the `demo/` scripts.

`main.py` is the single entry point: it starts the background Mailpit poller
thread and then runs the Flask app, so `uv run python main.py` brings up the
whole system.

---

## How Phish_Byte (the ML model) is actually used

Per the PRD, the ML signal comes from the pretrained
[`AnonymousSingh-007/Phish_Byte`](https://github.com/AnonymousSingh-007/Phish_Byte)
model — no training or fine-tuning happens in this project. All of this lives
in `app/detection/content_analyzer.py`:

1. **Lazy load, once.** `_load_phishbyte_engine()` tries
   `from phishbyte import PhishByteEngine` and
   `PhishByteEngine.from_pretrained("SamSec007/phishbyte")` exactly once per
   process (`_phishbyte_load_attempted` guards against retrying on every
   email). The loaded engine is cached in `_phishbyte_engine` and reused.

2. **Inference.** `run_phishbyte_analysis(raw_email)` calls
   `engine.analyze(raw_email)` with the *entire raw RFC822 email string* — the
   same input contract the PRD specifies (`engine.analyze(raw_email_string)`).

3. **Output normalization.** `_normalize_phishbyte_output()` adapts whatever
   shape the installed version of the repo actually returns — dict-like
   (`label`/`verdict`/`classification`, `confidence`/`score`/`probability`) or
   object-like (attribute access) — into one fixed internal shape:
   `{"label": "phishing"|"legitimate", "confidence": 0.0–1.0}`. It also
   normalizes a 0–100 confidence into 0–1 if the upstream model returns a
   percentage instead of a fraction. This is the adapter layer the PRD calls
   for ("the implementation must adapt the actual upstream response object if
   the repository exposes a different structure").

4. **Graceful fallback — this is the important part for this environment.**
   `Phish_Byte` is a GitHub project, **not published on PyPI**, so it is not a
   normal dependency of this project (see the comment in `pyproject.toml`).
   If the import fails (module not installed) *or* `engine.analyze()` raises
   at runtime, `run_phishbyte_analysis()` transparently falls back to
   `_heuristic_phishbyte_fallback()`: a small deterministic scorer that counts
   hits from the same urgency/fear/credential-request/reward keyword families
   used by the social-engineering analyzer, plus IP-literal-URL and
   password-field hints in the raw text, and derives a `label`/`confidence`
   pair with the exact same shape the real model would return. The result
   always carries an `engine` field (`"phishbyte_pretrained"`,
   `"heuristic_fallback"`, or `"heuristic_fallback_runtime_error"`) so it's
   always visible in logs/UI which one actually produced a given confidence
   score.

5. **How it's weighted, not decided.** `run_phishbyte_analysis()`'s output
   feeds into `risk_engine.compute_final_verdict()` as one of six weighted
   inputs (15% weight — see `config.RISK_WEIGHTS`). Per PRD section 18, it is
   explicitly **not allowed to override deterministic threat-intelligence
   findings** — a known-malicious LUT/Safe Browsing hit forces the score to
   ≥95 regardless of what Phish_Byte (or its fallback) says, and conversely a
   high Phish_Byte confidence alone (with no other findings) cannot exceed
   what its 15% weight allows.

To actually enable the real pretrained model instead of the heuristic
fallback: clone `Phish_Byte` and follow its own install steps
(`python -m venv venv && pip install -r requirements.txt && python
verify_install.py`) inside this project's environment. No code changes are
needed — `content_analyzer.py` will pick it up automatically the next time the
app starts.
