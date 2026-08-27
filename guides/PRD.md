# Product Requirements Document

## Project: Phishing Email Detection, Social Engineering Analysis & Automated Response

## Version: Hackathon Prototype v1.0

---

# 1. Product Overview

Build a locally runnable phishing-email detection system that intercepts simulated incoming emails through Mailpit, performs progressively deeper analysis, identifies phishing/social-engineering indicators, checks embedded links against known threat intelligence, explains the detection using an NVIDIA NIM LLM, and presents the result through a simulated end-user security notification.

The system will operate as a state machine:

```text
                    EMAIL RECEIVED
                          |
                          v
                 +------------------+
                 | STATIC SCREENING  |
                 +--------+---------+
                          |
                 suspicious / flagged?
                    /             \
                  YES              NO
                   |                |
                   v                v
               FLAGGED          CONTINUE
                   |
                   v
                 ALERT

              If not conclusively
              flagged by static layer
                          |
                          v
                 +------------------+
                 | DYNAMIC SCREENING|
                 +--------+---------+
                          |
                          v
                 URL / WEB ANALYSIS
                          |
                          v
                  ML / PHISH BYTE
                          |
                          v
                SOCIAL ENGINEERING
                    CONFIDENCE
                          |
                          v
                 NVIDIA NIM LLM
                          |
                          v
                    EXPLANATION
                          |
                          v
                 FINAL RISK VERDICT
                          |
                          v
                    ALERT / LOG
                          |
                          v
                 POST-DETECTION
                     ROUTINE
```

The prototype is intended to demonstrate **defense-in-depth at the email/application layer**.

It is not intended to simulate the physical, data-link, network, or transport layers.

---

# 2. Problem Statement

Phishing emails increasingly combine:

* Sender impersonation
* Domain spoofing
* Unicode/homoglyph attacks
* Malicious URLs
* URL redirects
* Credential-harvesting pages
* Social engineering
* Urgency and fear
* Requests for sensitive information
* Brand impersonation

A detector that only classifies email text is insufficient.

The proposed system therefore combines:

1. Rule-based static screening
2. URL threat-intelligence lookup
3. Unicode/domain analysis
4. Dynamic URL analysis
5. Pre-trained phishing detection
6. Social-engineering confidence scoring
7. LLM-generated explanation
8. Post-detection notification and persistence

---

# 3. Goals

## Primary Goals

The prototype MUST:

* Receive simulated emails through Mailpit.
* Automatically intercept incoming emails.
* Parse the complete email.
* Extract sender, headers, body, HTML, URLs and attachments.
* Perform static screening.
* Detect suspicious domains and Unicode/homoglyph tricks.
* Check URLs against Google Safe Browsing.
* Maintain a local threat/intelligence lookup table.
* Dynamically inspect suspicious URLs.
* Parse returned HTML safely.
* Detect obvious credential-harvesting indicators.
* Use the specified Phish_Byte pretrained model for phishing confidence.
* Use NVIDIA NIM to generate a human-readable explanation.
* Produce a final phishing confidence/risk score.
* Display a simulated end-user security notification.
* Persist the detection and indicators locally.
* Maintain enough information to support future organization-wide response.

## Secondary Goals

The prototype SHOULD:

* Avoid repeated API calls for known URLs.
* Explain exactly which signals contributed to the verdict.
* Continue working when external APIs are temporarily unavailable.
* Be completely runnable locally.
* Keep all API credentials in `.env`.
* Avoid LangChain and unnecessary orchestration frameworks.

---

# 4. Non-Goals

The 3-hour prototype will NOT attempt to implement:

* Physical-layer monitoring
* Data-link monitoring
* Network intrusion detection
* Transport-layer packet inspection
* Full enterprise mail-server deployment
* Microsoft 365 integration
* Google Workspace integration
* Real account disabling
* Malware execution
* JavaScript execution inside suspicious websites
* Browser automation
* Full malware sandboxing
* Autonomous password resets
* Production SOAR integration
* Model training from scratch
* CNN training from scratch
* Custom LLM fine-tuning

These can be future extensions.

---

# 5. Core Architecture

```text
                       +--------------------+
                       |  PHISHING SIMULATOR|
                       +---------+----------+
                                 |
                                SMTP
                                 |
                                 v
                       +--------------------+
                       |      MAILPIT       |
                       | SMTP : 1025        |
                       | UI   : 8025        |
                       +---------+----------+
                                 |
                           EMAIL RECEIVED
                                 |
                                 v
                       +--------------------+
                       | EMAIL INTERCEPTOR  |
                       +---------+----------+
                                 |
                                 v
                       +--------------------+
                       | EMAIL PARSER       |
                       +---------+----------+
                                 |
                                 v
                       +--------------------+
                       | STATIC SCREENING   |
                       +---------+----------+
                                 |
              +------------------+------------------+
              |                  |                  |
              v                  v                  v
         Sender/Header         URLs             Content
              |                  |                  |
              +------------------+------------------+
                                 |
                                 v
                       +--------------------+
                       | STATIC DECISION    |
                       +---------+----------+
                                 |
                    +------------+------------+
                    |                         |
                  FLAG                     PASS/UNCERTAIN
                    |                         |
                    v                         v
                 ALERT              +--------------------+
                                    | DYNAMIC SCREENING  |
                                    +---------+----------+
                                              |
                         +--------------------+-------------------+
                         |                    |                  |
                         v                    v                  v
                  Safe Browsing        URL Resolution      HTML Parsing
                         |                    |                  |
                         +--------------------+------------------+
                                              |
                                              v
                                   +--------------------+
                                   | PHISH_BYTE MODEL   |
                                   +---------+----------+
                                             |
                                      Confidence Score
                                             |
                                             v
                                   +--------------------+
                                   | SOCIAL ENGINEERING |
                                   | ANALYSIS           |
                                   +---------+----------+
                                             |
                                             v
                                   +--------------------+
                                   | NVIDIA NIM         |
                                   | EXPLANATION        |
                                   +---------+----------+
                                             |
                                             v
                                   +--------------------+
                                   | FINAL RISK ENGINE  |
                                   +---------+----------+
                                             |
                              +--------------+--------------+
                              |                             |
                         LEGITIMATE                      PHISHING
                              |                             |
                              v                             v
                         DELIVER                        QUARANTINE/
                                                        ALERT
                                                              |
                                                              v
                                                     POST-DETECTION
```

---

# 6. Technology Stack

## Email simulation

Use Mailpit as the local SMTP testing server.

The application sends test messages through SMTP into Mailpit.

Mailpit provides the controlled environment in which the prototype simulates organizational email reception.

---

## Programming language

Python 3.x.

---

## Web application

Use the existing lightweight Python web stack from the project.

Do not introduce a large framework solely for this feature.

---

## ML phishing detector

Use:

`https://github.com/AnonymousSingh-007/Phish_Byte`

The project MUST use the repository's pretrained model rather than implementing a new CNN or training a model during the hackathon.

The repository provides:

```python
from phishbyte import PhishByteEngine

engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")

verdict = engine.analyze(raw_email_string)
```

The agent MUST verify the current repository API during implementation rather than assuming function names if the upstream version has changed. The repository documents a pretrained local inference flow and a confidence-based verdict.

---

## LLM

Use NVIDIA NIM.

Environment variables:

```text
NVIDIA_API_KEY=
```

Base URL:

```text
https://integrate.api.nvidia.com/v1
```

Endpoint:

```text
POST /chat/completions
```

The NVIDIA NIM API supports OpenAI-compatible chat-completion requests.

The implementation MUST use direct HTTP requests.

Do NOT use:

* LangChain
* LangGraph
* LlamaIndex
* Agent frameworks
* unnecessary abstractions

Use Python `requests` or an equivalent minimal HTTP client.

---

## Google Safe Browsing

Environment variable:

```text
GOOGLE_API_KEY=
```

The detector will query the Safe Browsing `threatMatches:find` endpoint for URLs requiring external reputation checking. Google documents the endpoint as a POST request against the Safe Browsing threat lists.

---

## Database

Use SQLite.

Database:

```text
data/phishing_detector.db
```

No external database server is required.

---

# 7. Environment Configuration

Create:

```text
.env
```

Example:

```text
GOOGLE_API_KEY=your_google_key
NVIDIA_API_KEY=your_nvidia_key

NVIDIA_BASE_URL=https://integrate.api.nvidia.com/v1

MAILPIT_HOST=localhost
MAILPIT_SMTP_PORT=1025
MAILPIT_UI_PORT=8025

PHISHING_THRESHOLD=70
CRITICAL_THRESHOLD=90
```

`.env` MUST be included in `.gitignore`.

API keys MUST NEVER be committed to Git.

---

# 8. State Machine

The application MUST implement explicit processing states.

```text
RECEIVED
    |
    v
PARSED
    |
    v
STATIC_ANALYSIS
    |
    +---- HIGH CONFIDENCE PHISHING ----> FLAGGED
    |
    v
DYNAMIC_ANALYSIS
    |
    v
ML_ANALYSIS
    |
    v
SOCIAL_ENGINEERING_ANALYSIS
    |
    v
LLM_EXPLANATION
    |
    v
FINAL_VERDICT
    |
    +---- LEGITIMATE ----------> DELIVERED
    |
    +---- SUSPICIOUS ----------> WARNING
    |
    +---- PHISHING ------------> QUARANTINED
                                      |
                                      v
                               POST_DETECTION
```

Every state SHOULD produce structured logs.

---

# 9. Static Screening

Static screening must occur without making requests to the suspicious website.

## 9.1 Sender analysis

Extract:

* From
* Reply-To
* Return-Path
* Display name
* Sender domain

Check:

* From/Reply-To mismatch
* Display-name spoofing
* Domain mismatch
* Suspicious domain structure
* Known legitimate domain
* Known suspicious domain

---

# 10. Domain Lookup Table

Maintain a local domain lookup table.

Minimum structure:

```text
domains
--------------------------------
domain
classification
source
reason
created_at
```

Possible classifications:

```text
TRUSTED
SUSPICIOUS
MALICIOUS
UNKNOWN
```

The LUT must support:

```text
domain → verdict
```

without requiring an external API call.

---

# 11. Unicode / Homoglyph Detection

The detector MUST inspect domains for suspicious Unicode characters.

Examples include:

* Cyrillic characters resembling Latin characters
* Mixed scripts
* Punycode
* Visually deceptive domain names

Example:

```text
microsoft.com
```

versus a visually similar domain containing non-Latin characters.

The system should report:

```text
Unicode / homoglyph anomaly detected
```

rather than simply calling every Unicode domain malicious.

This is an indicator, not an automatic verdict.

---

# 12. URL Extraction

Extract URLs from:

* Plain-text body
* HTML `<a href>`
* Images containing links
* HTML references
* Embedded links

For each URL record:

```text
original_url
normalized_url
domain
scheme
anchor_text
source
```

---

# 13. URL Static Analysis

Check:

* HTTP vs HTTPS
* IP-based URLs
* URL shorteners
* Excessive subdomains
* Excessive hyphens
* Suspicious TLDs
* Long URLs
* Suspicious keywords
* Login-related paths
* Credential-related paths
* Unicode/homoglyphs
* Punycode
* Anchor-text mismatch
* Domain mismatch with sender
* Known malicious LUT entries

---

# 14. Google Safe Browsing Check

For URLs that require external reputation checking:

```text
URL
 |
 v
Local LUT
 |
 +---- KNOWN MALICIOUS ---> FLAG
 |
 +---- KNOWN SAFE --------> CONTINUE
 |
 +---- UNKNOWN
        |
        v
Google Safe Browsing
        |
        +---- MATCH ------> FLAG
        |
        +---- NO MATCH ---> CONTINUE
```

The result must be cached in the local database.

Do not repeatedly query the same URL unnecessarily.

---

# 15. Static Screening Decision

The static analyzer must produce structured output.

Example:

```json
{
  "status": "suspicious",
  "risk_score": 62,
  "signals": [
    "reply_to_mismatch",
    "suspicious_domain",
    "homoglyph_detected"
  ]
}
```

Static screening SHOULD immediately flag an email when there is sufficiently strong evidence such as:

* Known malicious URL
* Known malicious domain
* Extremely strong sender impersonation
* High-confidence threat-intelligence match

Otherwise it proceeds to dynamic screening.

---

# 16. Dynamic Screening

Dynamic screening is limited to controlled HTTP inspection.

The application MUST NOT execute JavaScript.

For a suspicious URL:

```text
URL
 |
 v
Validate scheme
 |
 v
HTTP GET
 |
 +-- timeout
 +-- redirect limit
 +-- response size limit
 +-- safe headers
 |
 v
HTML
 |
 v
BeautifulSoup
 |
 +-- forms
 +-- password fields
 +-- login fields
 +-- links
 +-- suspicious text
 +-- external domains
 +-- redirect indicators
```

Recommended safeguards:

* HTTPS preferred
* Request timeout
* Maximum redirect count
* Maximum response size
* No JavaScript execution
* No browser automation
* Do not download arbitrary executable content
* Do not submit forms
* Do not send credentials
* Do not interact with authentication systems

---

# 17. Dynamic HTML Indicators

Look for:

### Credential harvesting

* `<input type="password">`
* username fields
* login forms
* authentication forms

### Suspicious forms

* Form action points to unrelated domain
* Form action points to raw IP
* Form action uses suspicious domain

### Domain mismatch

```text
Email claims:
Microsoft

Page/domain:
random-example.xyz
```

### Additional links

Inspect extracted links for:

* domain mismatch
* suspicious redirects
* suspicious external domains

---

# 18. Phish_Byte ML Analysis

After static/dynamic evidence has been collected, run the email through the pretrained Phish_Byte engine.

Input:

```text
raw_email
```

Output MUST be normalized internally to:

```json
{
  "label": "phishing",
  "confidence": 0.91
}
```

The implementation must adapt the actual upstream response object if the repository exposes a different structure.

The model is an additional signal.

It MUST NOT blindly override deterministic threat-intelligence findings.

The repository documents its use of multiple independent signals and a calibrated phishing confidence output.

---

# 19. Social Engineering Detection

The prototype does not need to classify the exact social-engineering category.

The requirement is simply:

> Determine how strongly the email exhibits social-engineering characteristics.

Potential signals:

* Urgency
* Fear
* Threat of account suspension
* Authority impersonation
* Financial pressure
* Request for credentials
* Request for personal information
* Request for immediate action
* Suspicious reward/prize claims
* Emotional manipulation
* Artificial deadline

Output:

```json
{
  "social_engineering_confidence": 0.87
}
```

The system does not need to produce a detailed taxonomy.

---

# 20. NVIDIA NIM Explanation

NVIDIA NIM is used primarily for **explanation**, not as the sole phishing detector.

The system sends structured evidence to the model.

Example input:

```text
Email:
<sanitized email content>

Static findings:
- Reply-To mismatch
- Suspicious sender domain
- Homoglyph detected

URL findings:
- Google Safe Browsing match
- Login page detected
- Domain mismatch

ML:
Phish_Byte confidence: 91%

Social engineering confidence: 87%
```

The system prompt must be hardcoded.

The model must return a concise explanation suitable for an end-user security alert.

Example:

```text
This email is likely phishing because the sender claims to
represent a trusted organization but uses a mismatched domain.
The embedded URL is associated with a known unsafe resource,
and the linked page contains a credential-login form.
The message also uses urgency to pressure the recipient into
acting immediately.
```

The LLM MUST NOT be responsible for calculating the numerical risk score.

---

# 21. Final Risk Engine

The final score combines deterministic and ML signals.

Recommended initial weighting:

```text
Threat intelligence / Safe Browsing   30%
URL / domain analysis                 20%
Sender / header analysis              15%
Dynamic HTML analysis                 15%
Phish_Byte confidence                 15%
Social engineering confidence          5%
```

The implementation should make these weights configurable.

Important rule:

A confirmed malicious Safe Browsing match or known-malicious LUT entry should be treated as a strong deterministic signal and should not be diluted into a harmless result merely because the ML model disagrees.

---

# 22. Final Classification

```text
0–29
LEGITIMATE

30–69
SUSPICIOUS

70–89
PHISHING

90–100
CRITICAL PHISHING
```

Each result must contain:

```json
{
  "classification": "PHISHING",
  "risk_score": 94,
  "phishbyte_confidence": 0.91,
  "social_engineering_confidence": 0.87,
  "signals": [],
  "explanation": ""
}
```

---

# 23. End-User Notification

The prototype will use a simulated popup/web notification.

It should look like an endpoint security warning.

Example:

```text
+----------------------------------------+
|       PHISHING EMAIL DETECTED          |
|                                        |
| Risk: 94 / 100                         |
| Severity: CRITICAL                     |
|                                        |
| Sender: security@example.com           |
|                                        |
| Why?                                   |
| • Suspicious sender domain             |
| • Malicious URL detected               |
| • Credential form detected             |
| • Social engineering confidence: 87%  |
|                                        |
| [ REPORT PHISHING ]   [ DELETE ]       |
+----------------------------------------+
```

The notification MUST show:

* Risk score
* Classification
* Sender
* Key detection signals
* LLM explanation
* Report action

---

# 24. Post-Detection Routine

When an email is classified as phishing:

```text
PHISHING
   |
   +--> Save incident
   |
   +--> Save URLs
   |
   +--> Save domains
   |
   +--> Save sender
   |
   +--> Save model result
   |
   +--> Save explanation
   |
   +--> Update IOC LUT
   |
   +--> Show user alert
```

The system should treat the malicious URL/domain as a reusable IOC.

Future emails containing the same IOC should be detected quickly through the local lookup table.

---

# 25. Database Schema

SQLite database:

```text
data/phishing_detector.db
```

Minimum tables:

## emails

```text
id
message_id
sender
reply_to
recipient
subject
received_at
raw_email
classification
risk_score
```

## urls

```text
id
email_id
url
domain
verdict
source
risk_score
checked_at
```

## iocs

```text
id
indicator
indicator_type
verdict
source
first_seen
last_seen
```

## incidents

```text
id
email_id
severity
status
created_at
explanation
```

## users

```text
id
email
status
risk_level
```

---

# 26. Organization-Wide Response

For the hackathon, this is simulated.

The system MAY maintain a set of simulated users:

```text
user1@company.test
user2@company.test
user3@company.test
...
```

If an IOC is confirmed:

```text
IOC
 |
 v
Search email records
 |
 v
Find matching recipients
 |
 v
Mark affected users
 |
 v
Display organization alert
```

This demonstrates how the system could later integrate with a real enterprise mail provider.

---

# 27. Account Containment

Account lockdown is simulated.

The system should NOT actually disable external accounts.

Possible simulated actions:

```text
RECEIVED ONLY
    ↓
No account action

USER CLICKED
    ↓
Monitor / MFA warning

CREDENTIAL SUBMISSION DETECTED
    ↓
Account restricted
    ↓
Sessions revoked
    ↓
New device flagged
```

The containment mechanism is a demonstration of what a production integration with an identity provider could perform.

---

# 28. Local Execution Requirement

The complete project MUST run locally.

Required services:

```text
Python application
Mailpit
SQLite
```

External services:

```text
Google Safe Browsing
NVIDIA NIM
```

The system must degrade gracefully when either external API is unavailable.

For example:

```text
Google Safe Browsing unavailable
        ↓
Continue using:
    local LUT
    URL heuristics
    Phish_Byte
    other signals
```

Likewise:

```text
NVIDIA unavailable
        ↓
Detection still works
        ↓
Use fallback static explanation
```

The LLM is an enhancement, not a single point of failure.

---

# 29. Security Requirements

The dynamic crawler MUST be treated as untrusted-network interaction.

It must:

* Never execute returned JavaScript.
* Never submit forms.
* Never send credentials.
* Never download arbitrary executables.
* Limit redirects.
* Limit response size.
* Apply request timeouts.
* Validate URL schemes.
* Avoid localhost/private-network targets where practical.
* Avoid unrestricted access to internal services.

The email itself must be treated as untrusted input.

Do not render raw HTML directly into the application UI without sanitization.

---

# 30. Repository Integration

The implementation agent MUST use:

[AnonymousSingh-007/Phish_Byte](https://github.com/AnonymousSingh-007/Phish_Byte?utm_source=chatgpt.com)

as the ML component.

Do not fork the repository into a separate runtime service unless necessary.

Preferred architecture:

```text
our application
      |
      v
PhishByteEngine
      |
      v
pretrained local model
```

The agent should inspect the repository's current installation instructions and integrate the smallest amount of code necessary.

The repository currently documents local installation with:

```text
python -m venv venv
pip install -r requirements.txt
python verify_install.py
```

and local inference through `PhishByteEngine.from_pretrained(...)`.

---

# 31. Project File Responsibilities

Use the previously established structure:

```text
app/
├── email/
│   ├── mailpit.py
│   ├── interceptor.py
│   └── parser.py
│
├── detection/
│   ├── static_analyzer.py
│   ├── dynamic_analyzer.py
│   ├── sender_analyzer.py
│   ├── url_analyzer.py
│   └── content_analyzer.py
│
├── risk/
│   └── risk_engine.py
│
├── incident/
│   ├── incident_manager.py
│   └── ioc_extractor.py
│
└── containment/
    ├── containment_engine.py
    └── identity_service.py
```

Additional modules MAY be created if genuinely necessary.

Do not create unnecessary abstractions.

---

# 32. `mailpit.py`

Responsibilities:

* Mailpit configuration
* Mailpit API access if needed
* Retrieve received messages
* Mark/process messages appropriately
* Convert Mailpit messages into the application's email-processing pipeline

---

# 33. `interceptor.py`

Responsibilities:

```text
received message
      ↓
parse
      ↓
static analyzer
      ↓
dynamic analyzer
      ↓
ML
      ↓
risk engine
      ↓
alert
```

This should act as the central orchestrator for the email-processing state machine.

---

# 34. `parser.py`

Extract:

* headers
* sender
* reply-to
* recipient
* subject
* text body
* HTML body
* URLs
* attachments

Return a normalized internal email object.

---

# 35. `static_analyzer.py`

Coordinate:

```text
sender_analyzer
url_analyzer
content_analyzer
header analysis
Unicode analysis
LUT lookup
```

Return structured evidence.

---

# 36. `dynamic_analyzer.py`

Coordinate:

```text
Safe Browsing
URL GET
redirect inspection
HTML parsing
form detection
credential-page detection
```

Return structured evidence.

---

# 37. `content_analyzer.py`

Responsibilities:

* urgency detection
* social-engineering indicators
* suspicious request detection
* basic language indicators
* Phish_Byte invocation

Do not implement a second large ML model here unless required by the selected pretrained model.

---

# 38. `url_analyzer.py`

Responsibilities:

* URL extraction
* normalization
* domain extraction
* Unicode/homoglyph detection
* URL heuristics
* LUT lookup
* Safe Browsing integration
* anchor mismatch
* suspicious domain detection

---

# 39. `risk_engine.py`

This is the final decision-maker.

It must:

1. Collect all signals.
2. Apply deterministic overrides.
3. Calculate the risk score.
4. Produce classification.
5. Produce a list of reasons.
6. Return normalized JSON.

The risk engine MUST NOT call the LLM.

---

# 40. `incident_manager.py`

Responsibilities:

* Create incidents
* Store verdicts
* Store evidence
* Update incident status
* Link incidents to emails

---

# 41. `ioc_extractor.py`

Extract:

```text
sender
domain
URLs
IP addresses
attachment hashes where available
```

Store reusable indicators.

---

# 42. `containment_engine.py`

For the hackathon, this is simulated.

Responsibilities:

* Determine containment severity.
* Mark simulated users.
* Flag simulated devices.
* Generate simulated security actions.

---

# 43. `identity_service.py`

Provide a minimal simulated identity system.

Example endpoints:

```text
POST /login
POST /restrict
POST /unrestrict
POST /revoke-session
POST /flag-device
```

This exists solely to demonstrate the impact-prevention concept.

---

# 44. Test Scenarios

The simulator MUST provide at least these scenarios.

## Scenario 1 — Legitimate email

Normal sender, legitimate domain, no suspicious URL.

Expected:

```text
LEGITIMATE
```

---

## Scenario 2 — Social engineering

Example characteristics:

* Urgency
* Account suspension threat
* Immediate verification request
* Credential request

Expected:

```text
High social-engineering confidence
```

---

## Scenario 3 — Malicious URL

Email contains a URL detected by Safe Browsing or the local IOC LUT.

Expected:

```text
PHISHING
```

---

## Scenario 4 — Homoglyph/Unicode attack

Sender/domain visually resembles a legitimate organization using deceptive Unicode characters.

Expected:

```text
Unicode anomaly
+
suspicious domain
```

---

## Scenario 5 — Link mismatch

Visible link claims to point to a trusted organization while the actual href points elsewhere.

Expected:

```text
Link-domain mismatch
```

---

## Scenario 6 — Credential harvesting page

URL resolves to an HTML page containing a login/password form.

Expected:

```text
Dynamic credential-harvesting indicator
```

---

# 45. Failure Handling

The application must not crash if:

* Mailpit is unavailable.
* Safe Browsing API fails.
* NVIDIA NIM fails.
* URL cannot be reached.
* URL times out.
* HTML cannot be parsed.
* Phish_Byte cannot load.
* Email contains malformed MIME.
* Email contains malformed HTML.

Every failure should become a structured signal/log rather than an application crash.

---

# 46. Logging

Use structured application logging.

Each email should have a processing ID.

Example:

```text
EMAIL-000123

RECEIVED
STATIC_ANALYSIS
DYNAMIC_ANALYSIS
ML_ANALYSIS
RISK_CALCULATED
ALERT_GENERATED
INCIDENT_CREATED
```

This will make the live demonstration easier to debug.

---

# 47. Demo Workflow

The final demonstration should follow this sequence.

### Step 1

Open Mailpit.

### Step 2

Use the simulator to send a phishing email to:

```text
krishnaveni@company.test
```

### Step 3

Mailpit receives it.

### Step 4

Interceptor detects the new email.

### Step 5

Static analysis executes.

Display:

```text
Sender analysis
URL analysis
Unicode analysis
LUT
```

### Step 6

If required, dynamic analysis executes.

Display:

```text
Safe Browsing
URL response
Redirects
HTML
Credential form
```

### Step 7

Phish_Byte produces confidence.

Example:

```text
Phishing confidence: 91%
```

### Step 8

NVIDIA NIM generates:

```text
WHY THIS EMAIL IS SUSPICIOUS
```

### Step 9

Risk engine produces:

```text
CRITICAL PHISHING
94/100
```

### Step 10

Simulated endpoint popup appears.

### Step 11

IOC is saved.

### Step 12

Organization-wide affected-user lookup is demonstrated.

### Step 13

Simulated containment is demonstrated.

---

# 48. Definition of Done

The prototype is considered complete when the following complete flow works without manual intervention:

```text
Send phishing email
        ↓
Mailpit receives email
        ↓
Interceptor detects email
        ↓
Static analysis runs
        ↓
Dynamic analysis runs when necessary
        ↓
Google Safe Browsing is queried when necessary
        ↓
Phish_Byte generates confidence
        ↓
Social-engineering confidence is calculated
        ↓
NVIDIA NIM generates explanation
        ↓
Risk engine produces final verdict
        ↓
User notification appears
        ↓
IOC is stored
        ↓
Incident is created
        ↓
Post-detection routine executes
```

The application must remain functional if NVIDIA or Google Safe Browsing is unavailable.

---

# 49. Implementation Priority

The coding agent MUST implement in this order:

## P0 — Critical

* Mailpit integration
* Email parsing
* Static URL/sender analysis
* Phish_Byte integration
* Risk engine
* End-user popup

## P1 — Critical

* Google Safe Browsing
* Unicode/homoglyph detection
* Local IOC/domain LUT
* Dynamic URL analysis
* HTML parsing

## P2 — Important

* NVIDIA NIM explanation
* SQLite persistence
* Incident creation
* IOC extraction

## P3 — Demo enhancement

* Organization-wide notification
* Simulated affected-user lookup
* Simulated identity containment
* Login/device demonstration

If time runs short, P3 features must never delay the P0 end-to-end pipeline.

---

# 50. Development Principles

The implementation agent MUST follow these principles:

1. **Local-first.**
2. **Minimal dependencies.**
3. **No LangChain.**
4. **No unnecessary agent frameworks.**
5. **No model training during the hackathon.**
6. **Use the specified Phish_Byte pretrained model.**
7. **Use direct HTTP requests for NVIDIA NIM.**
8. **Use direct HTTP requests for Google Safe Browsing.**
9. **Keep API keys in `.env`.**
10. **Never commit `.env`.**
11. **Do not execute JavaScript from analyzed websites.**
12. **Do not submit forms to analyzed websites.**
13. **Do not treat one weak heuristic as definitive proof.**
14. **Use deterministic threat-intelligence matches as strong evidence.**
15. **The LLM explains evidence; it does not make the security decision.**
16. **Every major detection decision must be explainable.**
17. **Every external dependency must have a graceful fallback.**
18. **Keep the architecture simple enough to run locally.**

---

# 51. Future Production Architecture

The hackathon implementation should be designed so these components can later be replaced:

```text
Mailpit
   ↓
Enterprise Email Gateway
```

```text
Simulated Identity Service
   ↓
Microsoft Entra / Okta / Google Workspace
```

```text
SQLite IOC DB
   ↓
Enterprise Threat Intelligence Platform
```

```text
Simulated Popup
   ↓
Outlook/Gmail security warning
```

```text
Local URL crawler
   ↓
Isolated sandbox/browser analysis
```

The prototype therefore demonstrates the **architecture and decision flow**, while keeping the implementation realistically small.

---

# 52. Final Product Statement

The completed prototype should be demonstrable as:

> **A locally deployable, defense-in-depth phishing email detection system that intercepts incoming messages, performs rule-based static screening, validates embedded links against threat intelligence, dynamically inspects suspicious destinations, applies a pretrained phishing model for confidence scoring, uses NVIDIA NIM to explain social-engineering indicators, and automatically generates an end-user security alert and persistent incident record.**

The key distinction is:

```text
WE ARE NOT BUILDING:
"an ML model that says phishing."

WE ARE BUILDING:
"an email interception and analysis pipeline
that combines multiple independent signals
and produces an explainable security decision."
```

Look at .env.example for the examples of APIs that we are going to use.
