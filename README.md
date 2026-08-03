# Credential Harvesting Attempt — Direct Email-Based Solicitation (No Landing Page)

## Summary

A threat actor posing as a recruiter ("HR Connect") made contact with the target over email and, in a follow-up message, directly requested the target's email and password in plaintext, under the pretext of "reviewing the profile and preparing recommended adjustments."

No malicious link, attachment, or spoofed domain was involved. The attack relied entirely on **social engineering via a plausible pretext + urgency language**, sent from a legitimately-authenticated (not spoofed) free webmail account. This is a scoped, verified writeup — claims below are limited to what the evidence supports.

**Scope note:** There is no landing page, phishing link, or malware in this incident. This is a direct in-body credential solicitation attempt only.

---

## Technical Analysis

### Email Authentication (Header Analysis)

| Field | Value |
|---|---|
| From | `hr.connect2026[at]zohomail[.]com` |
| Return-Path | Matches From domain (legitimate Zoho infrastructure) |
| SPF | Pass |
| DKIM | Pass (`d=zohomail.com`, selector `zm2022`) |
| DMARC | Pass (`p=REJECT sp=REJECT dis=NONE`) |
| Attachments | None |
| Links | None |

**Key finding:** SPF/DKIM/DMARC all pass. This does **not** indicate a trustworthy sender — it only confirms the message was sent through Zoho's legitimate infrastructure using a real (likely disposable/freshly-created) `@zohomail.com` account. Authentication passing is frequently misread as "safe" by defenders; this case is a useful illustration of why that assumption is wrong. The trust signal that matters here is intent, not header hygiene.

### Submission Infrastructure

| Field | Value |
|---|---|
| Submission IP | `105.113.18[.]61` |
| Reverse DNS | None / missing PTR record |
| ASN | AS36873 — Airtel Networks Limited (mobile carrier, Nigeria) |
| IP usage type | Dynamic mobile broadband / CGNAT |
| Delivery infrastructure | Zoho Mail (outbound relay `136.143.188[.]92`) |
| Delivery interface | HTTP — logged as a manual Zoho Webmail browser session, not an automated SMTP/CLI tool |
| Zoho account identifier | `558d19fa657edde44560628027251181b2b6e4baca0bfcf93175186514f38aaf` |
| MXToolbox | IP flagged on one or more blacklists |
| AbuseIPDB | Historical low-severity noise present (dated port/CMS-scan reports), consistent with prior rotation of a shared mobile/CGNAT address rather than activity tied to this actor |
| Cisco Talos | Reviewed for reputation score |

This is a mobile carrier address, not a dedicated attacker-controlled host or relay. Shared dynamic mobile ranges routinely accumulate unrelated abuse history from prior users of the same address, so the AbuseIPDB history is treated as **background noise, not evidence tied to this specific actor**. The submission method (interactive webmail session) does indicate this was a live, manually-operated account rather than a bulk/automated spam tool, which is a more meaningful signal than the blacklist history.

### Pretext / Social Engineering Content

The actor:
1. Established contact under a plausible recruiting pretext
2. Opened with a low-suspicion screening questionnaire (role, salary, location, priorities)
3. Followed up requesting **email and password in plaintext**, framed as necessary to "review and prepare recommended profile adjustments for approval"
4. Used urgency language ("kindly share ... to proceed immediately")

No legitimate recruiter, staffing platform, or career service requires a candidate's actual account password for any reason — this is the definitive indicator that separates this from a normal (if oddly-run) recruiting interaction.

---

## Indicators of Compromise

| Type | Value |
|---|---|
| Email address | `hr.connect2026[at]zohomail[.]com` |
| Display name | HR Connect |
| Submission IP | `105.113.18[.]61` |
| ASN | AS36873 (Airtel Networks Limited, Nigeria) |
| Mail infrastructure | `mail.zoho.com` / `136.143.188[.]92` (legitimate provider, abused account) |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Notes |
|---|---|---|---|
| Resource Development | Establish Accounts: Email Account | T1585.002 | Free Zoho webmail account created/used for the pretext identity |
| Initial Access | Phishing | T1566 | General phishing via email under a recruiting pretext |
| Credential Access | Phishing for Information | T1598 | Parent technique used deliberately — no sub-technique (e.g. Spearphishing Link, T1598.003) applies, since the credential request occurred entirely in-body with no link or attachment |

---

## Detection & Prevention Recommendations

- **Never share account passwords with a third party**, regardless of the stated reason. Legitimate platforms authenticate via OAuth/SSO, never by collecting your raw credentials over email.
- Flag any message — even one passing SPF/DKIM/DMARC — that requests a password or full account credentials in plaintext. Authentication headers verify the transport path, not the sender's intent.
- Be cautious of recruiter contacts using free consumer webmail domains (Zoho, Gmail, Outlook.com) rather than a verifiable corporate domain, especially when paired with urgency language.
- Consider organizational mail filtering/banner rules that flag external messages containing both "password" and recruiting-related keywords in the body.

---

## Disclosure

This writeup is shared for security awareness and detection-engineering purposes.The reported sender address is a free-tier email account and is included only as a research indicator, not as an accusation against Zoho Corporation, which is not implicated beyond being the (abused) service provider.
