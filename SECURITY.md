# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report it privately through GitHub: **Security tab → Report a vulnerability** on this repository, or email hello@opsvantage.net. Include what is affected (which tool or page), steps to reproduce, and the impact you expect.

You will get an answer within 7 days. Confirmed issues are fixed as soon as possible, and you are credited in the changelog unless you ask not to be.

## Scope

In scope:
- anything that sends data a page says stays in the browser
- cross-site scripting or injection through pasted input, uploaded files, URL parameters or the embeddable widget
- weaknesses in the Content Security Policy or other headers in `_headers`
- the M365 Posture Scanner requesting or keeping more access than documented

Out of scope:
- third-party services the tools link to or query (VirusTotal, AbuseIPDB, urlscan, FIRST, CVE.org, Microsoft Graph and others)
- detection gaps (a phishing link or attack the tools don't flag): please open a normal issue so detection can improve
- issues that need an already compromised device or browser

## Known limits (by design, documented)

- The JWT Token Decoder does not verify signatures.
- Verdicts are rule-based and can be wrong; they are an aid to an analyst, not a replacement.
