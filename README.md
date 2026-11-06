# OpsVantage Tools

Free, private security tools for SOC analysts, IT admins and MSPs, live at **[tools.opsvantage.net](https://tools.opsvantage.net/)**.

Every tool is a static page that runs in your browser. There is no backend: what you paste is processed on your device, and the only network requests are the ones listed below. This repository is the full source of the site, so you can read exactly what each tool does, run it yourself, or host it internally.

## Tools

| Tool | What it does | Network requests |
|---|---|---|
| [IOC Extractor](https://tools.opsvantage.net/ioc-extractor/) | Pulls IPs, domains, URLs, hashes, emails, CVEs, file names, registry keys, ASNs and Bitcoin addresses out of any text; defang / refang, CSV | None |
| [Email Header Analyzer](https://tools.opsvantage.net/email-headers/) | SPF, DKIM, DMARC, delivery path, BEC red flags; reads a whole .eml for links and attachments | None |
| [Phishing Link Unwrapper](https://tools.opsvantage.net/link-unwrapper/) | Decodes Safe Links, Proofpoint URL Defense v1-v3 and redirect chains offline, then checks the destination | None |
| [SPF, DKIM & DMARC Checker](https://tools.opsvantage.net/dmarc-checker/) | Grades a domain's email security and gives the exact DNS records to fix | DNS-over-HTTPS to Cloudflare / Google |
| [Windows Event Triage](https://tools.opsvantage.net/event-triage/) | Event ID lookup and rule-based detection in Event Viewer, PowerShell, Sentinel, Splunk and Elastic exports | None |
| [M365 Sign-in Review](https://tools.opsvantage.net/m365-signins/) | Impossible travel, spraying, MFA fatigue and legacy auth in an Entra sign-in export | None |
| [M365 Posture Scanner](https://tools.opsvantage.net/m365-posture/) | Read-only graded review of a Microsoft 365 tenant | Microsoft sign-in and Graph, DNS |
| [Hunting Query Generator](https://tools.opsvantage.net/hunt-queries/) | IOCs to KQL (Sentinel / Defender XDR), Splunk SPL, CrowdStrike LogScale and Elastic queries | None |
| [CVE Prioritizer](https://tools.opsvantage.net/cve-prioritizer/) | Ranks CVEs with CISA KEV, FIRST EPSS and CVSS | CVE IDs to FIRST and CVE.org; KEV file from GitHub |
| [Payload Decoder](https://tools.opsvantage.net/payload-decoder/) | Peels encoded PowerShell, Base64, gzip, hex and more, layer by layer; nothing runs | None |
| [JWT Token Decoder](https://tools.opsvantage.net/jwt-decoder/) | Explains Entra ID and other tokens: app, MFA, roles, scopes, sign-in IP | None |

How each tool reaches its verdicts, with the exact thresholds, is documented on [How it works](https://tools.opsvantage.net/how-it-works/). The [privacy policy](https://tools.opsvantage.net/privacy/) lists everything stored in the browser.

The companion browser extension, [IOC Triage](https://github.com/kazisohan-cyber/soclens), gives indicators a verdict from threat-intel sources with a right-click.

## Run it locally

No build step. Serve the folder with any static web server:

```bash
python -m http.server 8770
```

Then open http://localhost:8770. The M365 Posture Scanner needs your own Entra app registration for live sign-in (set `clientId` in `m365-posture/config.js`); its demo tenant works without one.

## Layout

- `assets/` shared styles, helpers (`hub.js`), charts (`charts.js`) and libraries in `assets/lib/` (IOC extraction, header and .eml parsing, mail authentication checks)
- one folder per tool, each with `index.html` and `app.js`
- `guides/` and `events/` are generated pages (guides and Windows event ID reference)
- `_headers` sets the security headers, including a Content Security Policy for every page

## Contributing

Issues and pull requests are welcome: wrong verdicts, false positives, new detections or formats. Please include a sanitised sample. For security problems, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
