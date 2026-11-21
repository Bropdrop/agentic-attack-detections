# Changelog

## Unreleased

- Every branded indicator now names the publication it first appeared in: Datadog Security Labs (November 9, 2026) for the `artex-*` user agents and S3 placeholder names, Wiz Research (October 22) for `/zzz-nonexistent-xyz123`, `ReconProbe/1.0` and `norma/0.4`, Microsoft (October 21) for `azure-toolkit/1.0`, and Eye Security (November 12) for `X-ARTX-KEY`, `### ARTX-AGENT`, the probe markers and `ArtExVerify/1.0`. No indicator was removed.
- Context corrected: these strings are chosen at run time by the agents or the operator, which is why they are absent from the public code. 1.1.0 described them as coming from modified builds.
- `Mozilla/5.0 (compatible; ArtExVerify/1.0)` raised to high confidence, from Eye Security's primary report.
- New section in `docs/source-code-signals.md`: where the branded strings come from.

## 1.1.0, November 21, 2026

Detections drawn from a review of the ARTEX source code (BaaRai/ARTEX at f787b5f and the BaaRai/Norma v0.4.11 agent library it builds against). See [`docs/source-code-signals.md`](docs/source-code-signals.md).

- 31 new indicators in `iocs/indicators.csv`, each with the file it comes from: the `artex-update-check` user agent, the `X-Keenable-Title: ARTEX` header, the recording proxy credential `artex-pace:artex-pace`, the `__artex-exec-drop` launcher argument and `artex-exec-` shim folder, prompt and envelope markers in model requests, more tool function names, the console title and icon hash, port 8788, skill script names and the S3 archive prefix. Feeds rebuilt.
- Context of `norma/0.4` and both `spa-api-recon` user agents now points at the code that sends them.
- The branded user agents from 1.0.0 (`artex-pentest/1.0` and the rest) are now marked as coming from modified builds: they do not appear in the upstream ARTEX code. `artex-enrich/1.0` context corrected: upstream enrichment sends `Go-http-client/1.1`.
- New hunts:
  - 23 norma page reads and the Go enrichment probe that follows them.
  - 24 the ARTEX container toolchain seen from one source (refines 17).
  - 25 request rates that match the ARTEX noise profiles.
  - 26 headless browsers and ARTEX clients signing in, and the pause while a person relays the MFA code.
  - 27 accounts registered by a source that is also probing the application.
  - 28 ARTEX running on a monitored host (refines 20).
  - 29 ARTEX console and side-channel traffic in outbound proxy logs.
  - 30 bracketed-paste bytes in shell input.
- New analytics rules: ARTEX code-default user agents, and the ARTEX agent shell or proxy credential on a host.

## 1.0.0, November 20, 2026

First public release.

- 184 indicators in `iocs/indicators.csv`, each with its source, confidence and review date, built into STIX 2.1, a Sentinel watchlist, a Splunk lookup, a Zeek intel file, Suricata address rules and plain lists.
- 31 Sigma rules and 5 Sigma correlations, converted to Splunk, Sentinel and Elastic in `generated/`.
- 22 Microsoft Sentinel and Defender XDR hunts and 5 scheduled analytics rules.
- 9 Elastic ES|QL hunts and 5 Elastic detection rules.
- A Splunk app with 15 saved searches and macros.
- A Zeek detection script, 27 Suricata rules, 4 YARA rules and an osquery pack.
- Network tests against a synthetic pcap for Zeek and Suricata.
