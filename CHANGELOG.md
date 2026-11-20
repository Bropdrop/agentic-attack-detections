# Changelog

## 1.0.0, November 20, 2026

First public release.

- 184 indicators in `iocs/indicators.csv`, each with its source, confidence and review date, built into STIX 2.1, a Sentinel watchlist, a Splunk lookup, a Zeek intel file, Suricata address rules and plain lists.
- 31 Sigma rules and 5 Sigma correlations, converted to Splunk, Sentinel and Elastic in `generated/`.
- 22 Microsoft Sentinel and Defender XDR hunts and 5 scheduled analytics rules.
- 9 Elastic ES|QL hunts and 5 Elastic detection rules.
- A Splunk app with 15 saved searches and macros.
- A Zeek detection script, 27 Suricata rules, 4 YARA rules and an osquery pack.
- Network tests against a synthetic pcap for Zeek and Suricata.
