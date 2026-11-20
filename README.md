# ARTEX Detections

Detection rules, hunting queries and indicators for **ARTEX**, the open-source agentic AI penetration testing framework that state-aligned and criminal groups have used in real intrusions since August 2026. Includes its renamed builds and forks: ScopeWeaver, LUCK, Guanlan SEC, AntiFox and ARTEX PRO.

Maintained by [ThreatDefence](https://threatdefence.com). The full advisory, with how ARTEX works, who uses it and what each hunt looks for, is at
**https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting**

| | |
|---|---|
| Actors | Storm-0940, Storm-3358, VAPOR PANDA, an unattributed actor targeting South Korean finance, and financially motivated operators |
| Targets | Microsoft 365 and Entra ID, Okta, AWS, Azure, web applications, Active Directory |
| Platforms | Sigma, Microsoft Sentinel and Defender XDR, Splunk, Elastic, Zeek, Suricata, YARA, osquery, STIX 2.1 |
| Status | Experimental. Tested for syntax, conversion and against a synthetic pcap. Baseline every rule on your own data before alerting |

## What is in the repository

| Folder | Contents |
|---|---|
| [`iocs/indicators.csv`](iocs/indicators.csv) | 184 indicators: user agents, request artifacts, host artifacts, hashes, favicon hashes, domains, URLs and addresses. Each row has its source, confidence and a review date for addresses. This file is the single source for every feed |
| [`feeds/`](feeds) | Generated from the CSV: STIX 2.1 bundle, Sentinel watchlist and plain lists of addresses, domains, URLs, user agents and hashes |
| [`sigma/`](sigma) | 31 Sigma rules and 5 Sigma correlations for web, proxy, process, file, DNS, AWS, Azure, Entra ID and Okta logs |
| [`generated/`](generated) | The Sigma rules converted to Splunk SPL, Sentinel ASIM KQL and Elastic ES\|QL and Lucene. [`SUMMARY.md`](generated/SUMMARY.md) shows which rule converted to which backend |
| [`sentinel/hunting/`](sentinel/hunting) | 22 KQL hunts for Microsoft Sentinel and Defender XDR advanced hunting |
| [`sentinel/analytics/`](sentinel/analytics) | 5 scheduled analytics rules in the Sentinel template format |
| [`splunk/`](splunk) | A Splunk app: 15 saved searches (disabled by default), macros for your indexes and the indicator lookup |
| [`elastic/`](elastic) | 9 ES\|QL hunts and 5 detection rules in the Elastic detection-rules TOML format |
| [`zeek/`](zeek) | A detection script that raises notices for ARTEX traffic, and an Intel framework file |
| [`suricata/`](suricata) | 27 rules for user agents, probe artifacts, console pages, C2 domains and toolkit payload hosts, plus generated address rules |
| [`yara/`](yara) | 4 rules for ARTEX binaries, console assets, the backdoored console and probe files |
| [`osquery/`](osquery) | A pack for probe files and accounts, web service child shells, listening consoles and container images |
| [`docs/`](docs) | [Where to start](docs/hunting-order.md) and the [coverage matrix](docs/coverage.md) |
| [`tools/`](tools) | Feed builder, Sigma converter and validator |
| [`tests/`](tests) | A synthetic pcap and the Zeek and Suricata tests |

## Quick start

**Microsoft Sentinel.** Upload `feeds/sentinel-watchlist.csv` as a watchlist with the alias `ARTEX_IOCs` and the search key `value`, then run `sentinel/hunting/21-watchlist-indicator-sweep.kql`. Import the analytics rules from `sentinel/analytics/`. The hunts also run in Defender XDR advanced hunting where the tables exist.

**Splunk.** Copy `splunk/` into `$SPLUNK_HOME/etc/apps/TA-artex-detections`, point the macros in `default/macros.conf` at your indexes, run each saved search over 30 days, then enable it. The endpoint, web, authentication and network searches use the CIM data models.

**Elastic.** Paste the ES|QL hunts into Discover. Load the TOML rules with Elastic's detection-rules tooling, or recreate them in Kibana from the query and settings in each file. Fields follow ECS and the AWS, Azure and Elastic Defend integrations.

**Zeek.** Add `@load /path/to/zeek/artex` to `local.zeek`, and load `zeek/intel/artex.intel` through the Intel framework (see [`zeek/README.md`](zeek/README.md)).

**Suricata.** Add `suricata/artex.rules` and `suricata/artex-ip.rules` to your rule files. HTTP rules need cleartext or decrypted traffic. DNS and TLS SNI rules work on encrypted traffic.

**Sigma.** Convert with `sigma convert -t <backend> -p <pipeline> sigma/`, or use the conversions in `generated/`.

**Threat intelligence platforms.** Import `feeds/stix2.1-bundle.json`.

## Confidence

| Level | Meaning | How to use it |
|---|---|---|
| High | Specific to ARTEX: a user agent naming it, its probe artifacts, reported C2 domains, file hashes | Alert |
| Medium | Seen in ARTEX activity but changeable or shared: reported addresses, generic agent SDK user agents, community-reported markers | Alert after baselining, or hunt |
| Low | Legitimate services ARTEX uses: webhook.site, DNS log services, geolocation and AI model APIs | Context for another finding only |

Addresses from cloud and VPS providers are reassigned. Every address has a `review_by` date 180 days after it was reported. Check before you block.

## Testing

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py            # Sigma, KQL, ES|QL, TOML, Splunk, Suricata SIDs, YARA, osquery, feeds
python3 tools/convert.py             # regenerate generated/
python3 tests/make_pcap.py           # regenerate the synthetic pcap
bash tests/run_network_tests.sh      # needs zeek and suricata on the PATH
```

Last run: Suricata 8.0.8 and Zeek 9.0.1, all expected alerts and notices, no hit on the benign traffic in the pcap.

The pcap is synthetic. No rule in this repository has been tested against a captured ARTEX intrusion, so treat every rule as experimental until it has run on your own data.

## Sources

Indicators and behaviors come from these reports. Each row in `iocs/indicators.csv` names its own source.

- Microsoft, [Storm-0940 and the ConnectWise supply chain compromise](https://www.microsoft.com/en-us/security/blog/2026/10/21/storm-0940-uses-artex-agentic-ai-connectwise-supply-chain-compromise/) (October 21, 2026) and [ARTEX abuse expands as cybercriminals target the financial sector](https://www.microsoft.com/en-us/security/blog/2026/11/06/artex-abuse-expands-as-cybercriminals-target-financial-sector/) (November 6, 2026)
- FBI, [FLASH-20261113-001](https://www.ic3.gov/CSA/2026/261113.pdf) (November 13, 2026)
- Google Threat Intelligence Group and Mandiant, [ARTEX and Friends](https://cloud.google.com/blog/topics/threat-intelligence/artex-and-friends-enter-agentic-offensive-frameworks)
- CrowdStrike, [South Korean finance](https://www.crowdstrike.com/en-us/blog/unknown-threat-actor-uses-artex-to-target-south-korean-finance/) (October 7, 2026) and [VAPOR PANDA](https://www.crowdstrike.com/en-us/blog/vapor-panda-uses-artex-to-scale-global-campaign/) (October 29, 2026)
- Wiz, [ARTEX in the wild](https://www.wiz.io/blog/artex-in-the-wild-storm-0940-expands-targeting-of-it-and-software-vendors) (October 22, 2026)
- Censys, [ARTEX: Agentic Asbestos](https://censys.com/blog/artex-agentic-asbestos/) (November 5, 2026)
- Datadog Security Labs, [ARTEX in AWS environments](https://securitylabs.datadoghq.com/articles/artex-agentic-attacks-aws-environments/) (November 9, 2026)
- Elastic Security Labs, [Five AI attack frameworks](https://www.elastic.co/security-labs/threat-command/agentic-offensive-frameworks-detection-artex) (November 13, 2026)
- Cisco Talos, [ARTEX and beyond](https://blog.talosintelligence.com/artex-and-beyond/) (November 13, 2026). Snort users can also enable Talos SIDs 1:67494 to 1:67496 and 7:76 to 7:78
- ExtraHop, [Inside an agentic attack framework](https://www.extrahop.com/blog/artext-inside-an-agentic-attack-framework) (November 15, 2026)
- ReversingLabs, [Detection strategies for ARTEX and related forks](https://www.reversinglabs.com/blog/threat-researchers-notebook-detection-strategies-for-artex-and-related-forks) (November 18, 2026)
- MalwareMustDie, [MMD-072-2026](https://blog.malwaremustdie.org/2026/11/mmd-072-2026-artex-detection-signature.html) (November 13 to 17, 2026), for community-reported markers marked medium or low
- Fortinet FortiGuard Labs, [T-SQL being abused to deliver malware on compromised MS SQL servers](https://www.fortinet.com/blog/threat-research/t-sql-being-abused-to-deliver-malware-on-compromised-ms-sql-servers) (November 12, 2026), for the SQL Server toolkit hosts and payload hashes
- BadByte, via [e2e-assure](https://e2e-assure.com/guide/artex-attacks), for the backdoored container images

The rules, queries and scripts here are original work. No rule text was copied from other packs.

## Contributing

Pull requests are welcome. Add new indicators to `iocs/indicators.csv` with a public source, run `python3 tools/build_feeds.py` and `python3 tools/validate.py`, and commit the regenerated files. Report false positives as issues, with the rule name and the shape of the event (no customer data).

## License

MIT. See [LICENSE](LICENSE). The indicators are facts reported by the sources above. Use them in your own products and feeds.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.
