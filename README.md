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

## Contributing

Pull requests are welcome. Add new indicators to `iocs/indicators.csv` with their source, run `python3 tools/build_feeds.py` and `python3 tools/validate.py`, and commit the regenerated files. Report false positives as issues, with the rule name and the shape of the event (no customer data).

## License

MIT. See [LICENSE](LICENSE). Each indicator names its source in `iocs/indicators.csv`. Use them in your own products and feeds.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.
