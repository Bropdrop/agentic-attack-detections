# Agentic Attack Detections

Detection rules, hunting queries and indicators for agentic attack frameworks (ARTEX and its AntiFox fork, Cairn, PentAGI, HexStrike, CyberStrikeAI, Strix, Hermes Agent and Agent Zero so far): open-source tools that hand an intrusion to AI agents, which plan, run real attack tools and keep going until they reach a goal. Each framework gets its own folder, built from a review of its source code and the public reporting on its use. The behaviors they share, such as AI agents running attack tools with their approval prompts off, servers calling Chinese model APIs, bursts of tools from one source and probing through rotating proxies, have their own folder, so one rule covers every framework.

Maintained by [ThreatDefence](https://threatdefence.com).

> This repository was `artex-detections`. GitHub redirects the old address. The ARTEX rules moved from the root to [`frameworks/artex/`](frameworks/artex); `iocs/indicators.csv` and `feeds/` kept their paths.

## Frameworks

| Framework | What it is | Folder | Reporting |
|---|---|---|---|
| ARTEX | Go planner and worker agents with a web console, released July 2026 (AntiFox is the same code renamed), used by Storm-0940, Storm-3358, VAPOR PANDA and criminal groups against Microsoft 365, Okta, AWS, Azure, web applications and Active Directory | [`frameworks/artex/`](frameworks/artex) | [ARTEX advisory](https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting), [ARTEX deep hunting](https://threatdefence.com/article/artex-source-code-signals-deep-hunting) |
| Cairn | Python engine that drives Claude Code, Codex and Pi coding agents in Kali containers, used against online retailers, payment sites, Japanese web applications and WSUS servers | [`frameworks/cairn/`](frameworks/cairn) | [What Cairn leaves behind](frameworks/cairn/source-code-signals.md) |
| PentAGI | Go multi-agent platform from VXControl that runs Kali tools in a container per engagement, seen by GTIG and Mandiant in intrusions since August 2026 and on a PaperCut exploitation operator's infrastructure | [`frameworks/pentagi/`](frameworks/pentagi) | [What PentAGI leaves behind](frameworks/pentagi/source-code-signals.md) |
| HexStrike | Python MCP tool server that gives any AI assistant about 150 security tools over an unauthenticated API on port 8888, discussed for NetScaler exploitation in 2025 and seen by GTIG and Mandiant in intrusions | [`frameworks/hexstrike/`](frameworks/hexstrike) | [What HexStrike leaves behind](frameworks/hexstrike/source-code-signals.md) |
| CyberStrikeAI | Go operator console whose agents run about 90 tools and which builds its own implants, C2 listeners and webshell manager, tied to the FortiGate mass-exploitation infrastructure, an AWS intrusion and attacks on education organizations in Africa and Latin America | [`frameworks/cyberstrikeai/`](frameworks/cyberstrikeai) | [What CyberStrikeAI leaves behind](frameworks/cyberstrikeai/source-code-signals.md) |
| Strix | Python AI pentest agent that runs teams of agents in a Kali sandbox through a Caido proxy, on any model; found the flaws Cairn exploited in the retail card-theft campaign Gambit reported | [`frameworks/strix/`](frameworks/strix) | [What Strix leaves behind](frameworks/strix/source-code-signals.md) |
| Hermes Agent | Legitimate general-purpose agent turned into an attack console: approvals off, a bundled jailbreak skill, red-team personas and Telegram control. Used by knaithe/KnYuan, the Gambit retail operator, the Carbonato Docker botnet and inside Thailand's Ministry of Finance | [`frameworks/hermes/`](frameworks/hermes) | [What Hermes leaves behind](frameworks/hermes/source-code-signals.md) |
| Agent Zero | General-purpose agent in a Kali container with a built-in hacker profile and an open web UI; GTIG reported threat-actor experimentation | [`frameworks/agent-zero/`](frameworks/agent-zero) | [Agent Zero folder](frameworks/agent-zero/README.md) |

## Behaviors shared by agentic frameworks

[`behaviors/`](behaviors) holds rules that do not depend on any one framework:

| Behavior | Rules |
|---|---|
| AI agent CLIs in auto-approve mode starting attack tools (Qwen Code, Kimi CLI, Claude Code, Codex, Pi), whatever model is behind them | KQL hunt, Sentinel analytics rule, Sigma |
| Servers calling AI model APIs: Chinese models (DeepSeek, Qwen, GLM, Kimi, MiniMax, Doubao), gateways such as OpenRouter, and Western APIs | KQL hunt, Sigma, Zeek |
| An AI agent's page reader (Qwen Code, Kimi CLI, opencode, Claude Code) on your application next to attack traffic from the same address | KQL hunt, Sigma, Suricata, Zeek |
| One site probed through hundreds of rotating proxy addresses | KQL hunt, Zeek |
| Configuration and backup file theft, and probes of WSUS administration services | KQL hunt, Sentinel analytics rule, Sigma, Suricata, Zeek |
| Kerberos user enumeration and SMB or WinRM fan-out from one address | KQL hunt, Zeek |
| A server calling back to the address that was probing it, including PentAGI's worker ports 28000 to 29999 | KQL hunt, Suricata (PentAGI ports), Zeek |
| AWS credentials used at machine speed: several identities checked from one address, bulk user data reads, instance role keys used from outside | KQL hunt |
| Servers looking up out-of-band testing domains (interactsh `oast.*`, Burp Collaborator, dnslog.cn): a blind injection, SSRF or XXE payload ran on them | KQL hunt, Sigma, Suricata, Zeek |

The ARTEX folder also carries behavior hunts written before this split: user agent family bursts (hunt 17), web and database services starting shells (hunt 11), servers calling webhook and tunnel services (hunt 12), scripts written into web folders (hunt 13) and Kerberoasting, DCSync and WinRM fan-out (hunt 16). They apply to every framework.

## Shared indicators and feeds

| Path | Contents |
|---|---|
| [`iocs/indicators.csv`](iocs/indicators.csv) | 514 indicators across all frameworks. Each row has its source, confidence, a review date for addresses and a `framework` column (`artex`, `cairn`, `pentagi`, `hexstrike`, `cyberstrikeai`, `strix`, `hermes`, `agent-zero`, or several). This file is the single source for every feed |
| [`feeds/`](feeds) | Generated from the CSV for all frameworks: STIX 2.1 bundle with one tool per framework, Sentinel watchlist and plain lists of IPv4 and IPv6 addresses, domains, URLs, user agents and SHA-256 and MD5 hashes. [`feeds/by-framework/`](feeds/by-framework) has the plain lists per framework |
| [`generated/`](generated) | Every Sigma rule converted to Splunk SPL, Sentinel ASIM KQL and Elastic ES\|QL and Lucene, by framework. [`SUMMARY.md`](generated/SUMMARY.md) shows which rule converted to which backend |
| [`tools/`](tools) | Feed builder, Sigma converter and validator |
| [`docs/`](docs) | [Adding a framework](docs/adding-a-framework.md) |

Each framework folder has its own Zeek intel file and Suricata address rules, generated from the same CSV.

## Quick start

**Microsoft Sentinel.** Upload `feeds/sentinel-watchlist.csv` as a watchlist with the alias `AGENTIC_IOCs` and the search key `value`. The watchlist sweep in each framework folder filters it to that framework's rows. Import the analytics rules from `frameworks/*/sentinel/analytics/` and `behaviors/sentinel/analytics/`. The hunts also run in Defender XDR advanced hunting where the tables exist.

**Suricata.** Add the `.rules` files from `frameworks/*/suricata/` and `behaviors/suricata/`. HTTP rules need cleartext or decrypted traffic. DNS and TLS SNI rules work on encrypted traffic.

**Zeek.** Load the behavior package in `behaviors/zeek/agentic-behaviors/` ([setup](behaviors/zeek/README.md)), the ARTEX script in `frameworks/artex/zeek/artex/`, and `frameworks/*/zeek/intel/*.intel` through the Intel framework.

**YARA.** Scan container layers, home folders, `/tmp` and web roots with the files in `frameworks/*/yara/`.

**Sigma.** Convert the rules in `frameworks/*/sigma/` and `behaviors/sigma/` with `sigma convert`, or use the conversions in `generated/`.

**Splunk and Elastic.** The ARTEX folder has a Splunk app and Elastic rules. For the other frameworks use the conversions in `generated/`.

**Threat intelligence platforms.** Import `feeds/stix2.1-bundle.json`, or the per-framework lists in `feeds/by-framework/`.

## Confidence

| Level | Meaning | How to use it |
|---|---|---|
| High | Specific to a framework or its campaigns: its user agents, command lines, paths, prompt strings, probe artifacts, reported C2 and skimmer domains, file hashes | Alert |
| Medium | Seen in a framework's activity but changeable or shared: reported addresses, generic agent user agents, prompt text shared with similar tools | Alert after baselining, or hunt |
| Low | Common or legitimate: AI model APIs, request-collection services, agent CLI user agents, hosting ASNs, proxy providers | Context for another finding only |

Addresses from cloud and VPS providers are reassigned. Every address has a `review_by` date 180 days after it was reported. Check before you block.

## Testing

```bash
pip install -r tools/requirements.txt
python3 tools/validate.py                              # Sigma, KQL, ES|QL, TOML, Splunk, Suricata SIDs, YARA, osquery, feeds
python3 tools/convert.py                               # regenerate generated/
bash frameworks/artex/tests/run_network_tests.sh       # needs zeek and suricata on the PATH
bash behaviors/zeek/tests/run_tests.sh                 # needs zeek on the PATH
```

No rule in this repository has been tested against a captured intrusion, so treat every rule as experimental until it has run on your own data.

## Contributing

Pull requests are welcome. Add new indicators to `iocs/indicators.csv` with their source and framework, run `python3 tools/build_feeds.py` and `python3 tools/validate.py`, and commit the regenerated files. To add a framework, follow [docs/adding-a-framework.md](docs/adding-a-framework.md). Report false positives as issues, with the rule name and the shape of the event (no customer data).

## License

MIT. See [LICENSE](LICENSE). Each indicator names its source in `iocs/indicators.csv`. Use them in your own products and feeds.

## Disclaimer

Provided as is, without warranty. A match is a lead, not a verdict. Absence of a match does not mean absence of compromise.
