# WAF rules for agentic attack frameworks

Ready-to-deploy rules for **Cloudflare**, **AWS WAF** and **Azure WAF** (Application Gateway and Front Door). They act on the request-side fingerprints that agentic attack frameworks leave on web applications: their user agents, probe markers in URLs, custom headers, unsigned JWT probes, and the addresses from public reporting.

## Do I need a WAF to use this repository?

No. The rest of the repository is detection content for your SIEM, IDS and EDR, and it already sees attacks on web applications in web server logs, proxy logs and Suricata. A WAF is an extra place to **stop** part of that traffic at the edge.

These rules don't replace your WAF's managed rule sets. The frameworks drive ordinary attack tools (sqlmap, nuclei, ffuf and others), and an operator can change a user agent in one line. Managed rules, bot management and rate limiting still do the work against the exploits themselves. These rules add attribution and catch the framework-specific fingerprints.

Most of what these frameworks do after the first foothold never passes through a WAF: shells under web services, cloud API abuse, Kerberos, calls to AI model APIs and callbacks. Keep the SIEM and IDS content in place, and send your WAF logs to the SIEM. Several hunts work on them, including user agent bursts, an AI page reader next to attack traffic, and rotating proxy probing.

## What the rules do

Every file here is generated from [`signatures.yaml`](signatures.yaml) and `iocs/indicators.csv` by `tools/build_waf.py`.

| Group | Tier | Cloudflare | AWS WAF (default) | Azure (default) | Mirrors |
|---|---|---|---|---|---|
| Framework user agents (ARTEX, AntiFox, ScopeWeaver, HexStrike, CyberStrikeAI) | block | block | count, or block with a switch | Block | Suricata 3800001-3800009, 3803001-2, 3804001 |
| Probe markers in the URL, plus the `X-ARTX-KEY` and `X-ARTEX-Replay-Nonce` headers | block | block | count, or block | Block | Suricata 3800020-3800027, 3803004, 3804002 |
| Unsigned `alg:none` JWT in the URL or Authorization header | block | block | count, or block | Block | Suricata 3800023-3800033 |
| CyberStrikeAI webshell OS probe in the request body | block | off (needs Enterprise) | count, or block | Block | Suricata 3804003 |
| Scanner user agents (ffuf from Kali, HexStrike exploits, ReconProbe, norma, azure-toolkit) | challenge | managed challenge | count, challenge or CAPTCHA | Log | Suricata 3801011, 3803003 |
| Reported addresses (low and medium confidence) | challenge | managed challenge | count, challenge or CAPTCHA | Log | `iocs/indicators.csv` |
| AI agent page readers (Claude Code, Qwen Code, Kimi CLI, opencode, Agent Zero) | log | off (log needs Enterprise) | count | Log | Suricata 3801010-3801014 |
| Hermes results folder requested | log | off | count | Log | Suricata 3806012 |
| WSUS admin and sync services from the internet | opt-in | off | count, or block | Log | Suricata 3801040 |

- **Block** tier: fingerprints with no legitimate use. Safe to block. The one to check first is the unsigned JWT rule: it blocks every `alg:none` token, so keep it in log or count if an application of yours accepts unsigned tokens by design.
- **Challenge** tier: hostile tooling at medium confidence, and addresses. Hosting addresses get reused, so addresses are **never blocked by default**. Rows past their `review_by` date are left out.
- **Log** tier: agents people also use for real work. Log them, don't block them.
- **Opt-in**: turn the WSUS rule on only if the site fronts a WSUS server.

AWS rules ship in Count, and every rule adds a label (`td:agentic:<tier>:<group>`), so you can watch the matches before you enforce. The Azure templates create the policy in Detection mode, so nothing is blocked until you switch the policy to Prevention.

Response-side rules (attacker consoles, Swagger pages, skimmer JavaScript), outbound rules (implant C2, model API prompts, payload downloads) and host or cloud rules stay in the Suricata, Sigma, KQL and Zeek content. A WAF can't act on them.

## Cloudflare

Files: [`cloudflare/expressions.md`](cloudflare/expressions.md) (paste into the dashboard), [`cloudflare/rules.json`](cloudflare/rules.json) (Rulesets API), [`cloudflare/ip-list.json`](cloudflare/ip-list.json) (list items), [`cloudflare/terraform/`](cloudflare/terraform/main.tf) (provider 5.x).

The Free plan allows 5 custom rules, and 5 rules are on by default. The log action needs Enterprise, and body inspection needs Enterprise with Advanced application security.

**Dashboard:**
1. Go to **Manage Account > Configurations > Lists** and create an IP list named `td_agentic_attack_ips`.
2. Add the addresses from `ip-list.json`.
3. Create each rule from `expressions.md`.

**API:**

```bash
# IP list (account level)
LIST_ID=$(curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/rules/lists" \
  -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" \
  --data '{"name":"td_agentic_attack_ips","kind":"ip","description":"Agentic attack detections"}' | jq -r .result.id)
curl -s -X POST "https://api.cloudflare.com/client/v4/accounts/$ACCOUNT_ID/rules/lists/$LIST_ID/items" \
  -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data @waf/cloudflare/ip-list.json

# Add each rule to the zone's custom rules (keeps your existing rules)
RULESET_ID=$(curl -s "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/phases/http_request_firewall_custom/entrypoint" \
  -H "Authorization: Bearer $CF_API_TOKEN" | jq -r .result.id)
jq -c '.[]' waf/cloudflare/rules.json | while read -r rule; do
  curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/rulesets/$RULESET_ID/rules" \
    -H "Authorization: Bearer $CF_API_TOKEN" -H "Content-Type: application/json" --data "$rule" | jq -r '.success'
done
```

If the zone has no custom rules yet, the entrypoint lookup fails. Create one rule in the dashboard first. Don't `PUT` the entrypoint, because that replaces every custom rule in the zone.

**Terraform:** `terraform apply -var account_id=... -var zone_id=...`. Set `enabled_refs` to choose which rules are on. Like the API, this resource manages the zone's whole custom rules phase. If you already manage custom rules in Terraform, copy the rules into your own `cloudflare_ruleset`.

## AWS WAF

Files: [`aws/cloudformation.yaml`](aws/cloudformation.yaml), [`aws/terraform/`](aws/terraform/main.tf) (provider 5.x), and CLI input in [`aws/rule-group.json`](aws/rule-group.json), [`aws/ip-set-ipv4.json`](aws/ip-set-ipv4.json) and [`aws/ip-set-ipv6.json`](aws/ip-set-ipv6.json).

The rule group needs about 220 WCU and is created with a capacity of 350. Capacity can't change after creation, so the extra room lets later releases add signatures.

**CloudFormation** (recommended):

```bash
aws cloudformation deploy --stack-name td-agentic-attack --template-file waf/aws/cloudformation.yaml \
  --parameter-overrides BlockTierAction=Count ChallengeTierAction=Count
# Use Scope=CLOUDFRONT in us-east-1 for CloudFront distributions.
```

Then add the rule group to your web ACL (stack output `RuleGroupArn`) with **override action: None**. Once the labels look clean, redeploy with `BlockTierAction=Block`. Alternatively, keep Count in the group and override individual rules to Block in the web ACL.

**CLI:**

```bash
aws wafv2 create-ip-set --cli-input-json file://waf/aws/ip-set-ipv4.json   # note the ARN
aws wafv2 create-ip-set --cli-input-json file://waf/aws/ip-set-ipv6.json
export TD_AGENTIC_IPV4_SET_ARN=arn:aws:wafv2:... TD_AGENTIC_IPV6_SET_ARN=arn:aws:wafv2:...
envsubst < waf/aws/rule-group.json > /tmp/td-rule-group.json
aws wafv2 create-rule-group --cli-input-json file:///tmp/td-rule-group.json
```

The header rule matches the header names `x-artx-key` and `x-artex-replay-nonce` anywhere in the request's header names. AWS doesn't document how a regex is applied to header names, so watch this rule's label in Count before you enforce it.

The body rule inspects the first part of the body that AWS WAF forwards (8 KB on Application Load Balancer, 16 KB by default elsewhere), and longer bodies are still inspected up to that limit.

## Azure WAF

Files: [`azure/appgw-policy.bicep`](azure/appgw-policy.bicep) and [`.json`](azure/appgw-policy.json) (Application Gateway v2), [`azure/frontdoor-policy.bicep`](azure/frontdoor-policy.bicep) and [`.json`](azure/frontdoor-policy.json) (Front Door Standard or Premium), plus the plain `customRules` arrays in [`azure/appgw-custom-rules.json`](azure/appgw-custom-rules.json) and [`azure/frontdoor-custom-rules.json`](azure/frontdoor-custom-rules.json).

**New policy:**

```bash
az deployment group create -g $RG --template-file waf/azure/appgw-policy.bicep \
  --parameters policyName=TdAgenticAttack mode=Detection
az deployment group create -g $RG --template-file waf/azure/frontdoor-policy.bicep \
  --parameters policyName=TdAgenticAttack sku=Premium_AzureFrontDoor mode=Detection
```

The Application Gateway policy includes the Microsoft Default Rule Set 2.1 and turns on request body inspection. The Front Door policy carries only these custom rules, so add the Default Rule Set on Premium. Attach the policy to your gateway, listener or Front Door endpoint, review the logs, then set `mode=Prevention`.

**Existing policy:** deploying a template replaces the whole policy, managed rules included. Instead, add the rules from the `*-custom-rules.json` file to your policy, in the portal's JSON view or your own template. Their priorities start at 50 on Application Gateway and at 100 on Front Door. Renumber them if those collide with your own rules.

On Application Gateway, values with spaces are written as regular expressions with `\s`, because rule sets up to CRS 3.1 reject spaces in match values. Front Door accepts spaces and allows only 5 regex rules per policy, so its rules keep plain values and use a regular expression only for the two header checks. Application Gateway only matches IPv4 addresses, so the one IPv6 address is on Front Door only.

## Keeping it current

```bash
python3 tools/build_waf.py        # after changing signatures.yaml or iocs/indicators.csv
python3 tests/waf/run_tests.py    # offline checks for every platform
```

`as_of` in `signatures.yaml` sets the date used to drop expired addresses. Bump it with each release. Redeploy after each release. The Cloudflare list, the AWS IP sets and the Azure address rules are replaced as a whole.

## How the rules are checked

CI runs all of these on every push:

- **Deterministic build.** `tools/build_waf.py` must reproduce every committed file.
- **Behavior.** `tests/waf/run_tests.py` evaluates the generated files themselves with a small evaluator per platform:
  - Every signature value must fire its rule, upper-cased too where matching ignores case, and percent-encoded where it sits in the URL.
  - Every address must fire the address rule.
  - Each hand-written request in [`tests/waf/requests.yaml`](../tests/waf/requests.yaml) must fire exactly the rules it lists. Most of those requests are near misses.
  - The HTTP requests from the Suricata test flows are replayed: if Suricata fires a mirrored SID, the WAF rule must fire, and Suricata near misses must not fire a block-tier rule.
- **Limits and schemas:**
  - Cloudflare: expression length, plan fit and allowed actions.
  - AWS: capacity, regex length, no grouping syntax in a regex, and the JSON checked against the wafv2 API model from botocore. `cfn-lint` checks the CloudFormation template.
  - Azure: rule names, priority range, values per condition, the operator spelling each service expects, and Front Door's cap of 5 regex rules. `az bicep build` compiles both templates.
  - Terraform: `terraform validate` runs on both folders.
  - On every platform, no address rule may block by default.
