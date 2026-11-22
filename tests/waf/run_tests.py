#!/usr/bin/env python3
"""Check every generated WAF rule against test requests, offline, for Cloudflare, AWS WAF and both Azure WAFs.

    python3 tools/build_waf.py
    python3 tests/waf/run_tests.py

The checks evaluate the generated files themselves (waf/cloudflare/rules.json, waf/aws/rule-group.json and the IP
sets, waf/azure/*-custom-rules.json) with a small evaluator per platform, so a mistake in the generator shows up here.

1. Every signature value fires its rule on every platform, upper-cased too when the match is case-insensitive, and
   percent-encoded when it sits in the URL. Every address fires the address rule (IPv6 is skipped on Application
   Gateway, which only matches IPv4).
2. The hand-written requests in requests.yaml fire exactly the groups they list. Most are near misses that must
   stay silent: normal browsers, lookalike words, signed JWTs, the values in the wrong field.
3. The HTTP requests from the Suricata test flows (tests/suricata/run_tests.py) are replayed: a flow that fires a
   mirrored SID must fire the WAF group, and a Suricata near miss must not fire a block-grade group. Needs openssl.
4. Platform limits: Cloudflare expression length, actions and plan fit; AWS capacity and regex length, and the files
   against the wafv2 API model when botocore is installed; Azure rule names, priorities and value counts.

Exit status is non-zero on any failure.
"""
import ipaddress
import json
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import quote, unquote

import yaml

ROOT = Path(__file__).resolve().parents[2]
WAF = ROOT / "waf"
SPEC = yaml.safe_load((WAF / "signatures.yaml").read_text())
GROUPS = {g["id"]: g for g in SPEC["groups"]}
BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CLEAN_IP = "198.51.100.7"
failures = []


def fail(msg):
    failures.append(msg)
    print("FAIL", msg)


def request(path="/", query="", ua=BROWSER, headers=None, body="", ip=CLEAN_IP, method="GET"):
    h = [("Host", "app.example.test")] + ([("User-Agent", ua)] if ua is not None else []) + list((headers or {}).items())
    return {"method": method, "path": path, "query": query, "headers": h, "body": body, "ip": ip}


def header(req, name):
    vals = [v for k, v in req["headers"] if k.lower() == name.lower()]
    return vals[0] if vals else None


# ---------------------------------------------------------------- Cloudflare (subset of the Rules language)

CF_FIELDS = {"http.user_agent", "http.request.uri", "http.request.headers", "http.request.headers.names",
             "http.request.body.raw", "ip.src"}
CF_FUNCS = {"lower", "any", "starts_with"}
TOKEN = re.compile(r'\s*(?:(?P<str>"(?:[^"\\]|\\.)*")|(?P<list>\$[a-z0-9_]+)|(?P<star>\[\*\])|(?P<op>==|\(|\)|\[|\]|,)|(?P<word>[A-Za-z_][A-Za-z0-9_.]*))')


def cf_tokens(expr):
    pos, out = 0, []
    while pos < len(expr):
        m = TOKEN.match(expr, pos)
        if not m or m.end() == pos:
            if expr[pos:].strip() == "":
                break
            raise SyntaxError(f"bad token at {pos}: {expr[pos:pos + 20]!r}")
        kind = m.lastgroup
        val = m.group(kind)
        out.append((kind, json.loads(val) if kind == "str" else val))
        pos = m.end()
    return out


class CF:
    def __init__(self, expr, lists):
        self.t, self.i, self.lists = cf_tokens(expr), 0, lists
        self.ast = self.expr()
        if self.i != len(self.t):
            raise SyntaxError(f"trailing tokens: {self.t[self.i:]}")

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, val=None):
        k, v = self.peek()
        if val is not None and v != val:
            raise SyntaxError(f"expected {val!r}, got {v!r}")
        self.i += 1
        return k, v

    def expr(self):
        node = self.term()
        while self.peek()[1] == "or":
            self.take()
            node = ("or", node, self.term())
        return node

    def term(self):
        node = self.factor()
        while self.peek()[1] == "and":
            self.take()
            node = ("and", node, self.factor())
        return node

    def factor(self):
        k, v = self.peek()
        if v == "not":
            self.take()
            return ("not", self.factor())
        if v == "(":
            self.take()
            node = self.expr()
            self.take(")")
            return node
        left = self.value()
        k, v = self.peek()
        if v in ("contains", "==", "in"):
            self.take()
            rk, rv = self.take()
            if rk not in ("str", "list"):
                raise SyntaxError(f"right side of {v} must be a string or list, got {rv!r}")
            if rk == "list" and rv[1:] not in self.lists:
                raise SyntaxError(f"unknown list {rv}")
            return (v, left, rv)
        return ("bool", left)

    def value(self):
        k, v = self.take()
        if k != "word":
            raise SyntaxError(f"expected a field or function, got {v!r}")
        if self.peek()[1] == "(":
            if v not in CF_FUNCS:
                raise SyntaxError(f"unknown function {v}")
            self.take("(")
            args = [self.factor() if v == "any" else self.value_or_str()]
            while self.peek()[1] == ",":
                self.take()
                args.append(self.value_or_str())
            self.take(")")
            node = ("call", v, args)
        else:
            if v not in CF_FIELDS:
                raise SyntaxError(f"unknown field {v}")
            node = ("field", v)
        while True:
            k2, v2 = self.peek()
            if k2 == "star":
                self.take()
                node = ("star", node)
            elif v2 == "[":
                self.take()
                _, key = self.take()
                self.take("]")
                node = ("index", node, key)
            else:
                return node

    def value_or_str(self):
        if self.peek()[0] == "str":
            return ("lit", self.take()[1])
        return self.value()

    def eval(self, req):
        return bool(self.ev(self.ast, req))

    def ev(self, n, req):
        kind = n[0]
        if kind == "or":
            return self.ev(n[1], req) or self.ev(n[2], req)
        if kind == "and":
            return self.ev(n[1], req) and self.ev(n[2], req)
        if kind == "not":
            return not self.ev(n[1], req)
        if kind == "lit":
            return n[1]
        if kind == "field":
            f = n[1]
            if f == "http.user_agent":
                return header(req, "user-agent") or ""
            if f == "http.request.uri":
                return req["path"] + ("?" + req["query"] if req["query"] else "")
            if f == "http.request.headers.names":
                return [k for k, _ in req["headers"]]
            if f == "http.request.headers":
                d = {}
                for k, v in req["headers"]:
                    d.setdefault(k.lower(), []).append(v)
                return d
            if f == "http.request.body.raw":
                return req["body"]
            if f == "ip.src":
                return req["ip"]
        if kind == "index":
            return self.ev(n[1], req).get(n[2], [])
        if kind == "star":
            return list(self.ev(n[1], req))
        if kind == "call":
            name, args = n[1], n[2]
            if name == "lower":
                v = self.ev(args[0], req)
                return [x.lower() for x in v] if isinstance(v, list) else v.lower()
            if name == "starts_with":
                return self.ev(args[0], req).startswith(self.ev(args[1], req))
            if name == "any":
                v = self.ev(args[0], req)
                return any(v) if isinstance(v, list) else bool(v)
        if kind == "bool":
            return self.ev(n[1], req)
        if kind in ("contains", "==", "in"):
            left = self.ev(n[1], req)
            if kind == "in":
                ip = ipaddress.ip_address(left)
                return any(ip in ipaddress.ip_network(x) for x in self.lists[n[2][1:]] if ipaddress.ip_network(x).version == ip.version)
            op = (lambda a: n[2] in a) if kind == "contains" else (lambda a: a == n[2])
            return [op(x) for x in left] if isinstance(left, list) else op(left)
        raise ValueError(n)


def load_cloudflare():
    lists = {"td_agentic_attack_ips": {i["ip"] for i in json.loads((WAF / "cloudflare" / "ip-list.json").read_text())}}
    rules = json.loads((WAF / "cloudflare" / "rules.json").read_text())
    out = []
    for r in rules:
        try:
            out.append((r["ref"][3:].replace("_", "-"), CF(r["expression"], lists)))
        except SyntaxError as e:
            fail(f"cloudflare {r['ref']}: {e}")
    return rules, out


# ---------------------------------------------------------------- AWS WAF

def aws_transform(s, tts):
    for t in sorted(tts, key=lambda t: t["Priority"]):
        s = {"NONE": s, "LOWERCASE": s.lower(), "URL_DECODE": unquote(s)}[t["Type"]]
    return s


def aws_eval(stmt, req, sets):
    if "OrStatement" in stmt:
        return any(aws_eval(s, req, sets) for s in stmt["OrStatement"]["Statements"])
    if "IPSetReferenceStatement" in stmt:
        nets = sets[stmt["IPSetReferenceStatement"]["ARN"]]
        ip = ipaddress.ip_address(req["ip"])
        return any(ip in n for n in nets if n.version == ip.version)
    r = stmt["RegexMatchStatement"]
    f = r["FieldToMatch"]
    if "SingleHeader" in f:
        targets = [header(req, f["SingleHeader"]["Name"])]
    elif "UriPath" in f:
        targets = [req["path"]]
    elif "QueryString" in f:
        targets = [req["query"]]
    elif "Body" in f:
        targets = [req["body"]]
    elif "Headers" in f:
        assert f["Headers"]["MatchScope"] == "KEY"
        targets = [k for k, _ in req["headers"]]
    else:
        raise ValueError(f)
    rx = re.compile(r["RegexString"])
    return any(t is not None and rx.search(aws_transform(t, r["TextTransformations"])) for t in targets)


def load_aws():
    group = json.loads((WAF / "aws" / "rule-group.json").read_text())
    sets = {}
    for v in (4, 6):
        s = json.loads((WAF / "aws" / f"ip-set-ipv{v}.json").read_text())
        sets["${TD_AGENTIC_IPV%d_SET_ARN}" % v] = [ipaddress.ip_network(a) for a in s["Addresses"]]
    return group, sets


# ---------------------------------------------------------------- Azure WAF

def az_transform(s, tf):
    for t in tf:
        s = {"Lowercase": s.lower(), "UrlDecode": unquote(s)}[t]
    return s


def az_value(req, var, sel):
    if var in ("RequestHeaders", "RequestHeader"):
        return header(req, sel)
    if var == "RequestUri":
        return req["path"] + ("?" + req["query"] if req["query"] else "")
    if var == "QueryString":
        return req["query"]
    if var == "RequestBody":
        return req["body"]
    if var == "RemoteAddr":
        return req["ip"]
    raise ValueError(var)


def az_cond(c, req):
    if "matchVariables" in c:
        mv = c["matchVariables"][0]
        var, sel, values = mv["variableName"], mv.get("selector"), c["matchValues"]
    else:
        var, sel, values = c["matchVariable"], c.get("selector"), c["matchValue"]
    val = az_value(req, var, sel)
    if val is None:
        return False
    op = c["operator"]
    if op == "IPMatch":
        ip = ipaddress.ip_address(val)
        return any(ip in ipaddress.ip_network(v) for v in values if ipaddress.ip_network(v).version == ip.version)
    val = az_transform(val, c.get("transforms", []))
    if op == "Contains":
        return any(v in val for v in values)
    if op == "BeginsWith":
        return any(val.startswith(v) for v in values)
    if op in ("Regex", "RegEx"):
        return any(re.search(v, val) for v in values)
    raise ValueError(op)


def load_azure():
    return {k: json.loads((WAF / "azure" / f"{k}-custom-rules.json").read_text()) for k in ("appgw", "frontdoor")}


# ---------------------------------------------------------------- evaluation across platforms

CF_RULES, CF_COMPILED = load_cloudflare()
AWS_GROUP, AWS_SETS = load_aws()
AZURE = load_azure()
AZ_GROUP_OF = {}
for kind, rules in AZURE.items():
    for r in rules:
        m = re.match(r"Td([A-Za-z]+?)\d*$", r["name"])
        AZ_GROUP_OF[(kind, r["name"])] = next(g for g in GROUPS if "Td" + "".join(p.capitalize() for p in g.split("-")) == "Td" + m.group(1))


def fired(req):
    """Groups that fire on each platform."""
    return {
        "cloudflare": {gid for gid, c in CF_COMPILED if c.eval(req)},
        "aws": {r["Name"][3:] for r in AWS_GROUP["Rules"] if aws_eval(r["Statement"], req, AWS_SETS)},
        **{kind: {AZ_GROUP_OF[(kind, r["name"])] for r in rules if all(az_cond(c, req) for c in r["matchConditions"])}
           for kind, rules in AZURE.items()},
    }


def expect(name, req, groups, skip=()):
    for platform, got in fired(req).items():
        if platform in skip:
            continue
        if got != set(groups):
            fail(f"{name} [{platform}]: expected {sorted(groups)}, got {sorted(got)}")


def place(m, value):
    f = m["field"]
    if f == "user_agent":
        return request(ua=value)
    if f == "uri":
        return request(path="/index.php", query="q=" + value)
    if f == "authorization":
        return request(headers={"Authorization": "Bearer " + value})
    if f == "header_name":
        return request(headers={value.upper() if value.startswith("x-") else value: "1"})
    if f == "body":
        return request(method="POST", body="cmd=echo+" + value)
    raise ValueError(f)


def signature_cases():
    n = 0
    for g in SPEC["groups"]:
        for m in g["matchers"]:
            if m["field"] == "ip":
                for a in json.loads((WAF / "cloudflare" / "ip-list.json").read_text()):
                    skip = ("appgw",) if ":" in a["ip"] else ()
                    ip = str(next(iter(ipaddress.ip_network(a["ip"]).hosts()), ipaddress.ip_network(a["ip"]).network_address))
                    expect(f"{g['id']} address {a['ip']}", request(ip=ip), [g["id"]], skip)
                    n += 1
                continue
            for v in m["values"]:
                variants = [v]
                if m.get("nocase"):
                    variants.append(v.upper())
                if m["field"] == "uri" and "%" not in v:
                    variants.append(quote(v, safe="/-_.~=&"))
                for x in dict.fromkeys(variants):
                    req = place(m, x)
                    if m.get("op") == "starts_with":
                        req = place(m, x + "1.0")
                    expect(f"{g['id']} value {x!r}", req, [g["id"]])
                    n += 1
                if not m.get("nocase") and m["field"] != "header_name" and v.lower() != v:
                    expect(f"{g['id']} wrong case {v.lower()!r}", place(m, v.lower()), [])
                    n += 1
    return n


def yaml_cases():
    cases = yaml.safe_load((ROOT / "tests" / "waf" / "requests.yaml").read_text())
    for c in cases:
        req = request(path=c.get("path", "/"), query=c.get("query", ""), ua=c.get("ua", BROWSER),
                      headers=c.get("headers"), body=c.get("body", ""), ip=c.get("ip", CLEAN_IP), method=c.get("method", "GET"))
        expect(c["name"], req, c.get("expect", []), c.get("skip", []))
    return len(cases)


def parse_http(raw):
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, target, _ = lines[0].split(" ", 2)
    path, _, query = target.partition("?")
    headers = [tuple(x.split(": ", 1)) for x in lines[1:] if ": " in x]
    return {"method": method, "path": path, "query": query, "headers": headers, "body": body.decode("latin-1"), "ip": CLEAN_IP}


def suricata_cases():
    sys.path.insert(0, str(ROOT / "tests" / "suricata"))
    try:
        import run_tests as suri
    except ImportError as e:
        print(f"skip Suricata replay: {e}")
        return 0
    with tempfile.TemporaryDirectory() as work:
        try:
            suri.define_cases(work)
        except (FileNotFoundError, OSError) as e:
            print(f"skip Suricata replay: {e}")
            return 0
    sid_group = {sid: g["id"] for g in SPEC["groups"] for sid in g.get("suricata", [])}
    block = {g["id"] for g in SPEC["groups"] if g["tier"] == "block"}
    n = 0
    for c in suri.CASES:
        if not c["request"] or not re.match(rb"^[A-Z]+ \S+ HTTP/1\.[01]\r\n", c["request"]):
            continue
        req = parse_http(c["request"])
        want = {sid_group[s] for s in c["expect"] if s in sid_group}
        for platform, got in fired(req).items():
            if want - got:
                fail(f"suricata case {c['name']!r} [{platform}]: SIDs {c['expect']} fire, WAF misses {sorted(want - got)}")
            if not c["expect"] and got & block:
                fail(f"suricata near miss {c['name']!r} [{platform}]: fires {sorted(got & block)}")
        n += 1
    return n


# ---------------------------------------------------------------- limits and schemas

def limits():
    if len(CF_RULES) > 100:
        fail("cloudflare: more custom rules than the Business plan allows")
    if sum(r["enabled"] for r in CF_RULES) > 5:
        fail("cloudflare: more than 5 rules on by default, which the Free plan does not fit")
    for r in CF_RULES:
        if len(r["expression"]) > 4096:
            fail(f"cloudflare {r['ref']}: expression is {len(r['expression'])} characters, limit 4096")
        if r["action"] not in ("block", "managed_challenge", "js_challenge", "challenge", "log"):
            fail(f"cloudflare {r['ref']}: unknown action {r['action']}")
        if "ip.src" in r["expression"] and r["action"] == "block":
            fail(f"cloudflare {r['ref']}: addresses must never block by default")
        if "http.request.body" in r["expression"] and r["enabled"]:
            fail(f"cloudflare {r['ref']}: body rules need Enterprise and must ship off")

    sys.path.insert(0, str(ROOT / "tools"))
    import build_waf
    wcu = sum(build_waf.aws_wcu(r["Statement"]) for r in AWS_GROUP["Rules"])
    if wcu > AWS_GROUP["Capacity"]:
        fail(f"aws: rules need about {wcu} WCU, capacity is {AWS_GROUP['Capacity']}")
    if AWS_GROUP["Capacity"] > 1500:
        fail("aws: capacity over the 1,500 WCU a web ACL includes at no extra charge")

    def walk(s):
        if "OrStatement" in s:
            for x in s["OrStatement"]["Statements"]:
                yield from walk(x)
        else:
            yield s
    for r in AWS_GROUP["Rules"]:
        for s in walk(r["Statement"]):
            rx = s.get("RegexMatchStatement", {}).get("RegexString")
            if rx is not None:
                if len(rx) > 200:
                    fail(f"aws {r['Name']}: regex is {len(rx)} characters")
                if "(" in rx.replace("\\(", ""):
                    fail(f"aws {r['Name']}: regex uses grouping, which AWS WAF does not document as supported")
                re.compile(rx)
        if "IPSetReferenceStatement" in json.dumps(r) and "Block" in r["Action"]:
            fail(f"aws {r['Name']}: addresses must never block by default")
    try:
        import botocore.session
        from botocore.validate import ParamValidator
        model = botocore.session.get_session().get_service_model("wafv2")
        checks = [("CreateRuleGroup", AWS_GROUP)] + [("CreateIPSet", json.loads((WAF / "aws" / f"ip-set-ipv{v}.json").read_text())) for v in (4, 6)]
        for op, params in checks:
            report = ParamValidator().validate(params, model.operation_model(op).input_shape)
            if report.has_errors():
                fail(f"aws {op}: {report.generate_report()}")
    except ImportError:
        print("skip wafv2 API model check: botocore is not installed")

    for kind, rules in AZURE.items():
        names = [r["name"] for r in rules]
        if len(set(names)) != len(names):
            fail(f"azure {kind}: duplicate rule names")
        if len(rules) > 100:
            fail(f"azure {kind}: more than 100 custom rules")
        for r in rules:
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{0,127}", r["name"]):
                fail(f"azure {kind} {r['name']}: name must be letters and digits, starting with a letter")
            for c in r["matchConditions"]:
                vals = c.get("matchValues", c.get("matchValue"))
                if c["operator"] != "IPMatch" and len(vals) > 10:
                    fail(f"azure {kind} {r['name']}: {len(vals)} values in one condition")
                if kind == "appgw" and c["operator"] != "IPMatch" and any(re.search(r"[\s'\"]", v) for v in vals):
                    fail(f"azure {kind} {r['name']}: spaces or quotes in match values, which CRS 3.1 and older reject")
                if c["operator"].lower() == "regex":
                    if c["operator"] != ("RegEx" if kind == "frontdoor" else "Regex"):
                        fail(f"azure {kind} {r['name']}: operator is spelled {c['operator']}")
                    for v in vals:
                        re.compile(v)
                if c["operator"] == "IPMatch" and r["action"] == "Block":
                    fail(f"azure {kind} {r['name']}: addresses must never block by default")
        if kind == "frontdoor":
            n_regex = sum(any(c["operator"] == "RegEx" for c in r["matchConditions"]) for r in rules)
            if n_regex > 5:
                fail(f"azure frontdoor: {n_regex} regex rules, a policy allows 5")
        if kind == "appgw":
            arm = json.loads((WAF / "azure" / "appgw-policy.json").read_text())
            base = arm["parameters"]["basePriority"]["defaultValue"]
            if base < 1 or base + len(rules) - 1 > 100:
                fail(f"azure appgw: priorities {base} to {base + len(rules) - 1} fall outside 1 to 100")
            if any(":" in v for r in rules for c in r["matchConditions"] if c["operator"] == "IPMatch" for v in c["matchValues"]):
                fail("azure appgw: IPMatch only takes IPv4")


def main():
    n1 = signature_cases()
    n2 = yaml_cases()
    n3 = suricata_cases()
    limits()
    print(f"{n1} signature checks, {n2} hand-written requests, {n3} Suricata flows replayed, on 4 platforms")
    if failures:
        print(f"{len(failures)} failures")
        sys.exit(1)
    print("all WAF checks passed")


if __name__ == "__main__":
    main()
