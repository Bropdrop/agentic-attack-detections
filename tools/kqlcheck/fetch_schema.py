#!/usr/bin/env python3
"""Add tables to tools/kqlcheck/schema.json from Microsoft's Azure Monitor table reference.

    python3 tools/kqlcheck/fetch_schema.py DeviceProcessEvents AWSCloudTrail

Run it when a new hunt uses a table the checker does not know yet. Defender XDR tables also get the Timestamp column
that advanced hunting uses; the reference lists only TimeGenerated.
"""
import json
import re
import sys
import urllib.request
from pathlib import Path

path = Path(__file__).with_name("schema.json")
schema = json.loads(path.read_text(encoding="utf-8"))
for table in sys.argv[1:]:
    url = f"https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/{table.lower()}"
    try:
        page = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"}), timeout=30).read().decode()
    except Exception as exc:  # noqa: BLE001
        print(f"{table}: {exc}")
        continue
    columns = dict(re.findall(r"<tr>\s*<td>([A-Za-z_0-9]+)</td>\s*<td>([a-z]+)</td>", page))
    if not columns:
        print(f"{table}: no column table on {url}")
        continue
    if table.startswith(("Device", "Email", "Identity", "Alert", "CloudAppEvents", "UrlClick")):
        columns["Timestamp"] = "datetime"
    schema["tables"][table] = columns
    print(f"{table}: {len(columns)} columns")
path.write_text(json.dumps(schema, indent=0, separators=(",", ":")), encoding="utf-8")
