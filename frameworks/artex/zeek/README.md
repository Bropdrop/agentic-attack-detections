# Zeek

- `artex/` raises notices for ARTEX user agents, headers, probe markers, placeholder paths, alg:none tokens and console pages served in cleartext. Load it from `local.zeek` with `@load /path/to/artex`.
- `intel/artex.intel` is generated from `iocs/indicators.csv` by `tools/build_feeds.py`. Load it with the Intel framework:

```zeek
@load frameworks/intel/seen
@load frameworks/intel/do_notice
redef Intel::read_files += { "/path/to/frameworks/artex/zeek/intel/artex.intel" };
```

User agents in the intel file are exact matches (Intel::SOFTWARE). The script in `artex/` matches substrings and ignores case where the name is the indicator (`ARTEX-PENTEST/1.0`, `ScopeWeaver/1.0`), so it catches variants the intel file misses. `ARTeX` stays an exact match: its case is the indicator.
