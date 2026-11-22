## What this changes

<!-- One or two sentences. -->

## Source

<!-- Where each new signature string or indicator comes from: the framework's code (commit, file, line) or a published report (link). -->

## Checks

- [ ] `python3 tools/build_feeds.py` and `python3 tools/convert.py` ran, and everything they regenerated is committed
- [ ] `python3 tools/validate.py` passes
- [ ] `python3 tests/suricata/run_tests.py` passes, with a case and a near miss for each new Suricata rule
- [ ] No customer data, real user names, internal host names or internal addresses
