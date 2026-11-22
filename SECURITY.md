# Security

## Reporting a problem in this repository

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**. Please do not open a public issue for these.

Examples of what to report this way:

- An indicator that would make users block or alert on a legitimate, widely used service.
- A rule or query that can be made to hang, crash or exhaust a sensor or SIEM.
- A flaw in the tools under `tools/` or `tests/` that could run untrusted code.
- A secret or private data committed by mistake.

We aim to reply within two working days and to say what we will do and when.

## What is not a security report

A false positive, a missed detection or a broken query is a normal [issue](https://github.com/ThreatDefence/agentic-attack-detections/issues). Use the matching form.

## Using the rules safely

Every rule is experimental until it has run on your own data. Test and baseline before you alert on a rule, and check an address's `review_by` date before you block it: cloud and hosting addresses are reassigned.
