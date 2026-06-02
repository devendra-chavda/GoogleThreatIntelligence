# ASimAlertEventGoogleThreatIntelligence

**Title:** Alert Event ASIM parser for Google Threat Intelligence

**Schema:** AlertEvent (v0.1)

**Vendor:** Google

**Product:** Google Threat Intelligence

**Source Table:** RelevanceSystemAlerts_CL

## Description

This is the **parameter-less** ASIM parser for Google Threat Intelligence alert logs.
It normalizes all records from `RelevanceSystemAlerts_CL` to the ASIM AlertEvent schema
without applying any pre-filtering. Use `vimAlertEventGoogleThreatIntelligence` for
filtered queries via the unifying `imAlertEvent` parser.

## References

- [ASIM AlertEvent Schema](https://aka.ms/ASimAlertEventDoc)
- [ASIM Overview](https://aka.ms/AboutASIM)
