# vimAlertEventGoogleThreatIntelligence

**Title:** Alert Event ASIM filtering parser for Google Threat Intelligence

**Schema:** AlertEvent (v0.1)

**Vendor:** Google

**Product:** Google Threat Intelligence

**Source Table:** RelevanceSystemAlerts_CL

## Description

This ASIM parser supports normalizing and filtering Google Threat Intelligence alert logs
ingested into the `RelevanceSystemAlerts_CL` table to the ASIM AlertEvent normalized schema.

Fields mapped include alert name, severity, verdict, threat category, user context,
relevance analysis scores, and priority analysis reasoning. Rich analysis metadata is
preserved in `AdditionalFields`.

## Filter Parameters

| Parameter | Type | Description |
|---|---|---|
| starttime | datetime | Filter alerts from this time (inclusive) |
| endtime | datetime | Filter alerts to this time (inclusive) |
| username_has_any | dynamic | Filter by alert creator username |
| threatcategory_has_any | dynamic | Filter by derived threat category |
| alertverdict_has_any | dynamic | Filter by alert verdict |
| eventseverity_has_any | dynamic | Filter by event severity |
| disabled | bool | Set to true to disable this parser |

> **Note:** `ipaddr_has_any_prefix`, `hostname_has_any`, `attacktactics_has_any`, and
> `attacktechniques_has_any` are accepted as parameters for schema compatibility but
> are not applied — the Google Threat Intelligence source does not provide IP, hostname,
> or MITRE ATT&CK data in this table.

## References

- [ASIM AlertEvent Schema](https://aka.ms/ASimAlertEventDoc)
- [ASIM Overview](https://aka.ms/AboutASIM)
