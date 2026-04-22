# Cybersecurity Advisory: Continued Exploitation of Apache Log4j Vulnerabilities

**Alert Code:** AA24-107A
**Date Released:** April 16, 2024

## Summary

CISA and partner agencies continue to observe active exploitation of the Apache
Log4j vulnerability (CVE-2021-44228, commonly known as Log4Shell) and its
follow-on variants (CVE-2021-45046, CVE-2021-45105) across federal civilian
executive branch networks and the broader critical infrastructure community.

Threat actors — including ransomware-aligned groups and state-sponsored actors
targeting the energy, water, and manufacturing sectors — continue to scan for
unpatched Log4j instances and use successful exploitation to stage secondary
payloads, including credential theft tooling and in-network reconnaissance
utilities. The vulnerability remains on the CISA Known Exploited
Vulnerabilities (KEV) catalog.

## Technical Details

Log4Shell is an unauthenticated remote code execution vulnerability in the
Apache Log4j 2 library. Affected versions include Log4j 2.0-beta9 through
2.14.1. The vulnerability is triggered when a logged string contains a JNDI
lookup payload, which the library resolves — fetching and executing attacker-
controlled Java bytecode.

Observed post-exploitation behavior includes:
- Deployment of cryptomining binaries
- Installation of reverse shells and Cobalt Strike beacons
- Lateral movement to domain controllers

## Recommended Actions

Organizations are urged to:

1. Upgrade Log4j to 2.17.1 or later.
2. If upgrade is not immediately possible, apply the mitigation flags documented
   in the Apache Log4j security advisory.
3. Search enterprise logs for JNDI exploitation patterns over the last 18 months.
4. Review OT environments specifically — many historians and engineering
   workstations ship with bundled Log4j versions that are not covered by
   standard IT patching programs.

## References

- CVE-2021-44228
- CISA KEV Catalog
- Apache Log4j Security Advisory
