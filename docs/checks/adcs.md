# AD CS Check

Assesses Active Directory Certificate Services (AD CS) for certificate
templates and Certification Authorities vulnerable to known ESC attack paths.

```bash
ad-kit check adcs
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated) and
    [Certipy](https://github.com/ly4k/Certipy) installed.

## What it checks

ad-kit runs `certipy find ... -vuln` to enumerate certificate templates and
Certification Authorities and detect ESC classes. It detects the common ESC
classes (ESC1, ESC2, ESC3, ESC4, ESC6, ESC8, ESC9, ESC10, ESC13, ESC15, ESC16,
ESC17) and reports findings for the supported set of ESC1, ESC8, and ESC15.

## How it works

AD CS issues digital certificates that are trusted across the domain. A
certificate that can be used for authentication is effectively an alternative
credential, so a misconfigured template or authority can let a low-privileged
user obtain a certificate for another identity.

- **ESC1** - a template allows an enrollee to supply the subject and low
  privileged users can enrol for authentication-capable certificates.
- **ESC8** - HTTP-based certificate enrolment is reachable and vulnerable to
  NTLM relay.
- **ESC15** - a legacy Version 1 template permits enrollee-supplied subject
  information and does not validate Application Policies
  ([`CVE-2024-49019`](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-49019)).

## Why it matters

Abusing a vulnerable template or authority can yield a certificate mapped to a
privileged account, providing impersonation, persistence, lateral movement,
and a path to domain compromise.

## Findings

| Finding ID | Title |
|------------|-------|
| ADCS-ESC1 | Vulnerable Certificate Template (ESC1) |
| ADCS-ESC8 | NTLM Relay to AD CS Web Enrollment (ESC8) |
| ADCS-ESC15 | Vulnerable Certificate Template (ESC15) |

## Tooling

- [Certipy](https://github.com/ly4k/Certipy): used by this check.

## References

- [SpectorOps: Certified Pre-Owned](https://specterops.io/blog/2021/06/17/certified-pre-owned/)
- [Certipy: ESC attack paths](https://github.com/ly4k/Certipy/wiki)
- [MSRC: CVE-2024-49019](https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2024-49019)
- [Pentest Journeys: AD CS](https://x7331.gitbook.io/boxes/tl-dr/active-directory/general/authentication/ad-cs)