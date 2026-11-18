# AD CS Check

Assesses Active Directory Certificate Services (AD CS) for certificate
templates and Certification Authorities vulnerable to known ESC attack paths.

```bash
ad-kit check adcs
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated) and
    [Certipy](https://github.com/ly4k/Certipy) installed.

## Commands run

ad-kit runs Certipy's [`find`](https://github.com/ly4k/Certipy/wiki/08-%E2%80%90-Command-Reference#find) command to enumerate AD CS and detect ESC attack paths:

```bash
certipy find -u <username>@<domain> -p <password> -dc-ip <dc_ip> -stdout -vuln
```

The supported ESC classes (ESC1, ESC8, ESC15) are documented in Certipy's [Privilege Escalation guide](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation), which covers ESC1 through ESC17.

## What it checks

ad-kit enumerates certificate templates and Certification Authorities and
detects ESC classes. It detects the common ESC classes (ESC1, ESC2, ESC3, ESC4,
ESC6, ESC8, ESC9, ESC10, ESC13, ESC15, ESC16, ESC17) and reports findings for
the supported set of ESC1, ESC8, and ESC15.

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