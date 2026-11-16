# AD CS Check

Assess Active Directory Certificate Services (AD CS) configurations for known ESC attack paths.

```bash
ad-kit check adcs
```

## What it does

Runs Certipy to enumerate certificate templates and Certification Authorities, identifying known ESC vulnerabilities.

## Supported ESC Classes

ESC1, ESC2, ESC3, ESC4, ESC6, ESC8, ESC9, ESC10, ESC13, ESC15, ESC16, ESC17

## Findings

| Finding ID | Description |
|------------|-------------|
| ADCS-ESC1 | ESC1 vulnerable certificate template |
| ADCS-ESC8 | ESC8 vulnerable Certification Authority |
| ADCS-ESC15 | ESC15 vulnerable certificate template |

Requires `certipy` to be installed.