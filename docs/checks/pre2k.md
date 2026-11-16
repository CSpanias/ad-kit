# Pre-Windows 2000 Check

Identify pre-created computer accounts susceptible to the legacy pre-Windows 2000 machine account password convention.

```bash
ad-kit check pre2k
```

## What it does

Checks whether Kerberos authentication can be achieved using predictable default machine account credentials.

## Findings

No specific finding ID — reports accounts found and whether TGT acquisition succeeded.