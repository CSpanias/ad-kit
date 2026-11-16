# NoPAC Check

Check discovered Domain Controllers for NoPAC vulnerability indicators.

```bash
ad-kit check nopac
```

## What it does

Compares PAC and non-PAC TGT responses from each Domain Controller to identify the NoPAC vulnerability (CVE-2021-42278/CVE-2021-42287).

## Findings

| Finding ID | Description |
|------------|-------------|
| NOPAC-001 | Domain Controller vulnerable to NoPAC |