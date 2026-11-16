# Kerberoasting Check

Identify accounts susceptible to Kerberoasting attacks (accounts with SPNs).

```bash
ad-kit check kerberoast
```

## What it does

1. Requests Kerberos service tickets for all SPN-associated accounts
2. Checks for privileged group membership on Kerberoastable accounts

## Findings

| Finding ID | Description |
|------------|-------------|
| KERB-001 | Kerberoastable accounts identified |
| KERB-002 | Privileged Kerberoastable accounts identified |