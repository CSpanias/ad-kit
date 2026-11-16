# AS-REP Roasting Check

Identify accounts susceptible to AS-REP roasting attacks and check privileged group membership.

```bash
ad-kit check asreproast
```

## What it does

1. Enumerates accounts without Kerberos pre-authentication (AS-REP roastable)
2. If matches are found, prompts for Standard User credentials
3. Checks roastable accounts for privileged group membership

## Findings

| Finding ID | Description |
|------------|-------------|
| ASREP-001 | AS-REP roastable accounts identified |
| ASREP-002 | Privileged AS-REP roastable accounts identified |

Requires a filtered domain user list from `ad-kit enum`.