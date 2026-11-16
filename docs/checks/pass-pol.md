# Password Policy Check

Execute domain password policy checks against the AD-Kit baseline.

```bash
ad-kit check pass-pol
```

## What it does

Retrieves the domain password policy and assesses each setting against baseline values.

## Baseline

| Setting | Baseline |
|---------|----------|
| Minimum length | 12 characters |
| Password history | 2 |
| Minimum age | 1 day |
| Maximum age | Set (not "not set") |
| Complexity | Enabled |
| Observation window | >= 15 minutes |
| Lockout duration | >= 30 minutes |
| Lockout threshold | 1-10 |

## Findings

| Finding ID | Description |
|------------|-------------|
| PASS-001 | Password policy setting below baseline |
| PASS-003 | Non-expiring password accounts |
| PASS-002 | PASSWD_NOTREQD accounts |