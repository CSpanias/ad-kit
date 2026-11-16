# Privileged Groups Check

Review privileged group membership, DCSync rights, and built-in account status.

```bash
ad-kit check privileged
```

## What it does

- Evaluates membership of selected privileged AD groups
- Checks built-in Administrator and Guest account status
- Identifies non-default DCSync replication rights

## Findings

| Finding ID | Description |
|------------|-------------|
| PRIV-001 | Excessive privileged group membership (>10% of enabled users) |
| PRIV-002 | Excessive adminCount=1 accounts (>25% of enabled users) |
| PRIV-003 | Built-in Guest account enabled |
| PRIV-004 | Built-in Administrator account enabled |
| PRIV-005 | Non-default trustee with DCSync rights |