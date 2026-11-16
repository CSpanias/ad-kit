# Local Administrator Check

Review systems where the Standard User has local administrator access.

```bash
ad-kit check local-admin
```

## What it does

Determines whether the configured Standard User account has local administrator privileges on domain-joined systems and Domain Controllers.

## Output

- Number of hosts where the user has local admin access
- Number of Domain Controllers where the user has local admin access

## Findings

Uses PRIV-004 (built-in Administrator enabled) and PRIV-003 (built-in Guest enabled) findings from the privileged check category.