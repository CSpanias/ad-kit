# Machine Account Quota Check

Execute Machine Account Quota assessment checks.

```bash
ad-kit check maq
```

## What it does

Retrieves the domain Machine Account Quota configuration and tests whether authenticated users can create machine accounts.

If quota > 0, attempts to create, authenticate, and delete a test machine account.

## Output

- MachineAccountQuota value
- Whether machine account creation succeeded
- Whether machine account authentication succeeded
- Whether machine account deletion succeeded
- Cleanup method (Standard User or Domain Admin Required)