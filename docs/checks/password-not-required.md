# Password Not Required Check

Identify enabled accounts with the PASSWD_NOTREQD flag set.

```bash
ad-kit check password-not-required
```

## What it does

Identifies enabled accounts where the PASSWD_NOTREQD user account control flag is set, meaning no password is required.

## Findings

| Finding ID | Description |
|------------|-------------|
| PASS-002 | Enabled accounts with PASSWD_NOTREQD flag set |