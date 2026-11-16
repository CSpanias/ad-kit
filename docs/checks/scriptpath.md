# Script Path Check

Review user logon script paths and Standard User write access.

```bash
ad-kit check scriptPath
```

## What it does

Enumerates user `scriptPath` values from LDAP and inspects SMB paths for Standard User write access. Relative paths are resolved against the DC's NETLOGON share.

## Findings

| Finding ID | Description |
|------------|-------------|
| SCRIPT-001 | Standard User has write access to a logon script |