# LDAP Info Exposure Check

Review LDAP attributes for potentially sensitive information exposure.

```bash
ad-kit check ldap-info
```

## What it does

Scans user description, info, userPassword, and unixUserPassword attributes for sensitive keywords (password, secret, credential, token, VPN, SSH, RDP, SQL, etc.).

## Findings

| Finding ID | Description |
|------------|-------------|
| LDAPINFO-001 | User attributes containing sensitive information |
| LDAPINFO-002 | User attributes containing password values |