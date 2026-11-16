# SMB Check

Check SMB configuration, anonymous access, and writable shares across discovered systems.

```bash
ad-kit check smb
```

## What it checks

- SMB signing (enabled/disabled)
- SMBv1 protocol (enabled/disabled)
- Null authentication (anonymous SMB access)
- Anonymous share enumeration
- Anonymous user (SAMR) enumeration
- Standard User write access to shares

## Findings

| Finding ID | Description |
|------------|-------------|
| SMB-001 | SMB signing disabled |
| SMB-002 | SMBv1 enabled |
| SMB-003 | Anonymous shares enumerated |
| SMB-004 | Standard User write access to shares |