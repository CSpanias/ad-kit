# DNS Check

Check whether authenticated users can create DNS records within AD-integrated DNS zones.

```bash
ad-kit check dns
```

## What it does

Creates and removes a temporary DNS record to verify whether standard domain users possess sufficient permissions to modify DNS data.

## Findings

| Finding ID | Description |
|------------|-------------|
| DNS-001 | Authenticated users can create ADIDNS DNS records |

Requires `bloodyAD` to be installed.