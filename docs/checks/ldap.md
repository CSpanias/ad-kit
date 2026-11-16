# LDAP Check

Evaluate LDAP signing, channel binding enforcement, and anonymous LDAP bind configuration across all discovered Domain Controllers.

```bash
ad-kit check ldap
```

## What it checks

| Setting | Secure | Finding |
|---------|--------|---------|
| LDAP Signing | Required | LDAP-001 |
| Channel Binding | Enforced | LDAP-002 |
| Anonymous Bind | Disabled | LDAP-003 |

## Output

Displays a table with one row per Domain Controller showing signing status, channel binding status, and anonymous bind status. Generates findings for any insecure configurations.

## Example

```text
[LDAP Checks]

┏━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ DC                        ┃ LDAP Signing ┃ Channel Binding ┃ Anonymous Bind ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ DC01.DOMAIN.LOCAL         │ enforced     │ ✗ Not Enforced  │ ✓ Disabled     │
└───────────────────────────┴──────────────┴─────────────────┴────────────────┘
```