# LDAP Info Exposure Check

Reviews LDAP attributes for sensitive information accessible to authenticated
users, including account descriptions, informational fields, and password
attributes.

```bash
ad-kit check ldap-info
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## What it checks

ad-kit runs several NetExec modules to collect account attributes:

- `get-desc-users` - the `description` attribute.
- `get-info-users` - the informational fields on user objects.
- `get-userPassword` - the `userPassword` attribute.
- `get-unixUserPassword` - the `unixUserPassword` attribute.

Values are compared against a list of sensitive keywords (password, secret,
credential, token, VPN, SSH, RDP, SQL, and similar).

## How it works

Administrators sometimes leave operational notes in the `description` and
`info` fields that include passwords, account details, or infrastructure
information. The `userPassword` and `unixUserPassword` attributes can expose
password or hash values to authenticated users depending on the directory
configuration and its access controls.

## Why it matters

Sensitive LDAP information supports credential discovery and shortens the path
from a foothold to further access, particularly where password material is
exposed directly.

## Findings

| Finding ID | Title |
|------------|-------|
| LDAPINFO-001 | Sensitive Information Stored in LDAP Attributes |
| LDAPINFO-002 | Password Data Stored in LDAP Attributes |

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad): LDAP enumeration.

## References

- [MITRE ATT&CK T1087: Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK T1552.001: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Microsoft: Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)