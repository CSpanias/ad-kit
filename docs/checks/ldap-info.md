# LDAP Info Exposure Check

Reviews LDAP attributes for sensitive information accessible to authenticated
users, including account descriptions, informational fields, and password
attributes.

```bash
ad-kit check ldap-info
```

!!! info "Prerequisite"
    Requires a valid Standard User account (authenticated).

## Commands run

ad-kit runs several NetExec modules to collect account attributes:

```bash
nxc ldap <dc_ip> -u <username> -p <password> -M get-desc-users
nxc ldap <dc_ip> -u <username> -p <password> -M get-info-users
nxc ldap <dc_ip> -u <username> -p <password> -M get-userPassword
nxc ldap <dc_ip> -u <username> -p <password> -M get-unixUserPassword
```

The `get-desc-users` command maps to NetExec's
[get user descriptions](https://www.netexec.wiki/ldap-protocol/get-user-descriptions)
module.

## What it checks

ad-kit collects account attributes:

- `get-desc-users` - the `description` attribute.
- `get-info-users` - the informational fields on user objects.
- `get-userPassword` - the `userPassword` attribute.
- `get-unixUserPassword` - the `unixUserPassword` attribute.

Description and info values are checked for whole credential-related terms,
such as password, secret, credential, and token. Generic service names such as
SQL and VPN are not treated as matches. These terms still require review and
can produce false positives. Returned password attributes are also reported.
The console lists affected accounts and attributes without printing their
values; finding evidence and the saved command output retain the details.

## How it works

Administrators sometimes leave operational notes in the `description` and
`info` fields that include passwords, account details, or infrastructure
information. The `userPassword` and `unixUserPassword` attributes can expose
password or hash values to authenticated users depending on the directory
configuration and its access controls. Keyword matches and returned
password-attribute values require review; they do not prove that usable
credentials were exposed.

## Why it matters

Sensitive LDAP information supports credential discovery and shortens the path
from a foothold to further access, particularly where password material is
exposed directly.

## Findings

| Finding ID | Title |
|------------|-------|
| LDAPINFO-001 | Sensitive Information Stored in LDAP Attributes |

The single finding identifies the attributes returned by the check and
provides attribute-specific commentary and recommendations.

## Tooling

- [NetExec](https://github.com/Pennyw0rth/NetExec): used by this check.
- [ldapsearch-ad](https://github.com/yaap7/ldapsearch-ad): LDAP enumeration.

## References

- [MITRE ATT&CK T1087: Account Discovery](https://attack.mitre.org/techniques/T1087/)
- [MITRE ATT&CK T1552.001: Credentials in Files](https://attack.mitre.org/techniques/T1552/001/)
- [Microsoft: Active Directory Domain Services](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/)