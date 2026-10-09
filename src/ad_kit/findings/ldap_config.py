"""
LDAP configuration findings.

This module contains finding definitions relating to
LDAP signing and LDAP channel binding controls within
Active Directory environments.
"""

from ad_kit.core.finding import Finding


LDAP_SIGNING_NOT_ENFORCED = Finding(
    id="LDAP-001",
    title="LDAP Signing Not Enforced",
    severity="Medium",
    description=(
        "The domain does not enforce LDAP signing. LDAP signing "
        "provides integrity protection for LDAP communications and "
        "helps prevent tampering and relay attacks."
    ),
    impact=(
        "An attacker may be able to relay or manipulate LDAP "
        "authentication traffic. This weakness can increase the "
        "risk of credential theft, privilege escalation, and "
        "Active Directory compromise."
    ),
    recommendation=(
        "Configure the 'Domain Controller: LDAP Server Signing "
        "Requirements' policy to 'Require Signing' on all Domain "
        "Controllers. Verify that all directory-integrated "
        "applications support LDAP signing before enforcing the "
        "setting."
    ),
    affected_assets=[],
    evidence=[],
)


LDAP_CHANNEL_BINDING_NOT_ENFORCED = Finding(
    id="LDAP-002",
    title="LDAP Channel Binding Not Enforced",
    severity="Low",
    description=(
        "LDAP channel binding is not enforced on Domain Controllers. "
        "Channel binding strengthens the security of LDAP over TLS "
        "connections by binding authentication to the underlying "
        "encrypted session."
    ),
    impact=(
        "Attackers may be able to exploit weaknesses in LDAP over TLS "
        "configurations to facilitate relay-style attacks in certain "
        "environments."
    ),
    recommendation=(
        "Configure the 'Domain Controller: LDAP Server Channel "
        "Binding Token Requirements' policy to 'Always' after "
        "confirming application compatibility."
    ),
    affected_assets=[],
    evidence=[],
)