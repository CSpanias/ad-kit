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

    commentary=(
        "The Domain Controller did not enforce Lightweight "
        "Directory Access Protocol (LDAP) signing, allowing LDAP "
        "communications to occur without integrity protection and "
        "therefore susceptible to Adversary-in-the-Middle (AitM) "
        "attacks.\n\n"

        "Enforcing LDAP signing ensures that all LDAP traffic is "
        "cryptographically signed, preventing tampering and "
        "validating the integrity and authenticity of "
        "communications between clients and Domain Controllers.\n\n"

        "Without signing, an attacker positioned on the network "
        "can intercept LDAP communications between clients and "
        "servers, modify data in transit, and relay "
        "authentication requests to authenticate as legitimate "
        "users.\n\n"

        "This may allow attackers to manipulate LDAP queries, "
        "forge responses, and gain unauthorised access based on "
        "modified or falsified directory data."
    ),

    remediation=(
        "Modify Group Policy so that LDAP signing is required.\n\n"

        "Path:\n"
        "'Computer Configuration\\Windows Settings\\Security "
        "Settings\\Local Policies\\Security Options'\n\n"

        "Configure:\n"
        "'Domain controller: LDAP server signing requirements' "
        "to 'Require signature'.\n\n"

        "Note: Testing should be performed prior to "
        "implementation to confirm that legacy applications "
        "remain compatible."
    ),
)


LDAP_CHANNEL_BINDING_NOT_ENFORCED = Finding(
    id="LDAP-002",
    title="LDAP Channel Binding Not Enforced",
    severity="Low",
    commentary=(
        "LDAP channel binding was not enforced on the Domain "
        "Controller.\n\n"
        "LDAP channel binding ties authentication credentials "
        "to the specific secure channel being used, preventing "
        "credential relay attacks.\n\n"
        "Without LDAP channel binding, an attacker in an "
        "Adversary-in-the-Middle (AitM) position can relay "
        "authentication requests sent over a secure connection "
        "to a Domain Controller over a separate connection.\n\n"
        "Because the Domain Controller does not verify that the "
        "credentials are bound to the original secure channel, "
        "the attacker may be able to successfully authenticate "
        "and gain unauthorised access.\n\n"
        "Enforcing LDAP channel binding ensures that "
        "authentication tokens cannot be relayed across "
        "different connections, effectively preventing this "
        "attack vector."
    ),
    remediation=(
        "Configure LDAP Channel Binding to be enforced as "
        "'Always' (DWORD value: 2).\n\n"
        "If this is not feasible due to compatibility "
        "constraints, configure the setting as "
        "'When Supported' (DWORD value: 1).\n\n"
        "Note: Before making any changes to this configuration, "
        "verify that any legacy systems and third-party "
        "applications support LDAP channel binding to avoid "
        "authentication issues."
    ),
)