RESOURCE = 'Resource'
RESOURCE_FACTORY = 'ResourceFactory'
ENUMERATION = 'Enumeration'
ACCOUNT_MANAGEMENT = 'AccountManagement'
TOPOLOGY_MANAGEMENT = 'TopologyManagement'

OPERATIONAL_ATTRIBUTES = {
    "rootDomainNamingContext",
    "namingContexts",
    "defaultNamingContext",
    "schemaNamingContext",
    "configurationNamingContext",
    "dnsHostName",
    "ldapServiceName",
    "supportedLDAPVersion",
    "supportedControl",
    "supportedCapabilities",
    "supportedSASLMechanisms",
    "domainControllerFunctionality",
    "forestFunctionality",
    "domainFunctionality",
    "highestCommittedUSN",
    "isSynchronized",
    "isGlobalCatalogReady",
    "currentTime"
}

COMMON_ATTRIBUTES = [
    "objectClass",
    "objectGUID",
    "objectSid",
    "sAMAccountName",
    "dnsHostName",
    "servicePrincipalName",
    "userPrincipalName",
    "memberOf",
    "member",
    "distinguishedName",
]

from .core.server import Server
from .core.connection import Connection
