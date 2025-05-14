#!/usr/bin/env python3
import os
import json
import logging
from datetime import datetime

class VulnerabilityDetector:
    def __init__(self, storage):
        self.storage = storage
        self.rules = self._load_vulnerability_rules()
        
    def _load_vulnerability_rules(self):
        """Load vulnerability rules from the vulns.json file"""
        vulns_file = os.path.join(self.storage.root_folder, "vulns.json")
        
        # Check if vulns.json exists, if not, create it with default rules
        if not os.path.exists(vulns_file):
            default_rules = self._get_default_rules()
            os.makedirs(os.path.dirname(vulns_file), exist_ok=True)
            
            with open(vulns_file, 'w') as f:
                json.dump(default_rules, f, indent=4)
            
            logging.debug(f"[VulnerabilityDetector] Created default vulnerability rules at {vulns_file}")
            return default_rules
        
        # Load existing rules
        try:
            with open(vulns_file, 'r') as f:
                rules = json.load(f)
            
            # Compare loaded rules with default rules
            default_rules = self._get_default_rules()
            if rules != default_rules:
                logging.warning(f"[VulnerabilityDetector] Outdated vulnerability rules found in {vulns_file}. Updating with defaults.")
                try:
                    with open(vulns_file, 'w') as f:
                        json.dump(default_rules, f, indent=4)
                    logging.debug(f"[VulnerabilityDetector] Successfully updated vulnerability rules at {vulns_file}")
                    return default_rules
                except Exception as e:
                    logging.error(f"[VulnerabilityDetector] Error writing updated rules to {vulns_file}: {e}")
                    # Fallback to returning the outdated rules if update fails
                    return rules
            else:
                logging.debug(f"[VulnerabilityDetector] Loaded up-to-date vulnerability rules from {vulns_file}")
                return rules

        except Exception as e:
            logging.error(f"[VulnerabilityDetector] Error loading vulnerability rules: {e}")
            # Return default rules if there's an error loading the file
            default_rules = self._get_default_rules()
            # Attempt to write defaults if loading failed
            try:
                with open(vulns_file, 'w') as f:
                    json.dump(default_rules, f, indent=4)
                logging.debug(f"[VulnerabilityDetector] Created default vulnerability rules at {vulns_file} after load error.")
            except Exception as write_e:
                 logging.error(f"[VulnerabilityDetector] Error writing default rules after load error to {vulns_file}: {write_e}")
            return default_rules
    
    def _get_default_rules(self):
        """Return the default vulnerability rules"""
        return {
            "kerberoastable": {
                "description": "Kerberoastable account",
                "rules": [
                    {
                        "attribute": "servicePrincipalName",
                        "condition": "exists"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "computer"
                    },
                    {
                        "attribute": "adminCount",
                        "condition": "equals",
                        "value": 1
                    }
                ],
                "severity": "medium",
                "id": "VULN-001",
                "rule_operator": "AND"
            },
            "kerberoastable_with_high_privilege": {
                "description": "Kerberoastable high privilege account",
                "rules": [
                    {
                        "attribute": "servicePrincipalName",
                        "condition": "exists"
                    },
                    {
                        "attribute": "adminCount",
                        "condition": "equals",
                        "value": 1
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "computer"
                    }
                ],
                "severity": "medium",
                "id": "VULN-001",
                "rule_operator": "AND"
            },
            "password_never_expires": {
                "description": "User account with password that never expires",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "DONT_EXPIRE_PASSWORD"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "sAMAccountName",
                        "condition": "startswith",
                        "value": "MSOL_"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": ["ACCOUNTDISABLE","INTERDOMAIN_TRUST_ACCOUNT"]
                    }
                ],
                "severity": "low",
                "id": "VULN-002",
                "rule_operator": "AND"
            },
            "password_not_required": {
                "description": "User account with password not required",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "PASSWD_NOTREQD"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": ["ACCOUNTDISABLE", "INTERDOMAIN_TRUST_ACCOUNT"]
                    }
                ],
                "severity": "high",
                "id": "VULN-003",
                "rule_operator": "AND"
            },
            "admin_with_reversible_encryption": {
                "description": "Admin account with reversible encryption enabled",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ENCRYPTED_TEXT_PWD_ALLOWED"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-004",
                "rule_operator": "AND"
            },
            "unconstrained_delegation": {
                "description": "Account has unconstrained delegation enabled",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "TRUSTED_FOR_DELEGATION"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-005"
            },
            "old_password": {
                "description": "Account with old password (>90 days)",
                "rules": [
                    {
                        "attribute": "pwdLastSet",
                        "condition": "older_than",
                        "value": 90
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "medium",
                "id": "VULN-006",
                "rule_operator": "AND"
            },
            "inactive_account": {
                "description": "Inactive account (no login >30 days)",
                "rules": [
                    {
                        "attribute": "lastLogon",
                        "condition": "older_than",
                        "value": 30
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "low",
                "id": "VULN-007",
                "rule_operator": "AND"
            },
            "asreproastable": {
                "description": "User account does not require Kerberos preauthentication (vulnerable to ASREPRoast)",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "DONT_REQ_PREAUTH"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-009",
                "rule_operator": "AND"
            },
            "old_computer_operating_system": {
                "description": "Computer with old operating system",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "computer"
                    },
                    {
                        "attribute": "operatingSystem",
                        "condition": "contains",
                        "value": [
                            "Windows 2000", 
                            "Windows XP",
                            "Windows Server 2003",
                            "Windows Vista",
                            "Windows 7",
                            "Windows 8",
                            "Windows 8.1",
                            "Windows Server 2008",
                            "Windows Server 2008 R2",
                            "Windows Server 2012",
                            "Windows Server 2012 R2"
                        ]
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "low",
                "id": "VULN-010",
                "rule_operator": "AND"
            },
            "constrained_delegation": {
                "description": "Account configured for constrained delegation",
                "rules": [
                    {
                        "attribute": "msDS-AllowedToDelegateTo",
                        "condition": "exists"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "medium",
                "id": "VULN-011"
            },
            "resource_based_constrained_delegation": {
                "description": "Account vulnerable to resource-based constrained delegation",
                "rules": [
                    {
                        "attribute": "msDS-AllowedToActOnBehalfOfOtherIdentity",
                        "condition": "exists"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-012"
            },
            "empty_password": {
                "description": "Account with empty password",
                "rules": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "PASSWD_NOTREQD"
                    },
                    {
                        "attribute": "pwdLastSet",
                        "condition": "equals",
                        "value": 0
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "critical",
                "id": "VULN-013",
                "rule_operator": "AND"
            },
            "never_logged_on": {
                "description": "Account that has never logged on",
                "rules": [
                    {
                        "attribute": "lastLogon",
                        "condition": "equals",
                        "value": 0
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "medium",
                "id": "VULN-014"
            },
            "admin_with_plain_text_pw": {
                "description": "Admin account with password stored in reversible encryption",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Administrators"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ENCRYPTED_TEXT_PWD_ALLOWED"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "critical",
                "id": "VULN-015",
                "rule_operator": "AND"
            },
            "domain_controller_auth_policy": {
                "description": "Domain Controller with weak authentication policy",
                "rules": [
                    {
                        "attribute": "primaryGroupID",
                        "condition": "equals",
                        "value": 516
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "SERVER_TRUST_ACCOUNT"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "msDS-SupportedEncryptionTypes",
                        "condition": "contains",
                        "value": "AES256"
                    }
                ],
                "severity": "high",
                "id": "VULN-016",
                "rule_operator": "AND"
            },
            "inactive_admin": {
                "description": "Inactive administrator account",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Domain Admins"
                    },
                    {
                        "attribute": "lastLogon",
                        "condition": "older_than",
                        "value": 30
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    },
                    {
                        "attribute": "sAMAccountName",
                        "condition": "equals",
                        "value": "Administrator"
                    }
                ],
                "severity": "high",
                "id": "VULN-019",
                "rule_operator": "AND",
                "exclusion_operator": "OR"
            },
            "admin_account_delegation": {
                "description": "Admin account with delegation enabled",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Domain Admins"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "NOT_DELEGATED",
                        "negate": True
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-020",
                "rule_operator": "AND"
            },
            "default_krbtgt_password": {
                "description": "KRBTGT account password may never have been changed",
                "rules": [
                    {
                        "attribute": "sAMAccountName",
                        "condition": "equals",
                        "value": "krbtgt"
                    },
                    {
                        "attribute": "pwdLastSet",
                        "condition": "older_than",
                        "value": 180
                    }
                ],
                "exclusions": [],
                "severity": "critical",
                "id": "VULN-021",
                "rule_operator": "AND"
            },
            "rodc_password_replication": {
                "description": "Sensitive account allowed for password replication to RODCs",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Allowed RODC Password Replication Group"
                    },
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Domain Admins"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-022",
                "rule_operator": "AND"
            },
            "dns_zone_transfer_enabled": {
                "description": "DNS zone allows zone transfers to any server",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "dnsZone"
                    },
                    {
                        "attribute": "allowedTransferIPs",
                        "condition": "exists"
                    }
                ],
                "exclusions": [],
                "severity": "medium",
                "id": "VULN-023",
                "rule_operator": "AND"
            },
            "weak_certificate_template": {
                "description": "Certificate template with vulnerable configuration",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "pKICertificateTemplate"
                    },
                    {
                        "attribute": "msPKI-Certificate-Name-Flag",
                        "condition": "equals",
                        "value": 1
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-024",
                "rule_operator": "AND"
            },
            "gpo_with_cpassword": {
                "description": "Group Policy with potential cpassword attribute",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "groupPolicyContainer"
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-025"
            },
            "high_machine_account_quota": {
                "description": "Domain with high machine account quota (allows users to add computer accounts)",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "domain"
                    },
                    {
                        "attribute": "ms-DS-MachineAccountQuota",
                        "condition": "greater_than",
                        "value": 0
                    }
                ],
                "exclusions": [],
                "severity": "medium",
                "id": "VULN-026",
                "rule_operator": "AND"
            },
            "weak_password_policy": {
                "description": "Domain with weak minimum password length policy (less than 8 characters)",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "domainDNS"
                    },
                    {
                        "attribute": "minPwdLength",
                        "condition": "less_than",
                        "value": 8
                    }
                ],
                "exclusions": [],
                "severity": "low",
                "id": "VULN-029",
                "rule_operator": "AND"
            },
            "no_lockout_policy": {
                "description": "Domain without account lockout policy (lockoutThreshold = 0)",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "domainDNS"
                    },
                    {
                        "attribute": "lockoutThreshold",
                        "condition": "equals",
                        "value": 0
                    }
                ],
                "exclusions": [],
                "severity": "medium",
                "id": "VULN-030",
                "rule_operator": "AND"
            },
            "short_password_age": {
                "description": "Domain with short maximum password age policy (less than 30 days)",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "domainDNS"
                    },
                    {
                        "attribute": "maxPwdAge",
                        "condition": "less_than_or_equal",
                        "value": 30
                    },
                    {
                        "attribute": "maxPwdAge",
                        "condition": "not_equals",
                        "value": 0
                    }
                ],
                "exclusions": [],
                "severity": "medium",
                "id": "VULN-031",
                "rule_operator": "AND"
            },
            "user_with_homedir_on_sysvol": {
                "description": "User with home directory on SYSVOL (potentially exposing sensitive files)",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    },
                    {
                        "attribute": "homeDirectory",
                        "condition": "contains",
                        "value": "sysvol"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-034",
                "rule_operator": "AND"
            },
            "inactive_schema_admin": {
                "description": "Inactive Schema Admins account",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Schema Admins"
                    },
                    {
                        "attribute": "lastLogon",
                        "condition": "older_than",
                        "value": 90
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-035",
                "rule_operator": "AND"
            },
            "script_path_in_gpo": {
                "description": "Group Policy Object with script path that may contain malicious code",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "groupPolicyContainer"
                    },
                    {
                        "attribute": "displayName",
                        "condition": "contains",
                        "value": "script"
                    }
                ],
                "exclusions": [],
                "severity": "medium",
                "id": "VULN-036",
                "rule_operator": "AND"
            },
            "weak_service_principal_name": {
                "description": "Service account with weak SPN configuration",
                "rules": [
                    {
                        "attribute": "servicePrincipalName",
                        "condition": "contains",
                        "value": "MSSQL"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "medium",
                "id": "VULN-037",
                "rule_operator": "AND"
            },
            "dnsadmin_privilege_escalation": {
                "description": "User in DnsAdmins group (can be used for privilege escalation)",
                "rules": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "DnsAdmins"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [
                    {
                        "attribute": "memberOf",
                        "condition": "contains",
                        "value": "Domain Admins"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "contains",
                        "value": "ACCOUNTDISABLE"
                    }
                ],
                "severity": "high",
                "id": "VULN-038",
                "rule_operator": "AND",
                "exclusion_operator": "OR"
            },
            "weak_password_complexity": {
                "description": "Domain with password complexity disabled",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "domainDNS"
                    },
                    {
                        "attribute": "pwdProperties",
                        "condition": "missing_flag",
                        "value": 1
                    }
                ],
                "exclusions": [],
                "severity": "critical",
                "id": "VULN-039",
                "rule_operator": "AND"
            },
            "user_password_not_required_and_enabled": {
                "description": "User with PASSWORD_NOT_REQUIRED flag set and account enabled",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "has_flag",
                        "value": 32  # UF_PASSWD_NOTREQD
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "missing_flag",
                        "value": 2  # UF_ACCOUNTDISABLE
                    }
                ],
                "exclusions": [],
                "severity": "critical",
                "id": "VULN-040",
                "rule_operator": "AND"
            },
            "account_with_multiple_risky_flags": {
                "description": "User account with multiple risky UAC configurations",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "any_flag_set",
                        "value": ["PASSWD_NOTREQD", "DONT_EXPIRE_PASSWORD", "PASSWORD_EXPIRED"]
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "missing_flag",
                        "value": "UF_ACCOUNTDISABLE"
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-041",
                "rule_operator": "AND"
            },
            "domain_controller_weak_crypto": {
                "description": "Domain controller with weak cryptography settings",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "computer"
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "has_flag",
                        "value": "UF_SERVER_TRUST_ACCOUNT"
                    },
                    {
                        "attribute": "msDS-SupportedEncryptionTypes",
                        "condition": "missing_flag",
                        "value": "AES256_HMAC_SHA1"
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-042",
                "rule_operator": "AND"
            },
            "inactive_account_with_privileged_groups": {
                "description": "Inactive account with membership in privileged groups",
                "rules": [
                    {
                        "attribute": "lastLogon",
                        "condition": "older_than",
                        "value": 90
                    },
                    {
                        "attribute": "userAccountControl",
                        "condition": "missing_flag",
                        "value": "UF_ACCOUNTDISABLE"
                    },
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "user"
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-043",
                "rule_operator": "AND"
            },
            "sid_history_enabled": {
                "description": "Domain with SID history enabled",
                "rules": [
                    {
                        "attribute": "objectClass",
                        "condition": "contains",
                        "value": "trustedDomain"
                    },
                    {
                        "attribute": "trustAttributes",
                        "condition": "contains",
                        "value": "TREAT_AS_EXTERNAL"
                    }
                ],
                "exclusions": [],
                "severity": "high",
                "id": "VULN-044",
                "rule_operator": "AND"
            }
        }  
    
    def detect_vulnerabilities(self, entry):
        """Detect vulnerabilities in an LDAP entry based on loaded rules"""
        vulnerabilities = []
        
        for rule_name, rule_data in self.rules.items():
            # Check if this entry matches the vulnerability rule(s)
            if not self._check_vulnerability_rules(entry, rule_data):
                continue
            
            # Check exclusions if they exist
            if "exclusions" in rule_data and rule_data["exclusions"]:
                if self._check_vulnerability_exclusions(entry, rule_data):
                    continue
                
            # If we get here, the rule matched and no exclusions applied
            vuln_entry = {
                "name": rule_name,
                "description": rule_data["description"],
                "severity": rule_data["severity"],
                "id": rule_data.get("id", "VULN")
            }
            
            # Add details if they exist
            if "details" in rule_data:
                vuln_entry["details"] = rule_data["details"]
                
            vulnerabilities.append(vuln_entry)
        
        return vulnerabilities if vulnerabilities else None
    
    def _check_vulnerability_rules(self, entry, rule_data):
        """Check if entry matches the vulnerability rules"""
        # Get the rule operator (default to OR)
        rule_operator = rule_data.get("rule_operator", "OR").upper()
        
        # Handle backward compatibility with old format
        if "rule" in rule_data:
            # Convert old format to new format
            old_rule = rule_data["rule"]
            rules = [old_rule]
        else:
            rules = rule_data.get("rules", [])
        
        if not rules:
            return False
        
        results = []
        for rule in rules:
            # Skip if entry doesn't have the attribute needed for the rule
            rule_attribute = rule["attribute"]
            if rule_attribute not in entry:
                if rule_operator == "AND":
                    return False
                results.append(False)
                continue
            
            # Check if the rule condition is met
            rule_matched = self._check_condition(
                entry[rule_attribute], 
                rule["condition"],
                rule.get("value")
            )
            
            # Apply negation if specified
            if rule.get("negate", False):
                rule_matched = not rule_matched
            
            results.append(rule_matched)
            
            # For AND operator, we can short-circuit if any rule fails
            if rule_operator == "AND" and not rule_matched:
                return False
            
            # For OR operator, we can short-circuit if any rule succeeds
            if rule_operator == "OR" and rule_matched:
                return True
        
        # If we got here with AND operator, all rules matched
        if rule_operator == "AND":
            return True
        
        # If we got here with OR operator, no rules matched
        return any(results)
    
    def _check_vulnerability_exclusions(self, entry, rule_data):
        """Check if any exclusion rule applies to this entry"""
        # Handle backward compatibility with old format
        if "exclusion" in rule_data:
            # Convert old format to new format
            old_exclusion = rule_data["exclusion"]
            exclusions = [old_exclusion]
        else:
            exclusions = rule_data.get("exclusions", [])
        
        if not exclusions:
            return False
        
        # Get the exclusion operator (default to OR)
        exclusion_operator = rule_data.get("exclusion_operator", "OR").upper()
        
        results = []
        for exclusion in exclusions:
            exclusion_attribute = exclusion["attribute"]
            
            # If the exclusion attribute doesn't exist, the exclusion doesn't apply
            if exclusion_attribute not in entry:
                results.append(False)
                continue
            
            exclusion_matched = self._check_condition(
                entry[exclusion_attribute],
                exclusion["condition"],
                exclusion.get("value")
            )
            
            results.append(exclusion_matched)
            
            # For OR operator, we can short-circuit if any exclusion applies
            if exclusion_operator == "OR" and exclusion_matched:
                return True
        
        # For OR operator, return true if any exclusion matched
        if exclusion_operator == "OR":
            return any(results)
        
        # For AND operator, return true only if all exclusions matched
        return all(results)
    
    def _check_condition(self, attribute_value, condition, condition_value=None):
        """Check if the attribute value meets the condition"""
        if condition == "exists":
            return attribute_value is not None and attribute_value != []
            
        elif condition == "not_exists":
            return attribute_value is None or attribute_value == []
            
        elif condition == "equals" and condition_value is not None:
            # Handle list of values (OR condition)
            if isinstance(condition_value, list):
                return any(self._check_condition(attribute_value, "equals", val) for val in condition_value)
            
            # Handle pipe-separated values
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return any(self._check_condition(attribute_value, "equals", val) for val in values)
            
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return attribute_value.lower() == condition_value.lower()
            return attribute_value == condition_value
            
        elif condition == "not_equals" and condition_value is not None:
            # Handle list of values (AND condition)
            if isinstance(condition_value, list):
                return all(self._check_condition(attribute_value, "not_equals", val) for val in condition_value)
            
            # Handle pipe-separated values
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return all(self._check_condition(attribute_value, "not_equals", val) for val in values)
            
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return attribute_value.lower() != condition_value.lower()
            return attribute_value != condition_value
            
        elif condition == "contains" and condition_value is not None:
            # Handle list of values (OR condition)
            if isinstance(condition_value, list):
                return any(self._check_condition(attribute_value, "contains", val) for val in condition_value)
            
            # Handle pipe-separated values as OR condition
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return any(self._check_condition(attribute_value, "contains", val) for val in values)
            
            if isinstance(attribute_value, list):
                if isinstance(condition_value, str):
                    condition_value_lower = condition_value.lower()
                    return any(condition_value_lower in str(item).lower() for item in attribute_value)
                return any(condition_value in str(item) for item in attribute_value)
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return condition_value.lower() in attribute_value.lower()
            return condition_value in str(attribute_value)
            
        elif condition == "not_contains" and condition_value is not None:
            # Handle list of values (AND condition)
            if isinstance(condition_value, list):
                return all(self._check_condition(attribute_value, "not_contains", val) for val in condition_value)
            
            # Handle pipe-separated values as OR condition
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return all(self._check_condition(attribute_value, "not_contains", val) for val in values)
            
            if isinstance(attribute_value, list):
                if isinstance(condition_value, str):
                    condition_value_lower = condition_value.lower()
                    return not any(condition_value_lower in str(item).lower() for item in attribute_value)
                return not any(condition_value in str(item) for item in attribute_value)
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return condition_value.lower() not in attribute_value.lower()
            return condition_value not in str(attribute_value)
            
        elif condition == "startswith" and condition_value is not None:
            # Handle list of values (OR condition)
            if isinstance(condition_value, list):
                return any(self._check_condition(attribute_value, "startswith", val) for val in condition_value)
            
            # Handle pipe-separated values as OR condition
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return any(self._check_condition(attribute_value, "startswith", val) for val in values)
            
            if isinstance(attribute_value, list):
                if isinstance(condition_value, str):
                    condition_value_lower = condition_value.lower()
                    return any(str(item).lower().startswith(condition_value_lower) for item in attribute_value)
                return any(str(item).startswith(condition_value) for item in attribute_value)
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return attribute_value.lower().startswith(condition_value.lower())
            return str(attribute_value).startswith(condition_value)
            
        elif condition == "endswith" and condition_value is not None:
            # Handle list of values (OR condition)
            if isinstance(condition_value, list):
                return any(self._check_condition(attribute_value, "endswith", val) for val in condition_value)
            
            # Handle pipe-separated values as OR condition
            if isinstance(condition_value, str) and "|" in condition_value:
                values = [v.strip() for v in condition_value.split("|")]
                return any(self._check_condition(attribute_value, "endswith", val) for val in values)
            
            if isinstance(attribute_value, list):
                if isinstance(condition_value, str):
                    condition_value_lower = condition_value.lower()
                    return any(str(item).lower().endswith(condition_value_lower) for item in attribute_value)
                return any(str(item).endswith(condition_value) for item in attribute_value)
            if isinstance(attribute_value, str) and isinstance(condition_value, str):
                return attribute_value.lower().endswith(condition_value.lower())
            return str(attribute_value).endswith(condition_value)
            
        elif condition == "older_than" and condition_value is not None:
            try:
                if isinstance(attribute_value, datetime):
                    age_days = (datetime.now() - attribute_value).days
                    return age_days > condition_value
                return False
            except:
                return False
                
        elif condition == "newer_than" and condition_value is not None:
            try:
                if isinstance(attribute_value, datetime):
                    age_days = (datetime.now() - attribute_value).days
                    return age_days < condition_value
                return False
            except:
                return False
                
        elif condition == "greater_than" and condition_value is not None:
            try:
                # Convert values to integers for numeric comparison
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                cond_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return attr_val > cond_val
            except (ValueError, TypeError):
                return False
                
        elif condition == "less_than" and condition_value is not None:
            try:
                # Convert values to integers for numeric comparison
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                cond_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return attr_val < cond_val
            except (ValueError, TypeError):
                return False
                
        elif condition == "greater_than_or_equal" and condition_value is not None:
            try:
                # Convert values to integers for numeric comparison
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                cond_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return attr_val >= cond_val
            except (ValueError, TypeError):
                return False
                
        elif condition == "less_than_or_equal" and condition_value is not None:
            try:
                # Convert values to integers for numeric comparison
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                cond_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return attr_val <= cond_val
            except (ValueError, TypeError):
                return False
                
        elif condition == "in_range" and condition_value is not None and isinstance(condition_value, list) and len(condition_value) == 2:
            try:
                # Convert values to integers for numeric comparison
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                min_val = int(condition_value[0]) if not isinstance(condition_value[0], int) else condition_value[0]
                max_val = int(condition_value[1]) if not isinstance(condition_value[1], int) else condition_value[1]
                return min_val <= attr_val <= max_val
            except (ValueError, TypeError, IndexError):
                return False
                
        elif condition == "has_flag" and condition_value is not None:
            try:
                # This checks if a specific bit flag is set in a value
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                flag_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return (attr_val & flag_val) == flag_val
            except (ValueError, TypeError):
                return False
                
        elif condition == "missing_flag" and condition_value is not None:
            try:
                # This checks if a specific bit flag is NOT set in a value
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                flag_val = int(condition_value) if not isinstance(condition_value, int) else condition_value
                return (attr_val & flag_val) == 0
            except (ValueError, TypeError):
                return False
                
        elif condition == "any_flag_set" and condition_value is not None and isinstance(condition_value, list):
            try:
                # Check if any of the specified flags are set
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                for flag in condition_value:
                    flag_val = int(flag) if not isinstance(flag, int) else flag
                    if (attr_val & flag_val) != 0:
                        return True
                return False
            except (ValueError, TypeError):
                return False
                
        elif condition == "all_flags_set" and condition_value is not None and isinstance(condition_value, list):
            try:
                # Check if all of the specified flags are set
                attr_val = int(attribute_value) if not isinstance(attribute_value, int) else attribute_value
                for flag in condition_value:
                    flag_val = int(flag) if not isinstance(flag, int) else flag
                    if (attr_val & flag_val) != flag_val:
                        return False
                return True
            except (ValueError, TypeError):
                return False
                
        return False 