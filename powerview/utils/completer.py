import os
import re
import shlex
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

COMMANDS = {
    'Clear-Cache':[''],
    'Login-As':['-Username','-Password','-Domain','-Hash'],
    'Get-Domain':['-Identity','-Properties', '-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetDomain':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'ConvertFrom-SID':['-ObjectSID','-Server', '-Outfile', '-NoCache'],
    'ConvertFrom-UACValue':['-Value','-TableView','-Outfile'],
    'Get-DomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetDomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainDNSZone':['-Identity','-Properties','-SearchBase','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainDNSRecord':['-ZoneName','-Identity','-Properties','-SearchBase','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainCA':['-CheckWebEnrollment','-SearchBase','-Properties','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-CA':['-CheckWebEnrollment','-SearchBase','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainSCCM':['-Identity','-CheckDatalib','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-SCCM':['-Identity','-CheckDatalib','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainGMSA':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-GMSA':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainRBCD':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-RBCD':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainCATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties', '-NoCache', '-NoVulnCheck','-SearchBase','-Server','-Select','-Where', '-TableView', '-SortBy', '-Count', '-NoWrap', '-OutFile', '-Raw'],
    'Get-CATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties', '-NoCache', '-NoVulnCheck','-SearchBase','-Server','-Select', '-Where', '-TableView', '-SortBy', '-Count', '-NoWrap', '-OutFile', '-Raw'],
    'Add-DomainCATemplate':['-DisplayName','-Name','-Duplicate','-Server','-NoWrap'],
    'Add-CATemplate':['-DisplayName','-Name','-Duplicate','-Server','-NoWrap'],
    'Add-NetService':['-Computer','-Name','-DisplayName','-Path','-Password','-ServiceType','-StartType','-ErrorControl','-ServiceStartName'],
    'Get-DomainGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainGPOLocalGroup':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-GPOLocalGroup':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainGPOSettings':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-GPOSettings':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Server','-Select','-GPLink', '-ResolveGPLink', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Server','-Select','-GPLink', '-ResolveGPLink', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainGroupMember':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetGroupmember':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainForeignGroupMember':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Find-ForeignGroup':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainForeignUser':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Find-ForeignUser':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainTrust':['-Identity','-Properties','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetTrust':['-Identity','-Properties','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainTrustKey':['-Identity','-Properties','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-TrustKey':['-Identity','-Properties','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-Enabled','-Disabled','-RBCD', '-ShadowCred', '-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-Lockout','-PassExpired','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-RBCD','-ShadowCred','-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-Lockout','-PassExpired','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-LocalUser':['-Computer','-ComputerName', '-Identity', '-Properties', '-Select','-Enabled','-Disabled', '-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NamedPipes':['-Name','-Computer','-ComputerName', '-Timeout', '-MaxThreads', '-Server', '-NoWrap', '-Count', '-TableView', '-OutFile'],
    'Get-NetShare':['-Computer','-ComputerName','-TableView','-Server', '-NoWrap', '-Count', '-OutFile'],
    'Get-NetSession':['-Computer','-ComputerName','-Username','-Password','-Hash','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetComputerInfo':['-Computer','-ComputerName','-Username','-Password','-Hash','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetLoggedOn':['-Computer','-ComputerName','-Username','-Password','-Hash','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-RegLoggedOn':['-Computer','-ComputerName','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetService':['-Name','-Computer','-ComputerName','-IsRunning','-IsStopped','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Find-LocalAdminAccess':['-Computer','-ComputerName','-Username','-Password','-Hash','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Invoke-ASREPRoast':['-Identity', '-SearchBase', '-NoCache', '-Server', '-Select', '-NoWrap', '-OutFile', '-TableView', '-SortBy', '-NoCache'],
    'Invoke-Kerberoast':['-Identity', '-Opsec','-LDAPFilter','-Server', '-Select', '-NoWrap', '-OutFile', '-TableView', '-SortBy', '-NoCache'],
    'Invoke-PrinterBug':['-Target', '-Listener', '-Port', '-Server', '-OutFile', '-TableView', '-Select', '-Where', '-SortBy', '-Count', '-NoWrap'],
    'Invoke-DFSCoerce':['-Target', '-Listener', '-Port', '-Server', '-OutFile', '-TableView', '-Select', '-Where', '-SortBy', '-Count', '-NoWrap'],
    'Get-ExchangeServer':['-Identity','-Properties','-LDAPFilter','-SearchBase','-TableView', '-SortBy','-Server','-Select','-Count','-NoWrap','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-ExchangeMailbox':['-Identity','-Properties','-LDAPFilter','-SearchBase','-TableView', '-SortBy','-Server','-Select','-Count','-NoWrap','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-ExchangeDatabase':['-Identity','-Properties','-LDAPFilter','-SearchBase','-TableView', '-SortBy','-Server','-Select','-Count','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Unlock-ADAccount':['-Identity','-SearchBase', '-Server', '-Outfile'],
    'Get-DomainObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-NoCache', '-NoVulnCheck', '-TableView', '-SortBy','-OutFile', '-Raw'],
    'Get-ADObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-Raw'],
    'Remove-DomainObject':['-Identity','-SearchBase','-Server','-OutFile'],
    'Remove-ADObject':['-Identity','-SearchBase','-Server','-OutFile'],
    'Remove-NetService':['-Computer','-Name'],
    'Get-DomainObjectOwner':['-Identity','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-ObjectOwner':['-Identity','-ResolveSID','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainObjectAcl':['-Identity','-SearchBase','-Server','-SecurityIdentifier','-ResolveGUIDs','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-ObjectAcl':['-Identity','-SearchBase','-Server','-ResolveGUIDs','-SecurityIdentifier','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-DomainComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Server','-Select','-Enabled','-Disabled','-Unconstrained','-TrustedToAuth', '-LAPS', '-BitLocker', '-RBCD', '-ShadowCred','-SPN','-GMSAPassword','-Pre2K','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Get-NetComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Server','-Select','-Enabled','-Disabled','-Unconstrained','-TrustedToAuth', '-LAPS', '-BitLocker', '-RBCD', '-ShadowCred','-SPN','-GMSAPassword','-Pre2K','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile', '-NoCache', '-NoVulnCheck', '-Raw'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass','-BaseDN','-Server', '-OutFile'],
    'Add-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Server', '-OutFile'],
    'Add-ADComputer':['-ComputerName','-ComputerPass','-Server', '-OutFile'],
    'Add-DomainUser':['-UserName','-UserPass','-BaseDN','-Server', '-OutFile'],
    'Add-DomainGroup':['-Identity','-BaseDN','-Server', '-OutFile'],
    'Add-ADUser':['-UserName','-UserPass','-BaseDN','-Server', '-OutFile'],
    'Remove-DomainUser':['-Identity','-Server', '-OutFile'],
    'Remove-ADUser':['-Identity','-Server', '-OutFile'],
    'Remove-DomainCATemplate':['-Identity','-Properties','-SearchBase','-Server','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Remove-CATemplate':['-Identity','-Properties','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Remove-DomainComputer':['-ComputerName','-BaseDN','-Server', '-OutFile'],
    'Remove-ADComputer':['-ComputerName','-Server','-OutFile'],
    'Add-DomainGroupMember':['-Identity','-Members','-Server','-OutFile'],
    'Add-GroupMember':['-Identity','-Members','-Server', '-OutFile'],
    'Remove-DomainGroupMember':['-Identity','-Members','-Server', '-OutFile'],
    'Remove-GroupMember':['-Identity','-Members','-Server', '-OutFile'],
    'Add-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity','-Rights','-RightsGUID','-Inheritance','-ACEType','-Server','-OutFile'],
    'Add-ObjectAcl':['-PrincipalIdentity','-TargetIdentity','-Rights','-RightsGUID','-Inheritance','-ACEType','-Server','-OutFile'],
    'Add-DomainOU':['-Identity','-ProtectedFromAccidentalDeletion','-BaseDN','-Server','-OutFile'],
    'Add-OU':['-Identity','-ProtectedFromAccidentalDeletion','-BaseDN','-Server','-OutFile'],
    'Add-DomainGPO':['-Identity','-Description','-LinkTo','-BaseDN','-Server','-OutFile'],
    'Add-GPO':['-Identity','-Description','-ProtectedFromAccidentalDeletion','-BaseDN','-Server','-OutFile'],
    'Remove-DomainOU':['-Identity','-DistinguishedName','-Server','-OutFile'],
    'Remove-OU':['-Identity','-DistinguishedName','-Server','-OutFile'],
    'Remove-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity','-Rights','-RightsGUID','-Inheritance','-ACEType','-Server','-OutFile'],
    'Remove-ObjectAcl':['-PrincipalIdentity','-TargetIdentity','-Rights','-RightsGUID','-Inheritance','-ACEType','-Server','-OutFile'],
    'Set-DomainObject':['-Identity','-Clear','-Set','-Append','-SearchBase','-Server','-OutFile'],
    'Set-ADObject':['-Identity','-Clear','-Set','-Append','-SearchBase','-Server','-OutFile'],
    'Set-DomainObjectDN':['-Identity','-DestinationDN','-SearchBase','-Server','-OutFile'],
    'Set-ADObjectDN':['-Identity','-DistinguishedName','-SearchBase','-Server','-OutFile'],
    'Set-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Server', '-OutFile'],
    'Remove-DomainDNSRecord':['-ZoneName','-RecordName','-Server', '-OutFile'],
    'Disable-DomainDNSRecord':['-ZoneName','-RecordName','-Server', '-OutFile'],
    'Set-DomainCATemplate':['-Identity','-Clear','-Set','-Append','-Server', '-OutFile'],
    'Set-CATemplate':['-Identity','-Clear','-Set','-Append','-Server', '-OutFile'],
    'Add-DomainCATemplateAcl':['-Template','-PrincipalIdentity','-Rights','-Server', '-OutFile'],
    'Add-CATemplateAcl':['-Template','-PrincipalIdentity','-Rights','-Server', '-OutFile'],
    'Set-DomainUserPassword':['-Identity','-AccountPassword', '-OldPassword','-Server','-OutFile'],
    'Set-DomainComputerPassword':['-Identity','-AccountPassword', '-OldPassword','-Server','-OutFile'],
    'Set-DomainRBCD':['-Identity','-DelegateFrom','-SearchBase','-Server','-OutFile'],
    'Set-RBCD':['-Identity','-DelegateFrom','-SearchBase','-Server','-OutFile'],
    'Set-DomainObjectOwner':['-TargetIdentity','-PrincipalIdentity','-SearchBase','-Server','-OutFile'],
    'Set-ObjectOwner':['-TargetIdentity','-PrincipalIdentity','-SearchBase','-Server','-OutFile'],
    'Set-NetService':['-Computer','-Name','-DisplayName','-Path','-Password'],
    'Start-NetService':['-Computer','-Name'],
    'Stop-NetService':['-Computer','-Name'],
    'Add-GPLink':['-GUID','-TargetIdentity','-LinkEnabled','-Enforced','-SearchBase','-Server','-OutFile'],
    'Remove-GPLink':['-GUID','-TargetIdentity','-SearchBase','-Server','-OutFile'],
    'clear':'',
    'exit':'',
}

RE_SPACE = re.compile(r'.*\s+$', re.M)

class Completer(object):

    def _listdir(self, root):
        "List directory 'root' appending the path separator to subdirs."
        res = []
        for name in os.listdir(root):
            path = os.path.join(root, name)
            if os.path.isdir(path):
                name += os.sep
            res.append(name)
        return res

    def _complete_path(self, path=None):
        "Perform completion of filesystem path."
        if not path:
            return self._listdir('.')
        dirname, rest = os.path.split(path)
        tmp = dirname if dirname else '.'
        res = [os.path.join(dirname, p)
                for p in self._listdir(tmp) if p.startswith(rest)]
        # more than one match, or single match which does not exist (typo)
        if len(res) > 1 or not os.path.exists(path):
            return res
        # resolved to a single directory, so return list of files below it
        if os.path.isdir(path):
            return [os.path.join(path, p) for p in self._listdir(path)]
        # exact file match terminates this completion
        return [path + ' ']

    def complete_extra(self, args):
        "Completions for the 'extra' command."
        if not args:
            return self._complete_path('.')
        # treat the last arg as a path and complete it
        return self._complete_path(args[-1])

    def complete(self, text, state):
        buffer = readline.get_line_buffer()
        
        # Handle empty buffer case
        if not buffer.strip():
            return [c + ' ' for c in list(COMMANDS.keys())][state]
        
        try:
            line = shlex.split(buffer)
        except ValueError:
            # Handle unclosed quotes
            line = shlex.split(buffer + '"')
        
        # Add empty token if buffer ends with space
        if RE_SPACE.match(buffer):
            line.append('')
        
        cmd = line[0].strip().casefold()
        
        # Complete command names
        if len(line) == 1:
            results = [c + ' ' for c in list(COMMANDS.keys()) if c.casefold().startswith(cmd)] + [None]
            return results[state]
        
        # Complete command arguments
        if cmd in (c.casefold() for c in COMMANDS.keys()):
            args = line[-1].strip()
            full_cmd = [c for c in list(COMMANDS.keys()) if c.casefold() == cmd][0]
            
            # Filter out flags already used in command
            used_flags = [arg for arg in line if arg.startswith('-')]
            available_flags = [arg for arg in COMMANDS[full_cmd] if arg not in used_flags]
            
            if args.startswith('-') or not args:
                results = [arg + ' ' for arg in available_flags if arg.casefold().startswith(args.casefold())] + [None]
                return results[state]
            
            # Handle file paths for specific arguments that need file completion
            file_related_flags = ['-OutFile']
            prev_arg = line[-2] if len(line) > 1 else None
            
            if prev_arg in file_related_flags:
                return self._complete_path(args)[state]
        
        return None

    def setup_completer(self):
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")
        readline.set_completer(self.complete)
