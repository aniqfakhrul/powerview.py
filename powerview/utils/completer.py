import os
import re
import shlex
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

COMMANDS = {
    'Get-Domain':['-Identity','-Properties', '-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetDomain':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'ConvertFrom-SID':['-ObjectSID','-Server', '-Outfile'],
    'ConvertFrom-UACValue':['-Value','-Server', '-Outfile'],
    'Get-DomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetDomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainDNSZone':['-Identity','-Properties','-SearchBase','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-DomainDNSRecord':['-ZoneName','-Identity','-Properties','-SearchBase','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainCA':['-CheckWebEnrollment','-SearchBase','-Properties','-Server','-Select','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-CA':['-CheckWebEnrollment','-SearchBase','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainSCCM':['-Identity','-CheckDatalib','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-SCCM':['-Identity','-CheckDatalib','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-DomainGMSA':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-GMSA':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-DomainRBCD':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-RBCD':['-Identity','-LDAPFilter','-SearchBase','-Server','-Select','-Where','-Count','-NoWrap','-TableView', '-SortBy','-OutFile'],
    'Get-DomainCATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-SearchBase','-Server','-Select','-Where', '-TableView', '-SortBy', '-Count', '-NoWrap', '-OutFile'],
    'Get-CATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-SearchBase','-Server','-Select', '-Where', '-TableView', '-SortBy', '-Count', '-NoWrap', '-OutFile'],
    'Add-DomainCATemplate':['-DisplayName','-Name','-Duplicate','-Server','-NoWrap'],
    'Add-CATemplate':['-DisplayName','-Name','-Duplicate','-Server','-NoWrap'],
    'Get-DomainGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainGPOLocalGroup':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-GPOLocalGroup':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Server','-Select','-GPLink', '-ResolveGPLink', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Server','-Select','-GPLink', '-ResolveGPLink', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-NetGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-DomainGroupMember':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetGroupmember':['-Identity','-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainForeignGroupMember':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Find-ForeignGroup':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainForeignUser':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Find-ForeignUser':['-LDAPFilter','-Server','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainTrust':['-Identity','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-NetTrust':['-Identity','-Properties','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-RBCD', '-ShadowCred', '-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-LocalUser':['-Computer','-ComputerName', '-Identity', '-Properties', '-Select', '-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select','-RBCD','-ShadowCred','-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NamedPipes':['-Name','-Computer','-ComputerName','-Server', '-NoWrap', '-Count', '-OutFile'],
    'Get-NetShare':['-Computer','-ComputerName','-Server', '-NoWrap', '-Count', '-OutFile'],
    'Get-NetSession':['-Computer','-ComputerName','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetLoggedOn':['-Computer','-ComputerName','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-RegLoggedOn':['-Computer','-ComputerName','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Get-NetService':['-Name','-Computer','-ComputerName','-IsRunning','-IsStopped','-Server', '-Count', '-OutFile', '-TableView', '-SortBy'],
    'Find-LocalAdminAccess':['-Computer','-ComputerName','-Server', '-Count', '-OutFile'],
    'Invoke-Kerberoast':['-Identity', '-Properties', '-Opsec','-LDAPFilter','-Server', '-Select', '-NoWrap', '-OutFile', '-TableView', '-SortBy'],
    'Get-ExchangeServer':['-Identity','-Properties','-LDAPFilter','-SearchBase','-TableView', '-SortBy','-Server','-Select','-Count','-OutFile'],
    'Get-Exchange':['-Identity','-Properties','-LDAPFilter','-SearchBase','-TableView', '-SortBy','-Server','-Select','-Count','-OutFile'],
    'Unlock-ADAccount':['-Identity','-SearchBase', '-Server', '-Outfile'],
    'Get-DomainObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Remove-DomainObject':['-Identity','-SearchBase','-Server','-OutFile'],
    'Remove-ADObject':['-Identity','-SearchBase','-Server','-OutFile'],
    'Get-ADObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-DomainObjectOwner':['-Identity','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-ObjectOwner':['-Identity','-ResolveSID','-SearchBase','-Server','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-SortBy','-OutFile'],
    'Get-DomainObjectAcl':['-Identity','-SearchBase','-Server','-SecurityIdentifier','-ResolveGUIDs','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-OutFile'],
    'Get-ObjectAcl':['-Identity','-SearchBase','-Server','-ResolveGUIDs','-SecurityIdentifier','-Select', '-Where', '-Count', '-NoWrap', '-TableView', '-OutFile'],
    'Get-DomainComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Server','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-BitLocker', '-RBCD', '-ShadowCred','-SPN','-GMSAPassword','-Pre2K','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Get-NetComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Server','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-BitLocker', '-RBCD', '-ShadowCred','-SPN','-GMSAPassword','-Pre2K','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap', '-TableView', '-SortBy', '-OutFile'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass','-BaseDN','-Server', '-OutFile'],
    'Add-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Server', '-OutFile'],
    'Add-ADComputer':['-ComputerName','-ComputerPass','-Server', '-OutFile'],
    'Add-DomainUser':['-UserName','-UserPass','-BaseDN','-Server', '-OutFile'],
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
    'Add-GPLink':['-GUID','-TargetIdentity','-LinkEnabled','-Enforced','-SearchBase','-Server','-OutFile'],
    'Remove-GPLink':['-GUID','-TargetIdentity','-SearchBase','-Server','-OutFile'],
    'clear':'',
    'exit':'',
}

RE_SPACE = re.compile('.*\s+$', re.M)

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
        line = shlex.split(buffer)
        
        if not line:
            return [c + ' ' for c in list(COMMANDS.keys())][state]
        
        if RE_SPACE.match(buffer):
            line.append('')
        
        cmd = line[0].strip().casefold()
        
        if len(line) == 1:
            results = [c + ' ' for c in list(COMMANDS.keys()) if c.casefold().startswith(cmd)] + [None]
            return results[state]
        
        if cmd in (c.casefold() for c in COMMANDS.keys()):
            args = line[-1].strip()
            full_cmd = [c for c in list(COMMANDS.keys()) if c.casefold() == cmd][0]  # Resolve exact case-sensitive match
            
            if len(line) > 1:
                results = [arg + ' ' for arg in COMMANDS[full_cmd] if arg.casefold().startswith(args.casefold()) and arg not in line] + [None]
                return results[state]
        
        return None
