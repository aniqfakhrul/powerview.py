import os
import re
import shlex
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

COMMANDS = {
    'Get-Domain':['-Identity','-Properties', '-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetDomain':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'ConvertFrom-SID':['-ObjectSID','-Domain', '-Outfile'],
    'Get-DomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetDomainController':['-Identity','-ResolveSIDs','-SearchBase','-LDAPFilter','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainDNSZone':['-Identity','-Properties','-SearchBase','-Domain','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainDNSRecord':['-ZoneName','-Identity','-Properties','-SearchBase','-Domain','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainCA':['-CheckWebEnrollment','-Properties','-Domain','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-CA':['-CheckWebEnrollment','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainSCCM':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select','-Where','-Count','-NoWrap','-OutFile'],
    'Get-SCCM':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select','-Where','-Count','-NoWrap','-OutFile'],
    'Get-DomainCATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-SearchBase','-Domain','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-CATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Add-DomainCATemplate':['-DisplayName','-Name','-Duplicate','-Domain','-NoWrap'],
    'Add-CATemplate':['-DisplayName','-Name','-Duplicate','-Domain','-NoWrap'],
    'Get-DomainGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetGPO':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainGPOLocalGroup':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-GPOLocalGroup':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetOU':['-Identity','-Properties','-SearchBase','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetGroup':['-Identity','-Properties','-LDAPFilter','-SearchBase','-MemberIdentity','-AdminCount','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainGroupMember':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-NetGroupmember':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainForeignGroupMember':['-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Find-ForeignGroup':['-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainForeignUser':['-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Find-ForeignUser':['-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainTrust':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetTrust':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select','-RBCD', '-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetUser':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select','-RBCD','-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NamedPipes':['-Name','-Computer','-ComputerName','-Domain', '-NoWrap', '-Count', '-OutFile'],
    'Get-NetShare':['-Computer','-ComputerName','-Domain', '-NoWrap', '-Count', '-OutFile'],
    'Get-NetSession':['-Computer','-ComputerName','-Domain', '-Count', '-OutFile'],
    'Find-LocalAdminAccess':['-Computer','-ComputerName','-Domain', '-Count', '-OutFile'],
    'Invoke-Kerberoast':['-Identity', '-Properties', '-Opsec','-LDAPFilter','-Domain', '-NoWrap','-OutFile'],
    'Get-DomainObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Remove-DomainObject':['-Identity','-SearchBase','-Domain','-OutFile'],
    'Get-ADObject':['-Identity','-Properties','-LDAPFilter','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainObjectOwner':['-Identity','-ResolveSID','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-ObjectOwner':['-Identity','-ResolveSID','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap','-OutFile'],
    'Get-DomainObjectAcl':['-Identity','-SearchBase','-Domain','-SecurityIdentifier','-ResolveGUIDs','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-ObjectAcl':['-Identity','-SearchBase','-Domain','-ResolveGUIDs','-SecurityIdentifier','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-DomainComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-BitLocker', '-RBCD','-SPN','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Get-NetComputer':['-Identity','-Properties','-ResolveIP','-ResolveSIDs','-LDAPFilter','-SearchBase','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS','-RBCD','-SPN','-Printers','-ExcludeDCs', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass','-Domain', '-OutFile'],
    'Add-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Domain', '-OutFile'],
    'Add-ADComputer':['-ComputerName','-ComputerPass','-Domain', '-OutFile'],
    'Add-DomainUser':['-UserName','-UserPass','-BaseDN','-Domain', '-OutFile'],
    'Add-ADUser':['-UserName','-UserPass','-BaseDN','-Domain', '-OutFile'],
    'Remove-DomainUser':['-Identity','-Domain', '-OutFile'],
    'Remove-ADUser':['-Identity','-Domain', '-OutFile'],
    'Remove-DomainCATemplate':['-Identity','-Properties','-SearchBase','-Domain','-Select','-Where', '-Count', '-NoWrap', '-OutFile'],
    'Remove-CATemplate':['-Identity','-Properties','-SearchBase','-Domain','-Select', '-Where', '-Count', '-NoWrap', '-OutFile'],
    'Remove-DomainComputer':['-ComputerName','-Domain', '-OutFile'],
    'Remove-ADComputer':['-ComputerName','-Domain', '-OutFile'],
    'Add-DomainGroupMember':['-Identity','-Members','-Domain', '-OutFile'],
    'Add-GroupMember':['-Identity','-Members','-Domain', '-OutFile'],
    'Remove-DomainGroupMember':['-Identity','-Members','-Domain', '-OutFile'],
    'Remove-GroupMember':['-Identity','-Members','-Domain', '-OutFile'],
    'Add-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain','-OutFile'],
    'Add-ObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain','-OutFile'],
    'Remove-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain', '-OutFile'],
    'Remove-ObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain', '-OutFile'],
    'Set-DomainObject':['-Identity','-Clear','-Set','-Append','-SearchBase','-Domain','-OutFile'],
    'Set-DomainObjectDN':['-Identity','-DistinguishedName','-SearchBase','-Domain','-OutFile'],
    'Set-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Domain', '-OutFile'],
    'Remove-DomainDNSRecord':['-ZoneName','-Identity','-Domain', '-OutFile'],
    'Set-Object':['-Identity','-Clear','-Set','-Append','-SearchBase','-Domain', '-OutFile'],
    'Set-DomainCATemplate':['-Identity','-Clear','-Set','-Append','-Domain', '-OutFile'],
    'Set-CATemplate':['-Identity','-Clear','-Set','-Append','-Domain', '-OutFile'],
    'Add-DomainCATemplateAcl':['-Template','-PrincipalIdentity','-Rights','-Domain', '-OutFile'],
    'Add-CATemplateAcl':['-Template','-PrincipalIdentity','-Rights','-Domain', '-OutFile'],
    'Set-DomainUserPassword':['-Identity','-AccountPassword', '-OldPassword','-Domain','-OutFile'],
    'Set-DomainComputerPassword':['-Identity','-AccountPassword', '-OldPassword','-Domain','-OutFile'],
    'Set-DomainObjectOwner':['-TargetIdentity','-PrincipalIdentity','-SearchBase','-Domain','-OutFile'],
    'Set-ObjectOwner':['-TargetIdentity','-PrincipalIdentity','-SearchBase','-Domain','-OutFile'],
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
        "Generic readline completion entry point."
        buffer = readline.get_line_buffer()
        line = shlex.split(readline.get_line_buffer())
        # show all commands
        if not line:
           return [c + ' ' for c in list(COMMANDS.keys())][state]
        # account for last argument ending in a space
        if RE_SPACE.match(buffer):
            line.append('')

        # resolve command to the implementation function
        cmd = line[0].strip()
        results = [c + ' ' for c in list(COMMANDS.keys()) if c.casefold().startswith(cmd.casefold())] + [None]

        if len(line) > 1:
            for c in list(COMMANDS.keys()):
                if cmd.casefold() == c.casefold():
                    args = line[-1].strip()
                    results = [c + ' ' for c in COMMANDS[c] if c.casefold().startswith(args.casefold()) and c not in line] + [None]
                    return results[state]
        return results[state]
