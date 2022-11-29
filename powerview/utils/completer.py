import os
import re
import shlex
from sys import platform
if platform == "linux" or platform == "linux2":
    import gnureadline as readline
else:
    import readline

COMMANDS = {
    'Get-Domain':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetDomain':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'ConvertFrom-SID':['-ObjectSID','-Domain'],
    'Get-DomainController':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetDomainController':['-Identity','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainDNSZone':['-Identity','-Properties','-Domain','-Select','-Where', '-Count', '-NoWrap'],
    'Get-DomainDNSRecord':['-ZoneName','-Identity','-Properties','-Domain','-Select','-Where', '-Count', '-NoWrap'],
    'Get-DomainCA':['-Properties','-Domain','-Select','-Where', '-Count', '-NoWrap'],
    'Get-CA':['-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainCATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-Domain','-Select','-Where', '-Count', '-NoWrap'],
    'Get-CATemplate':['-Identity','-Vulnerable','-Enabled','-ResolveSIDs','-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainGPO':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetGPO':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainGPOLocalGroup':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-GPOLocalGroup':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainOU':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-Count', '-NoWrap'],
    'Get-NetOU':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-Count', '-NoWrap'],
    'Get-DomainGroup':['-Identity','-Properties','-LDAPFilter','-MemberIdentity','-AdminCount','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetGroup':['-Identity','-Properties','-LDAPFilter','-MemberIdentity','-AdminCount','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainGroupMember':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetGroupmember':['-Identity','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainTrust':['-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-NetTrust':['-Properties','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainUser':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-RBCD', '-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap'],
    'Get-NetUser':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-RBCD','-Unconstrained','-PassNotRequired','-PreAuthNotRequired','-AllowDelegation','-DisallowDelegation','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-Count', '-NoWrap'],
    'Get-NamedPipes':['-Name','-Computer','-ComputerName','-Domain', '-NoWrap', '-Count'],
    'Get-Shares':['-Computer','-ComputerName','-Domain', '-NoWrap', '-Count'],
    'Get-NetShares':['-Computer','-ComputerName','-Domain', '-Count'],
    'Find-LocalAdminAccess':['-Computer','-ComputerName','-Domain', '-Count'],
    'Invoke-Kerberoast':['-Identity','-Opsec','-LDAPFilter','-Domain', '-NoWrap'],
    'Get-DomainObject':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-ADObject':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainObjectOwner':['-Identity','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-ObjectOwner':['-Identity','-Domain','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainObjectAcl':['-Identity','-Domain','-SecurityIdentifier','-ResolveGUIDs','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-ObjectAcl':['-Identity','-Domain','-ResolveGUIDs','-SecurityIdentifier','-Select', '-Where', '-Count', '-NoWrap'],
    'Get-DomainComputer':['-Identity','-Properties','-ResolveIP','-LDAPFilter','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS','-RBCD','-SPN','-Printers','-ExcludeDCs','-Where', '-Count', '-NoWrap'],
    'Get-NetComputer':['-Identity','-Properties','-ResolveIP','-LDAPFilter','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS','-RBCD','-SPN','-Printers','-ExcludeDCs', '-Where', '-Count', '-NoWrap'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass','-Domain'],
    'Add-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Domain'],
    'Add-ADComputer':['-ComputerName','-ComputerPass','-Domain'],
    'Add-DomainUser':['-UserName','-UserPass','-BaseDN','-Domain'],
    'Add-ADUser':['-UserName','-UserPass','-BaseDN','-Domain'],
    'Remove-DomainUser':['-Identity','-Domain'],
    'Remove-ADUser':['-Identity','-Domain'],
    'Remove-DomainComputer':['-ComputerName','-Domain'],
    'Remove-ADComputer':['-ComputerName','-Domain'],
    'Add-DomainGroupMember':['-Identity','-Members','-Domain'],
    'Add-GroupMember':['-Identity','-Members','-Domain'],
    'Remove-DomainGroupMember':['-Identity','-Members','-Domain'],
    'Remove-GroupMember':['-Identity','-Members','-Domain'],
    'Add-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain'],
    'Add-ObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain'],
    'Remove-DomainObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain'],
    'Remove-ObjectAcl':['-PrincipalIdentity','-TargetIdentity', '-Rights','-Domain'],
    'Set-DomainObject':['-Identity','-Clear','-Set','-Append','-Domain'],
    'Set-DomainDNSRecord':['-ZoneName','-RecordName','-RecordAddress','-Domain'],
    'Set-Object':['-Identity','-Clear','-Set','-Append','-Domain'],
    'Set-DomainCATemplate':['-Identity','-Clear','-Set','-Append','-Domain'],
    'Set-CATemplate':['-Identity','-Clear','-Set','-Append','-Domain'],
    'Set-DomainUserPassword':['-Identity','-AccountPassword','-Domain'],
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
