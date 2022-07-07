import os
import re
import readline
import shlex

COMMANDS = {
    'Get-Domain':['-Identity','-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-NetDomain':['-Identity','-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'ConvertFrom-SID':['-ObjectSID','-Domain'],
    'Get-DomainController':['-Identity','-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-NetDomainController':['-Identity','-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainDNSZone':['-Properties','-Domain','-Select','-Where', '-NoWrap'],
    'Get-DomainCA':['-Properties','-Domain','-Select','-Where', '-NoWrap'],
    'Get-NetCA':['-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainGPO':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-NetGPO':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainOU':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-NoWrap'],
    'Get-NetOU':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-GPLink', '-Where', '-NoWrap'],
    'Get-DomainGroup':['-Identity','-Properties','-LDAPFilter','-AdminCount','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-NetGroup':['-Identity','-Properties','-LDAPFilter','-AdminCount','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainTrust':['-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-NetTrust':['-Properties','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainUser':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-PreAuthNotRequired','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-NoWrap'],
    'Get-NetUser':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-PreAuthNotRequired','-AdminCount','-TrustedToAuth','-SPN', '-Where', '-NoWrap'],
    'Get-NamedPipes':['-Name','-Computer','-ComputerName','-Domain', '-NoWrap'],
    'Get-Shares':['-Computer','-ComputerName','-Domain', '-NoWrap'],
    'Get-NetShares':['-Computer','-ComputerName','-Domain'],
    'Find-LocalAdminAccess':['-Computer','-ComputerName','-Domain'],
    'Invoke-Kerberoast':['-Identity','-LDAPFilter','-Domain', '-NoWrap'],
    'Get-DomainObject':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-ADObject':['-Identity','-Properties','-LDAPFilter','-Domain','-Select', '-Where', '-NoWrap'],
    'Get-DomainObjectAcl':['-Identity','-Domain','-SecurityIdentifier','-ResolveGUIDs','-Select', '-Where', '-NoWrap'],
    'Get-ObjectAcl':['-Identity','-Domain','-ResolveGUIDs','-SecurityIdentifier','-Select', '-Where', '-NoWrap'],
    'Get-DomainComputer':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-Where', '-NoWrap'],
    'Get-NetComputer':['-Identity','-Properties','-LDAPFilter','-Domain','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-Where', '-NoWrap'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass','-Domain'],
    'Add-ADComputer':['-ComputerName','-ComputerPass','-Domain'],
    'Add-DomainUser':['-UserName','-UserPass','-Domain'],
    'Add-ADUser':['-UserName','-UserPass','-Domain'],
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
    'Set-DomainObject':['-Identity','-Clear','-Set','-Domain'],
    'Set-Object':['-Identity','-Clear','-Set','-Domain'],
    'Set-DomainUserPassword':['-Identity','-AccountPassword','-Domain'],
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
