import os
import re
import readline

COMMANDS = {
    'Get-Domain':['-Identity','-Properties','-Select', '-Where'],
    'Get-DomainGPO':['-Identity','-Properties','-Select', '-Where'],
    'Get-DomainOU':['-Identity','-Properties','-Select','-GPLink', '-Where'],
    'Get-DomainGroup':['-Identity','-Properties','-Select', '-Where'],
    'Get-DomainTrust':['-Properties','-Select', '-Where'],
    'Get-DomainUser':['-Identity','-Properties','-Select','-PreAuthNotRequired','-AdminCount','-TrustedToAuth','-SPN', '-Where'],
    'Get-Shares':['-Computer','-ComputerName'],
    'Get-DomainObject':['-Identity','-Properties','-Select', '-Where'],
    'Get-DomainComputer':['-Identity','-Properties','-Select','-Unconstrained','-TrustedToAuth', '-LAPS', '-Where'],
    'Add-DomainComputer':['-ComputerName','-ComputerPass'],
    'Add-DomainGroupMember':['-Identity','-Members'],
    'Set-DomainObject':['-Identity','-Clear','-Set'],
    'Remove-DomainComputer':['-ComputerName'],
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
        line = readline.get_line_buffer().split()
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
                    results = [c + ' ' for c in COMMANDS[c] if c.casefold().startswith(args.casefold())] + [None]
                    return results[state]

        return results[state]
