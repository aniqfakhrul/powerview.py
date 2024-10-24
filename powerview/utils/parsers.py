import argparse
import sys

from impacket import version
from powerview.utils.completer import COMMANDS
from powerview.utils.colors import bcolors
from powerview.utils.helpers import escape_filter_chars_except_asterisk
from powerview._version import BANNER,__version__

# https://stackoverflow.com/questions/14591168/argparse-dont-show-usage-on-h
class PowerViewParser(argparse.ArgumentParser):
    def error(self, message):
        print(message)
        sys.exit(0)

def arg_parse():
    parser = PowerViewParser(description = f"Python alternative to SharpSploit's PowerView script, version {bcolors.OKBLUE + __version__ + bcolors.ENDC}")
    parser.add_argument('target', action='store', metavar='target', help='[[domain/]username[:password]@]<targetName or address>')
    parser.add_argument('-p','--port', dest='port', action='store', help='LDAP server port. (Default: 389|636)', type=int)
    parser.add_argument('-d','--debug', dest='debug', action='store_true', help='Enable debug output')
    parser.add_argument('--stack-trace', dest='stack_trace', action='store_true', help='raise exceptions and exit if unhandled errors')
    parser.add_argument('-q','--query', dest='query', action='store', help='PowerView query to be executed one-time')
    parser.add_argument('--no-admin-check', dest='no_admin_check', action='store_true', help='Skip admin check when first logging in')
    ns_group_parser = parser.add_mutually_exclusive_group()
    ns_group_parser.add_argument('--use-system-nameserver', action='store_true', default=False, dest='use_system_ns', help='Use system nameserver to resolve hostname/domain')
    ns_group_parser.add_argument('-ns','--nameserver', dest='nameserver', action='store', help='Specify custom nameserver. If not specified, domain controller will be used instead')
    parser.add_argument('-v','--version', dest='version', action='version',version=BANNER)

    protocol = parser.add_argument_group('protocol')
    group = protocol.add_mutually_exclusive_group()
    group.add_argument('--use-ldap', dest='use_ldap', action='store_true', help='[Optional] Use LDAP instead of LDAPS')
    group.add_argument('--use-ldaps', dest='use_ldaps', action='store_true', help='[Optional] Use LDAPS instead of LDAP')
    group.add_argument('--use-gc', dest='use_gc', action='store_true', help='[Optional] Use GlobalCatalog (GC) protocol')
    group.add_argument('--use-gc-ldaps', dest='use_gc_ldaps', action='store_true', help='[Optional] Use GlobalCatalog (GC) protocol for LDAPS')

    auth = parser.add_argument_group('authentication')
    auth.add_argument('-H','--hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    
    auth_type_group = auth.add_mutually_exclusive_group()
    auth_type_group.add_argument("-k", "--kerberos", dest="use_kerberos", action="store_true", help='Use Kerberos authentication. Grabs credentials from .ccache file (KRB5CCNAME) based on target parameters. If valid credentials cannot be found, it will use the ones specified in the command line')
    auth_type_group.add_argument("--use-channel-binding", action='store_true', default=False, help='[Optional] Use channel binding if channel binding is required on LDAP server')
    auth_type_group.add_argument("--use-sign-and-seal", action='store_true', default=False, help='[Optional] Use sign and seal if LDAP signing is required on ldap server')
    auth_type_group.add_argument("--simple-auth", dest="simple_auth", action="store_true", help='Authenticate with SIMPLE authentication')
    auth_type_group.add_argument("--pfx", dest="pfx", action="store", help='Supply .pfx formatted certificate. Use --cert and --key if no pfx')

    auth.add_argument('--no-pass', action="store_true", help="don't ask for password (useful for -k)")
    auth.add_argument('--aes-key', dest="auth_aes_key", action="store", metavar = "hex key", help='AES key to use for Kerberos Authentication \'(128 or 256 bits)\'')
    auth.add_argument("--dc-ip", action='store', metavar='IP address', help='IP Address of the domain controller or KDC (Key Distribution Center) for Kerberos. If omitted it will use the domain part (FQDN) specified in the identity parameter')

    relay = parser.add_argument_group('relay')
    relay.add_argument('--relay', dest='relay', action='store_true', help='Specify if you wish to turn on relay mode')
    relay.add_argument('--relay-host', dest='relay_host', action='store', default="0.0.0.0", help='Bind interface to expose http server (Default: 0.0.0.0)')
    relay.add_argument('--relay-port', dest='relay_port', action='store', type=int, default=80, help='Relay mode custom http port (Default: 80)')

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # check for mutually exclusive
    if args.use_kerberos and (args.relay):
        logging.error("Kerberos option cannot be used in relay mode. Exiting...")
        sys.exit(0)

    return args

def powerview_arg_parse(cmd):
    parser = PowerViewParser(exit_on_error=False)
    subparsers = parser.add_subparsers(dest='module')
    parser.add_argument('-Server', action='store', dest='server')
    parser.add_argument('-Where', action='store', dest='where')
    parser.add_argument('-Select', action='store', dest='select')
    parser.add_argument('-Count', action='store_true', dest='count')
    parser.add_argument('-NoWrap', action='store_true', dest='nowrap')

    #domain
    get_domain_parser = subparsers.add_parser('Get-Domain', aliases=['Get-NetDomain'], exit_on_error=False)
    get_domain_parser.add_argument('-Identity', action='store',default='*', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domain_parser.add_argument('-Properties', action='store', dest='properties')
    get_domain_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domain_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domain_parser.add_argument('-Server', action='store', dest='server')
    get_domain_parser.add_argument('-Select', action='store', dest='select')
    get_domain_parser.add_argument('-Where', action='store', dest='where')
    get_domain_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domain_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domain_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domain_parser.add_argument('-Count', action='store_true', dest='count')
    get_domain_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #domainobject
    get_domainobject_parser = subparsers.add_parser('Get-DomainObject', aliases=['Get-ADObject'] ,exit_on_error=False)
    get_domainobject_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobject_parser.add_argument('-Properties', action='store', dest='properties')
    get_domainobject_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainobject_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobject_parser.add_argument('-Server', action='store', dest='server')
    get_domainobject_parser.add_argument('-Select', action='store', dest='select')
    get_domainobject_parser.add_argument('-Where', action='store', dest='where')
    get_domainobject_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainobject_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainobject_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainobject_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainobject_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #domainobjectowner
    get_domainobjectowner_parser = subparsers.add_parser('Get-DomainObjectOwner', aliases=['Get-ObjectOwner'] ,exit_on_error=False)
    get_domainobjectowner_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobjectowner_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobjectowner_parser.add_argument('-Server', action='store', dest='server')
    get_domainobjectowner_parser.add_argument('-Select', action='store', dest='select')
    get_domainobjectowner_parser.add_argument('-Where', action='store', dest='where')
    get_domainobjectowner_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainobjectowner_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainobjectowner_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainobjectowner_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainobjectowner_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #domainobjectacl
    get_domainobjectacl_parser = subparsers.add_parser('Get-DomainObjectAcl', aliases=['Get-ObjectAcl'] ,exit_on_error=False)
    get_domainobjectacl_parser.add_argument('-Identity', action='store', default='*', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobjectacl_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainobjectacl_parser.add_argument('-Server', action='store', dest='server')
    get_domainobjectacl_parser.add_argument('-SecurityIdentifier', action='store', dest='security_identifier')
    get_domainobjectacl_parser.add_argument('-ResolveGUIDs', action='store_true',default=False, dest='resolveguids')
    get_domainobjectacl_parser.add_argument('-Select', action='store', dest='select')
    get_domainobjectacl_parser.add_argument('-Where', action='store', dest='where')
    get_domainobjectacl_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainobjectacl_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainobjectacl_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainobjectacl_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #group
    get_domaingroup_parser = subparsers.add_parser('Get-DomainGroup', aliases=['Get-NetGroup'], exit_on_error=False)
    get_domaingroup_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingroup_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaingroup_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingroup_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingroup_parser.add_argument('-MemberIdentity', action='store', dest='memberidentity')
    get_domaingroup_parser.add_argument('-AdminCount', action='store_true', default=False, dest='admincount')
    get_domaingroup_parser.add_argument('-Server', action='store', dest='server')
    get_domaingroup_parser.add_argument('-Select', action='store', dest='select')
    get_domaingroup_parser.add_argument('-Where', action='store', dest='where')
    get_domaingroup_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaingroup_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaingroup_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaingroup_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaingroup_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # foreignuser
    get_domainforeignuser_parser = subparsers.add_parser('Get-DomainForeignUser', aliases=['Find-ForeignUser'], exit_on_error=False)
    get_domainforeignuser_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainforeignuser_parser.add_argument('-Server', action='store', dest='server')
    get_domainforeignuser_parser.add_argument('-Select', action='store', dest='select')
    get_domainforeignuser_parser.add_argument('-Where', action='store', dest='where')
    get_domainforeignuser_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainforeignuser_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainforeignuser_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainforeignuser_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainforeignuser_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # foreigngroupmember
    get_domainforeigngroupmember_parser = subparsers.add_parser('Get-DomainForeignGroupMember', aliases=['Find-ForeignGroup'], exit_on_error=False)
    get_domainforeigngroupmember_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainforeigngroupmember_parser.add_argument('-Server', action='store', dest='server')
    get_domainforeigngroupmember_parser.add_argument('-Select', action='store', dest='select')
    get_domainforeigngroupmember_parser.add_argument('-Where', action='store', dest='where')
    get_domainforeigngroupmember_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainforeigngroupmember_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainforeigngroupmember_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainforeigngroupmember_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainforeigngroupmember_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #groupmember
    get_domaingroupmember_parser = subparsers.add_parser('Get-DomainGroupMember', aliases=['Get-NetGroupMember'], exit_on_error=False)
    get_domaingroupmember_parser.add_argument('-Identity', action='store',default='*', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingroupmember_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingroupmember_parser.add_argument('-Server', action='store', dest='server')
    get_domaingroupmember_parser.add_argument('-Select', action='store', dest='select')
    get_domaingroupmember_parser.add_argument('-Where', action='store', dest='where')
    get_domaingroupmember_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaingroupmember_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaingroupmember_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaingroupmember_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaingroupmember_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #user
    get_domainuser_parser = subparsers.add_parser('Get-DomainUser', aliases=['Get-NetUser'], exit_on_error=False)
    get_domainuser_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainuser_parser.add_argument('-Properties', action='store', dest='properties')
    get_domainuser_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainuser_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainuser_parser.add_argument('-Server', action='store', dest='server')
    get_domainuser_parser.add_argument('-Select', action='store', dest='select')
    get_domainuser_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainuser_parser.add_argument('-Where', action='store', dest='where') # type=parser.where
    get_domainuser_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainuser_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainuser_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainuser_parser.add_argument('-SPN', action='store_true', default=False, dest='spn')
    get_domainuser_parser.add_argument('-AdminCount', action='store_true', default=False, dest='admincount')
    get_domainuser_parser.add_argument('-PassNotRequired', action='store_true', default=False, dest='passnotrequired')
    get_domainuser_parser.add_argument('-RBCD', action='store_true', default=False, dest='rbcd')
    get_domainuser_parser.add_argument('-ShadowCred', action='store_true', default=False, dest='shadowcred')
    get_domainuser_parser.add_argument('-PreAuthNotRequired', action='store_true', default=False, dest='preauthnotrequired')
    get_domainuser_parser.add_argument('-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domainuser_parser.add_argument('-AllowDelegation', action='store_true', default=False, dest='allowdelegation')
    get_domainuser_parser.add_argument('-DisallowDelegation', action='store_true', default=False, dest='disallowdelegation')
    get_domainuser_parser.add_argument('-Unconstrained', action='store_true', default=False, dest='unconstrained')
    get_domainuser_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # get-localuser
    get_localuser_parser = subparsers.add_parser('Get-LocalUser', exit_on_error=False)
    get_localuser_group = get_localuser_parser.add_mutually_exclusive_group()
    get_localuser_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_localuser_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_localuser_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_localuser_parser.add_argument('-Properties', action='store', dest='properties')
    get_localuser_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_localuser_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_localuser_parser.add_argument('-Server', action='store', dest='server')
    get_localuser_parser.add_argument('-Select', action='store', dest='select')
    get_localuser_parser.add_argument('-Count', action='store_true', dest='count')
    get_localuser_parser.add_argument('-OutFile', action='store', dest='outfile')

    #computers
    get_domaincomputer_parser = subparsers.add_parser('Get-DomainComputer', aliases=['Get-NetComputer'], exit_on_error=False)
    get_domaincomputer_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincomputer_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaincomputer_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaincomputer_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincomputer_parser.add_argument('-ResolveIP', action='store_true', default=False, dest='resolveip')
    get_domaincomputer_parser.add_argument('-ResolveSIDs', action='store_true', default=False, dest='resolvesids')
    get_domaincomputer_parser.add_argument('-Server', action='store', dest='server')
    get_domaincomputer_parser.add_argument('-Select', action='store', dest='select')
    get_domaincomputer_parser.add_argument('-Where', action='store', dest='where')
    get_domaincomputer_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaincomputer_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaincomputer_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaincomputer_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaincomputer_parser.add_argument('-Unconstrained', action='store_true', default=False, dest='unconstrained')
    get_domaincomputer_parser.add_argument('-TrustedToAuth', action='store_true', default=False, dest='trustedtoauth')
    get_domaincomputer_parser.add_argument('-LAPS', action='store_true', default=False, dest='laps')
    get_domaincomputer_parser.add_argument('-BitLocker', action='store_true', default=False, dest='bitlocker')
    get_domaincomputer_parser.add_argument('-GMSAPassword', action='store_true', default=False, dest='gmsapassword')
    get_domaincomputer_parser.add_argument('-Pre2K', action='store_true', default=False, dest='pre2k')
    get_domaincomputer_parser.add_argument('-RBCD', action='store_true', default=False, dest='rbcd')
    get_domaincomputer_parser.add_argument('-ShadowCred', action='store_true', default=False, dest='shadowcred')
    get_domaincomputer_parser.add_argument('-SPN', action='store_true', dest='spn')
    get_domaincomputer_parser.add_argument('-Printers', action='store_true', default=False, dest='printers')
    get_domaincomputer_parser.add_argument('-ExcludeDCs', action='store_true', default=False, dest='excludedcs')
    get_domaincomputer_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #domain controller
    get_domaincontroller_parser = subparsers.add_parser('Get-DomainController', aliases=['Get-NetDomainController'], exit_on_error=False)
    get_domaincontroller_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincontroller_parser.add_argument('-ResolveSIDs', action='store_true', default=False, dest='resolvesids')
    get_domaincontroller_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincontroller_parser.add_argument('-Properties',action='store', dest='properties')
    get_domaincontroller_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaincontroller_parser.add_argument('-Server', action='store', dest='server')
    get_domaincontroller_parser.add_argument('-Select',action='store', dest='select')
    get_domaincontroller_parser.add_argument('-Where', action='store', dest='where')
    get_domaincontroller_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaincontroller_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaincontroller_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaincontroller_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaincontroller_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #gpo
    get_domaingpo_parser = subparsers.add_parser('Get-DomainGPO', aliases=['Get-NetGPO'], exit_on_error=False)
    get_domaingpo_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingpo_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaingpo_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingpo_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingpo_parser.add_argument('-Server', action='store', dest='server')
    get_domaingpo_parser.add_argument('-Select', action='store', dest='select')
    get_domaingpo_parser.add_argument('-Where', action='store', dest='where')
    get_domaingpo_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaingpo_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaingpo_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaingpo_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaingpo_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    #gpo local group / restricted groups
    get_domaingpolocalgroup_parser = subparsers.add_parser('Get-DomainGPOLocalGroup', aliases=['Get-GPOLocalGroup'], exit_on_error=False)
    get_domaingpolocalgroup_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingpolocalgroup_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingpolocalgroup_parser.add_argument('-Server', action='store', dest='server')
    get_domaingpolocalgroup_parser.add_argument('-Select', action='store', dest='select')
    get_domaingpolocalgroup_parser.add_argument('-Where', action='store', dest='where')
    get_domaingpolocalgroup_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaingpolocalgroup_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaingpolocalgroup_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaingpolocalgroup_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaingpolocalgroup_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # OU
    get_domainou_parser = subparsers.add_parser('Get-DomainOU', aliases=['Get-NetOU'], exit_on_error=False)
    get_domainou_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainou_parser.add_argument('-Properties', action='store', dest='properties')
    get_domainou_parser.add_argument('-GPLink', action='store', dest='gplink')
    get_domainou_parser.add_argument('-ResolveGPLink', action='store_true', default=False, dest='resolve_gplink')
    get_domainou_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainou_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainou_parser.add_argument('-Server', action='store', dest='server')
    get_domainou_parser.add_argument('-Select', action='store', dest='select')
    get_domainou_parser.add_argument('-Where', action='store', dest='where')
    get_domainou_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainou_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainou_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainou_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainou_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Find DNS Zone
    get_domaindnszone_parser = subparsers.add_parser('Get-DomainDNSZone', exit_on_error=False)
    get_domaindnszone_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaindnszone_parser.add_argument('-Properties', action='store' , dest='properties')
    get_domaindnszone_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaindnszone_parser.add_argument('-Server', action='store', dest='server')
    get_domaindnszone_parser.add_argument('-Select', action='store', dest='select')
    get_domaindnszone_parser.add_argument('-Where', action='store', dest='where')
    get_domaindnszone_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaindnszone_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaindnszone_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaindnszone_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaindnszone_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Get DNS Record
    get_domaindnsrecord_parser = subparsers.add_parser('Get-DomainDNSRecord', exit_on_error=False)
    get_domaindnsrecord_parser.add_argument('-ZoneName', action='store', dest='zonename')
    get_domaindnsrecord_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaindnsrecord_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaindnsrecord_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaindnsrecord_parser.add_argument('-Server', action='store', dest='server')
    get_domaindnsrecord_parser.add_argument('-Select', action='store', dest='select')
    get_domaindnsrecord_parser.add_argument('-Where', action='store', dest='where')
    get_domaindnsrecord_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaindnsrecord_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaindnsrecord_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaindnsrecord_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaindnsrecord_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Get SCCM
    get_domainsccm_parser = subparsers.add_parser('Get-DomainSCCM', aliases=['Get-SCCM'], exit_on_error=False)
    get_domainsccm_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainsccm_parser.add_argument('-CheckDatalib', action='store_true', default=False, dest='check_datalib')
    get_domainsccm_parser.add_argument('-Properties', action='store', dest='properties')
    get_domainsccm_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainsccm_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainsccm_parser.add_argument('-Server', action='store', dest='server')
    get_domainsccm_parser.add_argument('-Select', action='store', dest='select')
    get_domainsccm_parser.add_argument('-Where', action='store', dest='where')
    get_domainsccm_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainsccm_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainsccm_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainsccm_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainsccm_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Get-DomainGMSA
    get_domaingmsa_parser = subparsers.add_parser('Get-DomainGMSA', aliases=['Get-GMSA'], exit_on_error=False)
    get_domaingmsa_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingmsa_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domaingmsa_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaingmsa_parser.add_argument('-Server', action='store', dest='server')
    get_domaingmsa_parser.add_argument('-Select', action='store', dest='select')
    get_domaingmsa_parser.add_argument('-Where', action='store', dest='where')
    get_domaingmsa_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaingmsa_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaingmsa_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaingmsa_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaingmsa_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Get-DomainRBCD
    get_domainrbcd_parser = subparsers.add_parser('Get-DomainRBCD', aliases=['Get-RBCD'], exit_on_error=False)
    get_domainrbcd_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainrbcd_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_domainrbcd_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainrbcd_parser.add_argument('-Server', action='store', dest='server')
    get_domainrbcd_parser.add_argument('-Select', action='store', dest='select')
    get_domainrbcd_parser.add_argument('-Where', action='store', dest='where')
    get_domainrbcd_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainrbcd_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainrbcd_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainrbcd_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainrbcd_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Find CAs
    get_domainca_parser = subparsers.add_parser('Get-DomainCA', aliases=['Get-CA'], exit_on_error=False)
    get_domainca_parser.add_argument('-CheckWebEnrollment', action='store_true', dest='check_web_enrollment')
    get_domainca_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domainca_parser.add_argument('-Properties', action='store', dest='properties')
    get_domainca_parser.add_argument('-Server', action='store', dest='server')
    get_domainca_parser.add_argument('-Select', action='store', dest='select')
    get_domainca_parser.add_argument('-Where', action='store', dest='where')
    get_domainca_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domainca_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domainca_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domainca_parser.add_argument('-Count', action='store_true', dest='count')
    get_domainca_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # Find CA Templates
    get_domaincatemplate_parser = subparsers.add_parser('Get-DomainCATemplate', aliases=['Get-CATemplate'], exit_on_error=False)
    get_domaincatemplate_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincatemplate_parser.add_argument('-Enabled', action='store_true', dest='enabled')
    get_domaincatemplate_parser.add_argument('-Vulnerable', action='store_true', dest='vulnerable')
    get_domaincatemplate_parser.add_argument('-ResolveSIDs', action='store_true', dest='resolve_sids')
    get_domaincatemplate_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaincatemplate_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaincatemplate_parser.add_argument('-Server', action='store', dest='server')
    get_domaincatemplate_parser.add_argument('-Select', action='store', dest='select')
    get_domaincatemplate_parser.add_argument('-Where', action='store', dest='where')
    get_domaincatemplate_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaincatemplate_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaincatemplate_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaincatemplate_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaincatemplate_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    remove_domaincatemplate_parser = subparsers.add_parser('Remove-DomainCATemplate', aliases=['Remove-CATemplate'], exit_on_error=False)
    remove_domaincatemplate_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaincatemplate_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaincatemplate_parser.add_argument('-Server', action='store', dest='server')
    remove_domaincatemplate_parser.add_argument('-Select', action='store', dest='select')
    remove_domaincatemplate_parser.add_argument('-Where', action='store', dest='where')
    remove_domaincatemplate_parser.add_argument('-OutFile', action='store', dest='outfile')
    remove_domaincatemplate_parser.add_argument('-Count', action='store_true', dest='count')
    remove_domaincatemplate_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # add ca certificate template
    add_domaincatemplate_parser = subparsers.add_parser('Add-DomainCATemplate', aliases=['Add-CATemplate'], exit_on_error=False)
    add_domaincatemplate_parser.add_argument('-DisplayName', action='store', dest='displayname', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincatemplate_parser.add_argument('-Name', action='store', dest='name', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincatemplate_parser.add_argument('-Duplicate', action='store', dest='duplicate')
    add_domaincatemplate_parser.add_argument('-Server', action='store', dest='server')
    add_domaincatemplate_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # add domain ca template acl
    add_domaincatemplateacl_parser = subparsers.add_parser('Add-DomainCATemplateAcl', aliases=['Add-CATemplateAcl'], exit_on_error=False)
    add_domaincatemplateacl_parser.add_argument('-Template', action='store', const=None, dest='template', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincatemplateacl_parser.add_argument('-PrincipalIdentity', action='store', const=None, dest='principalidentity', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincatemplateacl_parser.add_argument('-Rights', action='store', const=None, dest='rights', choices=['all', 'enroll','write'], type = str.lower)
    add_domaincatemplateacl_parser.add_argument('-Server', action='store', dest='server')
    add_domaincatemplateacl_parser.add_argument('-OutFile', action='store', dest='outfile')

    # get named pipes
    get_namedpipes_parser = subparsers.add_parser('Get-NamedPipes', exit_on_error=False)
    get_namedpipes_parser.add_argument('-Name', action='store', dest='name')
    get_namedpipes_group = get_namedpipes_parser.add_mutually_exclusive_group()
    get_namedpipes_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_namedpipes_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_namedpipes_parser.add_argument('-Server', action='store', dest='server')
    get_namedpipes_parser.add_argument('-Count', action='store_true', dest='count')
    get_namedpipes_parser.add_argument('-OutFile', action='store', dest='outfile')

    # shares
    get_netshare_parser = subparsers.add_parser('Get-NetShare', exit_on_error=False)
    get_netshare_group = get_netshare_parser.add_mutually_exclusive_group()
    get_netshare_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netshare_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netshare_parser.add_argument('-Server', action='store', dest='server')
    get_netshare_parser.add_argument('-Count', action='store_true', dest='count')
    get_netshare_parser.add_argument('-OutFile', action='store', dest='outfile')

    # get-regloggedon
    get_regloggedon_parser = subparsers.add_parser('Get-RegLoggedOn', exit_on_error=False)
    get_regloggedon_group = get_regloggedon_parser.add_mutually_exclusive_group()
    get_regloggedon_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_regloggedon_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_regloggedon_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_regloggedon_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_regloggedon_parser.add_argument('-Server', action='store', dest='server')
    get_regloggedon_parser.add_argument('-Count', action='store_true', dest='count')
    get_regloggedon_parser.add_argument('-OutFile', action='store', dest='outfile')

    # get-netloggedon
    get_netloggedon_parser = subparsers.add_parser('Get-NetLoggedOn', exit_on_error=False)
    get_netloggedon_group = get_netloggedon_parser.add_mutually_exclusive_group()
    get_netloggedon_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netloggedon_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netloggedon_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_netloggedon_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_netloggedon_parser.add_argument('-Server', action='store', dest='server')
    get_netloggedon_parser.add_argument('-Count', action='store_true', dest='count')
    get_netloggedon_parser.add_argument('-OutFile', action='store', dest='outfile')

    # get-netsession
    get_netsession_parser = subparsers.add_parser('Get-NetSession', exit_on_error=False)
    get_netsession_group = get_netsession_parser.add_mutually_exclusive_group()
    get_netsession_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netsession_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netsession_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_netsession_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_netsession_parser.add_argument('-Server', action='store', dest='server')
    get_netsession_parser.add_argument('-Count', action='store_true', dest='count')
    get_netsession_parser.add_argument('-OutFile', action='store', dest='outfile')

    # get-netservice
    get_netservice_parser = subparsers.add_parser('Get-NetService', exit_on_error=False)
    get_netservice_parser.add_argument('-Name', action='store', dest='name', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netservice_group = get_netservice_parser.add_mutually_exclusive_group()
    get_netservice_group.add_argument('-Computer', action='store', const=None, dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netservice_group.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_netservice_status_group = get_netservice_parser.add_mutually_exclusive_group(required=False)
    get_netservice_status_group.add_argument('-IsRunning', action='store_true', default=False, dest='isrunning')
    get_netservice_status_group.add_argument('-IsStopped', action='store_true', default=False, dest='isstopped')
    get_netservice_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_netservice_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_netservice_parser.add_argument('-Server', action='store', dest='server')
    get_netservice_parser.add_argument('-Count', action='store_true', dest='count')
    get_netservice_parser.add_argument('-OutFile', action='store', dest='outfile')

    # shares
    find_localadminaccess_parser = subparsers.add_parser('Find-LocalAdminAccess', exit_on_error=False)
    find_localadminaccess_group = find_localadminaccess_parser.add_mutually_exclusive_group()
    find_localadminaccess_group.add_argument('-Computer', action='store', dest='computer', type=lambda value: escape_filter_chars_except_asterisk(value))
    find_localadminaccess_group.add_argument('-ComputerName', action='store', dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    find_localadminaccess_parser.add_argument('-Server', action='store', dest='server')
    find_localadminaccess_parser.add_argument('-Count', action='store_true', dest='count')
    find_localadminaccess_parser.add_argument('-OutFile', action='store', dest='outfile')

    # invoke kerberoast
    invoke_kerberoast_parser = subparsers.add_parser('Invoke-Kerberoast', exit_on_error=False)
    invoke_kerberoast_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    invoke_kerberoast_parser.add_argument('-Properties', action='store', dest='properties')
    invoke_kerberoast_parser.add_argument('-Opsec', action='store_true', default=False, dest='opsec')
    invoke_kerberoast_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    invoke_kerberoast_parser.add_argument('-Server', action='store', dest='server')
    invoke_kerberoast_parser.add_argument('-Select', action='store', dest='select')
    invoke_kerberoast_parser.add_argument('-Where', action='store', dest='where')
    invoke_kerberoast_parser.add_argument('-TableView', action='store_true', dest='tableview')
    invoke_kerberoast_parser.add_argument('-OutFile', action='store', dest='outfile')
    invoke_kerberoast_parser.add_argument('-SortBy', action='store', dest='sort_by')
    invoke_kerberoast_parser.add_argument('-Count', action='store_true', dest='count')
    invoke_kerberoast_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # get exchange server
    get_exchangeserver_parser = subparsers.add_parser('Get-ExchangeServer',aliases=['Get-Exchange'], exit_on_error=False)
    get_exchangeserver_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_exchangeserver_parser.add_argument('-Properties', action='store', dest='properties')
    get_exchangeserver_parser.add_argument('-LDAPFilter', action='store', dest='ldapfilter')
    get_exchangeserver_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_exchangeserver_parser.add_argument('-Server', action='store', dest='server')
    get_exchangeserver_parser.add_argument('-Select', action='store', dest='select')
    get_exchangeserver_parser.add_argument('-Where', action='store', dest='where')
    get_exchangeserver_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_exchangeserver_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_exchangeserver_parser.add_argument('-Count', action='store_true', dest='count')
    get_exchangeserver_parser.add_argument('-OutFile', action='store', dest='outfile')

    # unlock_adaccount
    unlock_adaccount_parser = subparsers.add_parser('Unlock-ADAccount',aliases=['Unlock-ADAccount'], exit_on_error=False)
    unlock_adaccount_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    unlock_adaccount_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    unlock_adaccount_parser.add_argument('-Server', action='store', dest='server')
    unlock_adaccount_parser.add_argument('-OutFile', action='store', dest='outfile')

    #trust
    get_domaintrust_parser = subparsers.add_parser('Get-DomainTrust', aliases=['Get-NetTrust'], exit_on_error=False)
    get_domaintrust_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    get_domaintrust_parser.add_argument('-Properties', action='store', dest='properties')
    get_domaintrust_parser.add_argument('-Server', action='store', dest='server')
    get_domaintrust_parser.add_argument('-Select', action='store', dest='select')
    get_domaintrust_parser.add_argument('-Where', action='store', dest='where')
    get_domaintrust_parser.add_argument('-TableView', action='store_true', dest='tableview')
    get_domaintrust_parser.add_argument('-SortBy', action='store', dest='sort_by')
    get_domaintrust_parser.add_argument('-OutFile', action='store', dest='outfile')
    get_domaintrust_parser.add_argument('-Count', action='store_true', dest='count')
    get_domaintrust_parser.add_argument('-NoWrap', action='store_true', default=False, dest='nowrap')

    # convert from uac value
    convertfrom_uacvalue_parser = subparsers.add_parser('ConvertFrom-UACValue' ,exit_on_error=False)
    convertfrom_uacvalue_parser.add_argument('-Value', action='store', dest='value')
    convertfrom_uacvalue_parser.add_argument('-Server', action='store', dest='server')
    convertfrom_uacvalue_parser.add_argument('-OutFile', action='store', dest='outfile')
    
    # convert from sid
    convertfrom_sid_parser = subparsers.add_parser('ConvertFrom-SID' ,exit_on_error=False)
    convertfrom_sid_parser.add_argument('-ObjectSID', action='store', dest='objectsid')
    convertfrom_sid_parser.add_argument('-Server', action='store', dest='server')
    convertfrom_sid_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain group members
    add_domaingroupmember_parser = subparsers.add_parser('Add-DomainGroupMember',aliases=['Add-GroupMember'], exit_on_error=False)
    add_domaingroupmember_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaingroupmember_parser.add_argument('-Members', action='store', const=None, dest='members')
    add_domaingroupmember_parser.add_argument('-Server', action='store', dest='server')
    add_domaingroupmember_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain object
    remove_domainobject_parser = subparsers.add_parser('Remove-DomainObject',aliases=['Remove-ADObject'], exit_on_error=False)
    remove_domainobject_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainobject_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainobject_parser.add_argument('-Server', action='store', dest='server')
    remove_domainobject_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain group members
    remove_domaingroupmember_parser = subparsers.add_parser('Remove-DomainGroupMember',aliases=['Remove-GroupMember'], exit_on_error=False)
    remove_domaingroupmember_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaingroupmember_parser.add_argument('-Members', action='store', const=None, dest='members', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaingroupmember_parser.add_argument('-Server', action='store', dest='server')
    remove_domaingroupmember_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain ou
    add_domainou_parser = subparsers.add_parser('Add-DomainOU', aliases=['Add-OU'], exit_on_error=False)
    add_domainou_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domainou_parser.add_argument('-ProtectedFromAccidentalDeletion', action='store_true', default=False, dest='protectedfromaccidentaldeletion')
    add_domainou_parser.add_argument('-BaseDN', action='store', const=None, dest='basedn', help="[Optional] (Default: root DN)")
    add_domainou_parser.add_argument('-Server', action='store', dest='server')
    add_domainou_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain gpo
    add_domaingpo_parser = subparsers.add_parser('Add-DomainGPO', aliases=['Add-GPO'], exit_on_error=False)
    add_domaingpo_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=str)
    add_domaingpo_parser.add_argument('-Description', action='store', dest='description', type=str)
    add_domaingpo_parser.add_argument('-LinkTo', action='store', dest='linkto', type=str)
    add_domaingpo_parser.add_argument('-BaseDN', action='store', const=None, dest='basedn', help="[Optional] (Default: root DN)")
    add_domaingpo_parser.add_argument('-Server', action='store', dest='server')
    add_domaingpo_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain ou
    remove_domainou_parser = subparsers.add_parser('Remove-DomainOU', aliases=['Remove-OU'], exit_on_error=False)
    remove_domainou_parser.add_argument('-Identity', action='store', const=None, dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainou_parser.add_argument('-DistinguishedName', action='store', const=None, dest='distinguishedname')
    remove_domainou_parser.add_argument('-Server', action='store', dest='server')
    remove_domainou_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain object acl
    add_domainobjectacl_parser = subparsers.add_parser('Add-DomainObjectAcl', aliases=['Add-ObjectAcl'], exit_on_error=False)
    add_domainobjectacl_parser.add_argument('-TargetIdentity', action='store', required=True, const=None, dest='targetidentity', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domainobjectacl_parser.add_argument('-PrincipalIdentity', action='store', required=True, const=None, dest='principalidentity', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domainobjectacl_parser.add_argument('-Rights', action='store',  dest='rights', choices=['immutable','fullcontrol', 'resetpassword', 'writemembers', 'dcsync'], nargs='?', default='fullcontrol', type=str.lower)
    add_domainobjectacl_parser.add_argument('-RightGUID', action='store', dest='rights_guid', type = str.lower)
    add_domainobjectacl_parser.add_argument('-ACEType', action='store', dest='ace_type', choices=['allowed', 'denied'], nargs='?', default='allowed', type = str.lower)
    add_domainobjectacl_parser.add_argument('-Inheritance', action='store_true', dest='inheritance', default=False)
    add_domainobjectacl_parser.add_argument('-Server', action='store', dest='server')
    add_domainobjectacl_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain object acl
    remove_domainobjectacl_parser = subparsers.add_parser('Remove-DomainObjectAcl', aliases=['Remove-ObjectAcl'], exit_on_error=False)
    remove_domainobjectacl_parser.add_argument('-TargetIdentity', action='store', required=True, const=None, dest='targetidentity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainobjectacl_parser.add_argument('-PrincipalIdentity', action='store', required=True, const=None, dest='principalidentity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainobjectacl_parser.add_argument('-Rights', action='store',  dest='rights', choices=['immutable', 'resetpassword', 'writemembers', 'dcsync'], nargs='?', default='fullcontrol', type=str.lower)
    remove_domainobjectacl_parser.add_argument('-RightGUID', action='store', dest='rights_guid', type = str.lower)
    remove_domainobjectacl_parser.add_argument('-ACEType', action='store', dest='ace_type', choices=['allowed', 'denied'], nargs='?', default='allowed', type = str.lower)
    remove_domainobjectacl_parser.add_argument('-Inheritance', action='store_true', dest='inheritance', default=False)
    remove_domainobjectacl_parser.add_argument('-Server', action='store', dest='server')
    remove_domainobjectacl_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain computer
    add_domaincomputer_parser = subparsers.add_parser('Add-DomainComputer', aliases=['Add-ADComputer'], exit_on_error=False)
    add_domaincomputer_parser.add_argument('-ComputerName', action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincomputer_parser.add_argument('-ComputerPass', action='store', const=None, dest='computerpass')
    add_domaincomputer_parser.add_argument('-BaseDN', action='store', default=None, const=None, dest='basedn', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domaincomputer_parser.add_argument('-Server', action='store', dest='server')
    add_domaincomputer_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add dns record
    add_domaindnsrecord_parser = subparsers.add_parser('Add-DomainDNSRecord', exit_on_error=False)
    add_domaindnsrecord_parser.add_argument('-ZoneName', action='store', dest='zonename')
    add_domaindnsrecord_parser.add_argument('-RecordName', action='store', dest='recordname')
    add_domaindnsrecord_parser.add_argument('-RecordAddress', action='store', dest='recordaddress')
    add_domaindnsrecord_parser.add_argument('-Server', action='store', dest='server')
    add_domaindnsrecord_parser.add_argument('-OutFile', action='store', dest='outfile')

    # add domain user
    add_domainuser_parser = subparsers.add_parser('Add-DomainUser', aliases=['Add-ADUser'], exit_on_error=False)
    add_domainuser_parser.add_argument('-UserName', action='store', default=None, const=None, dest='username')
    add_domainuser_parser.add_argument('-UserPass', action='store', default=None, const=None, dest='userpass')
    add_domainuser_parser.add_argument('-BaseDN', action='store', default=None, const=None, dest='basedn', type=lambda value: escape_filter_chars_except_asterisk(value))
    add_domainuser_parser.add_argument('-Server', action='store', dest='server')
    add_domainuser_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain user
    remove_domainuser_parser = subparsers.add_parser('Remove-DomainUser', aliases=['Remove-ADUser'], exit_on_error=False)
    remove_domainuser_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domainuser_parser.add_argument('-Server', action='store', dest='server')
    remove_domainuser_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove domain computer
    remove_domaincomputer_parser = subparsers.add_parser('Remove-DomainComputer', aliases=['Remove-ADComputer'], exit_on_error=False)
    remove_domaincomputer_parser.add_argument('-ComputerName',action='store', const=None, dest='computername', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaincomputer_parser.add_argument('-BaseDN', action='store', default=None, const=None, dest='basedn', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaincomputer_parser.add_argument('-Server', action='store', dest='server')
    remove_domaincomputer_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain object properties
    set_domainobject_parser = subparsers.add_parser('Set-DomainObject', aliases=['Set-ADObject'], exit_on_error=False)
    set_domainobject_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value))
    set_domainobject_group = set_domainobject_parser.add_mutually_exclusive_group()
    set_domainobject_group.add_argument('-Set', dest='set')
    set_domainobject_group.add_argument('-Append', dest='append')
    set_domainobject_group.add_argument('-Clear',action='store', dest='clear')
    set_domainobject_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    set_domainobject_parser.add_argument('-Server', action='store', dest='server')
    set_domainobject_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain object distinguishednam
    set_domainobjectdn_parser = subparsers.add_parser('Set-DomainObjectDN', aliases=['Set-ADObjectDN'], exit_on_error=False)
    set_domainobjectdn_parser.add_argument('-Identity', action='store', dest='identity', type=lambda value: escape_filter_chars_except_asterisk(value), required=True)
    set_domainobjectdn_parser.add_argument('-DestinationDN', action='store', dest='destination_dn', required=True)
    set_domainobjectdn_parser.add_argument('-SearchBase', action='store', dest='searchbase', type=lambda value: escape_filter_chars_except_asterisk(value))
    set_domainobjectdn_parser.add_argument('-Server', action='store', dest='server')
    set_domainobjectdn_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set dns record
    set_domaindnsrecord_parser = subparsers.add_parser('Set-DomainDNSRecord', exit_on_error=False)
    set_domaindnsrecord_parser.add_argument('-ZoneName', action='store', dest='zonename')
    set_domaindnsrecord_parser.add_argument('-RecordName', action='store', dest='recordname')
    set_domaindnsrecord_parser.add_argument('-RecordAddress', action='store', dest='recordaddress')
    set_domaindnsrecord_parser.add_argument('-Server', action='store', dest='server')
    set_domaindnsrecord_parser.add_argument('-OutFile', action='store', dest='outfile')

    # remove dns record
    remove_domaindnsrecord_parser = subparsers.add_parser('Remove-DomainDNSRecord', exit_on_error=False)
    remove_domaindnsrecord_parser.add_argument('-ZoneName', action='store', dest='zonename')
    remove_domaindnsrecord_parser.add_argument('-RecordName', action='store', dest='recordname', type=lambda value: escape_filter_chars_except_asterisk(value))
    remove_domaindnsrecord_parser.add_argument('-Server', action='store', dest='server')
    remove_domaindnsrecord_parser.add_argument('-OutFile', action='store', dest='outfile')

    # disable dns record
    disable_domaindnsrecord_parser = subparsers.add_parser('Disable-DomainDNSRecord', exit_on_error=False)
    disable_domaindnsrecord_parser.add_argument('-ZoneName', action='store', dest='zonename')
    disable_domaindnsrecord_parser.add_argument('-RecordName', action='store', dest='recordname', type=lambda value: escape_filter_chars_except_asterisk(value))
    disable_domaindnsrecord_parser.add_argument('-Server', action='store', dest='server')
    disable_domaindnsrecord_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain ca template properties
    set_domaincatemplate_parser = subparsers.add_parser('Set-DomainCATemplate', aliases=['Set-CATemplate'], exit_on_error=False)
    set_domaincatemplate_parser.add_argument('-Identity', action='store', dest='identity')
    set_domaincatemplate_group = set_domaincatemplate_parser.add_mutually_exclusive_group()
    set_domaincatemplate_group.add_argument('-Set', dest='set')
    set_domaincatemplate_group.add_argument('-Append', dest='append')
    set_domaincatemplate_group.add_argument('-Clear',action='store', dest='clear')
    set_domaincatemplate_parser.add_argument('-Server', action='store', dest='server')
    set_domaincatemplate_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain user password
    set_domainuserpassword_parser = subparsers.add_parser('Set-DomainUserPassword', exit_on_error=False)
    set_domainuserpassword_parser.add_argument('-Identity', action='store', dest='identity')
    set_domainuserpassword_parser.add_argument('-AccountPassword', action='store', dest='accountpassword')
    set_domainuserpassword_parser.add_argument('-OldPassword', action='store', dest='oldpassword')
    set_domainuserpassword_parser.add_argument('-Server', action='store', dest='server')
    set_domainuserpassword_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain computer password
    set_domaincomputerpassword_parser = subparsers.add_parser('Set-DomainComputerPassword', exit_on_error=False)
    set_domaincomputerpassword_parser.add_argument('-Identity', action='store', dest='identity')
    set_domaincomputerpassword_parser.add_argument('-AccountPassword', action='store', dest='accountpassword')
    set_domaincomputerpassword_parser.add_argument('-OldPassword', action='store', dest='oldpassword')
    set_domaincomputerpassword_parser.add_argument('-Server', action='store', dest='server')
    set_domaincomputerpassword_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain rbcd
    set_domainrbcd_parser = subparsers.add_parser('Set-DomainRBCD', aliases=['Set-RBCD'], exit_on_error=False)
    set_domainrbcd_parser.add_argument('-Identity', action='store', const=None, dest='identity')
    set_domainrbcd_parser.add_argument('-DelegateFrom', action='store', const=None, dest='delegatefrom')
    set_domainrbcd_parser.add_argument('-SearchBase', action='store', dest='searchbase')
    set_domainrbcd_parser.add_argument('-Server', action='store', dest='server')
    set_domainrbcd_parser.add_argument('-OutFile', action='store', dest='outfile')

    # set domain object owner
    set_domainobjectowner_parser = subparsers.add_parser('Set-DomainObjectOwner', aliases=['Set-ObjectOwner'], exit_on_error=False)
    set_domainobjectowner_parser.add_argument('-TargetIdentity', action='store', const=None, dest='targetidentity')
    set_domainobjectowner_parser.add_argument('-PrincipalIdentity', action='store', const=None, dest='principalidentity')
    set_domainobjectowner_parser.add_argument('-SearchBase', action='store', dest='searchbase')
    set_domainobjectowner_parser.add_argument('-Server', action='store', dest='server')
    set_domainobjectowner_parser.add_argument('-OutFile', action='store', dest='outfile')

    # new gp link
    add_gplink_parser = subparsers.add_parser('Add-GPLink', exit_on_error=False)
    add_gplink_parser.add_argument('-GUID', action='store', const=None, dest='guid')
    add_gplink_parser.add_argument('-TargetIdentity', action='store', const=None, dest='targetidentity')
    add_gplink_parser.add_argument('-LinkEnabled', action='store', dest='link_enabled', default="Yes", choices=["Yes","No"])
    add_gplink_parser.add_argument('-Enforced', action='store', dest='enforced', default="No", choices=["Yes","No"])
    add_gplink_parser.add_argument('-SearchBase', action='store', dest='searchbase')
    add_gplink_parser.add_argument('-Server', action='store', dest='server')
    add_gplink_parser.add_argument('-OutFile', action='store', dest='outfile')

    # new gp link
    remove_gplink_parser = subparsers.add_parser('Remove-GPLink', exit_on_error=False)
    remove_gplink_parser.add_argument('-GUID', action='store', const=None, dest='guid')
    remove_gplink_parser.add_argument('-TargetIdentity', action='store', const=None, dest='targetidentity')
    remove_gplink_parser.add_argument('-SearchBase', action='store', dest='searchbase')
    remove_gplink_parser.add_argument('-Server', action='store', dest='server')
    remove_gplink_parser.add_argument('-OutFile', action='store', dest='outfile')
    
    subparsers.add_parser('exit', exit_on_error=False)
    subparsers.add_parser('clear', exit_on_error=False)

    try:
        args, unknown = parser.parse_known_args(cmd)
        
        if unknown:
            for unk in unknown:
                if unk[0] == "-":
                    if unk.casefold() in [ item.casefold() for item in COMMANDS[cmd[0]]]:
                        indexs = [item.lower() for item in COMMANDS[cmd[0]]].index(unk.lower())
                        cmd = [c.replace(unk,COMMANDS[cmd[0]][indexs]) for c in cmd]
                    else:
                        print(f"Unrecognized argument: {unk}")
                        return None
                else:
                    if hasattr(args, 'identity'):
                        args.identity = escape_filter_chars_except_asterisk(unk)
                    elif hasattr(args, 'objectsid'):
                        args.objectsid = unk
                    elif hasattr(args, 'value'):
                        args.value = unk
                    else:
                        print(f"Unrecognized argument: {unk}")
                        return None
                    return args
            return parser.parse_args(cmd)

        return args
    except argparse.ArgumentError as e:
        try:
            for i in list(COMMANDS.keys()):
                if cmd[0].casefold() == i.casefold():
                    cmd[0] = i
                    return parser.parse_args(cmd)
        except:
            pass
        
        if "module" in str(e):
            print("Invalid command")
        else:
            print(str(e))
        
        return None
    except SystemExit:
        return None
