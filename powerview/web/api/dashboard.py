from bisect import insort
from collections import Counter
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from heapq import nsmallest

from ldap3.core.exceptions import LDAPException, LDAPNoSuchObjectResult
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars

from powerview.utils.query_reads import track_query_reads


SAMPLE_LIMIT = 100
INACTIVE_DAYS = (30, 60, 90, 180)
PASSWORD_AGE_DAYS = 365
NEVER = 'never'
EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
IN_CHAIN = '1.2.840.113556.1.4.1941'
ALL_BITS = '1.2.840.113556.1.4.803'
ANY_BIT = '1.2.840.113556.1.4.804'
ACCOUNTDISABLE = 0x2
PASSWD_NOTREQD = 0x20
SERVER_TRUST_ACCOUNT = 0x2000
DONT_EXPIRE_PASSWORD = 0x10000
TRUSTED_FOR_DELEGATION = 0x80000
DONT_REQ_PREAUTH = 0x400000
PARTIAL_SECRETS_ACCOUNT = 0x4000000
CONTROLLER = SERVER_TRUST_ACCOUNT | PARTIAL_SECRETS_ACCOUNT
ENABLED_FILTER = f'(!(userAccountControl:{ALL_BITS}:={ACCOUNTDISABLE}))'
ACCOUNT_PROPERTIES = ['name', 'sAMAccountName', 'distinguishedName', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet']
USER_PROPERTIES = ACCOUNT_PROPERTIES + ['adminCount', 'servicePrincipalName']
COMPUTER_PROPERTIES = ACCOUNT_PROPERTIES + ['logonCount', 'dNSHostName', 'operatingSystem', 'msDS-AllowedToDelegateTo']
PRIVILEGED_GROUPS = (
    ('S-1-5-32-544', 'Administrators'), (512, 'Domain Admins'), (519, 'Enterprise Admins'), (518, 'Schema Admins'),
    ('S-1-5-32-548', 'Account Operators'), ('S-1-5-32-551', 'Backup Operators'), ('S-1-5-32-549', 'Server Operators'), ('S-1-5-32-550', 'Print Operators'),
)
PROTECTED_USERS_RID = 525
DOMAIN_PROPERTIES = [
    'ms-DS-MachineAccountQuota',
    'minPwdLength', 'pwdHistoryLength', 'maxPwdAge', 'minPwdAge',
    'lockoutThreshold', 'lockoutDuration', 'pwdProperties',
]


def attributes(entry):
    return {key.lower(): value for key, value in entry.get('attributes', {}).items()}


def first(value):
    return value[0] if isinstance(value, (list, tuple)) and value else value


def number(value):
    try:
        return int(first(value))
    except (TypeError, ValueError):
        return None


def text(value):
    value = first(value)
    if value is None or value == []:
        return ''
    return value.decode('utf-8', errors='replace') if isinstance(value, bytes) else str(value)


def sid(value):
    value = first(value)
    return format_sid(value) if isinstance(value, bytes) else text(value)


def timestamp(value):
    value = first(value)
    if isinstance(value, datetime):
        result = value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
        return result if result > EPOCH else None
    ticks = number(value)
    if ticks is not None:
        if ticks <= 0:
            return None
        try:
            result = EPOCH + timedelta(microseconds=ticks // 10)
            return result if result.year > 1601 else None
        except OverflowError:
            return None
    try:
        result = datetime.fromisoformat(text(value).replace('Z', '+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except ValueError:
        return None


def never_set(value):
    value = first(value)
    return number(value) == 0 or (isinstance(value, datetime) and timestamp(value) is None)


def iso(value):
    return value.isoformat() if value else None


def interval_seconds(value):
    value = first(value)
    if value == timedelta.max:
        return NEVER
    if isinstance(value, timedelta):
        return abs(value.total_seconds())
    ticks = number(value)
    if ticks == -9223372036854775808:
        return NEVER
    return abs(ticks) / 10000000 if ticks is not None else None


def listed(values):
    values = values if isinstance(values, list) else [values]
    return text(values) + (f' (+{len(values) - 1} more)' if len(values) > 1 else '')


def object_row(entry, attrs):
    return {
        'dn': text(entry.get('dn') or attrs.get('distinguishedname')),
        'name': text(attrs.get('samaccountname') or attrs.get('name')) or 'Unnamed object',
    }


@dataclass(frozen=True)
class Account:
    row: dict
    attrs: dict
    uac: int | None
    last_logon: datetime | None
    password_set: datetime | None
    password_never_set: bool

    @classmethod
    def from_entry(cls, entry):
        attrs = attributes(entry)
        return cls(
            object_row(entry, attrs), attrs, number(attrs.get('useraccountcontrol')),
            timestamp(attrs.get('lastlogontimestamp')), timestamp(attrs.get('pwdlastset')), never_set(attrs.get('pwdlastset')),
        )

    @property
    def enabled(self):
        return self.uac is not None and not self.uac & ACCOUNTDISABLE

    @property
    def password(self):
        return NEVER if self.password_never_set else iso(self.password_set)

    @property
    def operating_system(self):
        return text(self.attrs.get('operatingsystem')) or 'Not reported'

    def flagged(self, flags):
        return self.uac is not None and bool(self.uac & flags)


@dataclass(frozen=True)
class Signal:
    key: str
    ldap_filter: str
    order: str
    matches: Callable[[Account], bool]
    evidence: Callable[[Account], str] | None = None


def flag_filter(flags):
    return f'(userAccountControl:{ALL_BITS}:={flags})'


def stale_signal(cutoff):
    ticks = (cutoff - EPOCH) // timedelta(microseconds=1) * 10
    return Signal(
        'stale', f'(lastLogonTimestamp>=1)(lastLogonTimestamp<={ticks - 1})', 'last_logon',
        lambda account: account.last_logon is not None and account.last_logon < cutoff,
    )


USER_SIGNALS = (
    Signal('preauth', flag_filter(DONT_REQ_PREAUTH), 'password_set', lambda account: account.flagged(DONT_REQ_PREAUTH)),
    Signal(
        'spn', '(servicePrincipalName=*)(!(sAMAccountName=krbtgt))', 'password_set',
        lambda account: bool(account.attrs.get('serviceprincipalname')) and account.row['name'].lower() != 'krbtgt',
        lambda account: listed(account.attrs['serviceprincipalname']),
    ),
    Signal('password_not_required', flag_filter(PASSWD_NOTREQD), 'password_set', lambda account: account.flagged(PASSWD_NOTREQD)),
    Signal('never_expires', flag_filter(DONT_EXPIRE_PASSWORD), 'password_set', lambda account: account.flagged(DONT_EXPIRE_PASSWORD)),
    Signal('admin', '(adminCount=1)', 'password_set', lambda account: number(account.attrs.get('admincount')) == 1),
)
COMPUTER_SIGNALS = (
    Signal('pre2k', '(userAccountControl=4128)(logonCount=0)', 'password_set', lambda account: account.uac == 4128 and number(account.attrs.get('logoncount')) == 0),
    Signal(
        'unconstrained', f'{flag_filter(TRUSTED_FOR_DELEGATION)}(!(userAccountControl:{ANY_BIT}:={CONTROLLER}))', 'name',
        lambda account: account.flagged(TRUSTED_FOR_DELEGATION) and not account.flagged(CONTROLLER),
    ),
    Signal(
        'constrained', '(msDS-AllowedToDelegateTo=*)', 'name',
        lambda account: bool(account.attrs.get('msds-allowedtodelegateto')),
        lambda account: listed(account.attrs['msds-allowedtodelegateto']),
    ),
    Signal('password_not_required', flag_filter(PASSWD_NOTREQD), 'password_set', lambda account: account.flagged(PASSWD_NOTREQD)),
)
ORDERS = {
    'password_set': lambda account: (not account.password_never_set, account.password_set is None, account.password_set or EPOCH),
    'last_logon': lambda account: (account.last_logon is None, account.last_logon or EPOCH),
    'name': lambda account: account.row['name'].lower(),
}


class Collection:
    def __init__(self, powerview, fresh=False, now=None):
        self.powerview = powerview
        self.fresh = fresh
        self.now = now or datetime.now(timezone.utc)
        self.read_at = None
        self.cached = False

    def read(self, method, **kwargs):
        started = datetime.now(timezone.utc)
        with track_query_reads() as reads:
            entries = getattr(self.powerview, method)(raw=True, no_cache=self.fresh, no_vuln_check=True, **kwargs)
            if entries is None or entries is False:
                raise ValueError('The directory did not return a result. Check the session and permissions.')
            entries = list(entries)
        if any(not isinstance(entry, Mapping) or not isinstance(entry.get('attributes'), Mapping) for entry in entries):
            raise ValueError('The directory returned an unexpected result.')
        if reads.read_at is None:
            for entry in entries:
                if entry.get('from_cache'):
                    reads.record(timestamp(entry.get('read_at')) or started, cached=True)
        self.cached = self.cached or reads.cached
        self.read_at = min(filter(None, (self.read_at, reads.read_at or started)))
        return entries


def domain_summary(collection, **_):
    entries = collection.read('get_domain', properties=DOMAIN_PROPERTIES, search_scope='BASE')
    if not entries:
        raise ValueError('The domain object is not readable in this session.')
    attrs = attributes(entries[0])
    policy = {key: number(attrs.get(key.lower())) for key in DOMAIN_PROPERTIES if key not in ['maxPwdAge', 'minPwdAge', 'lockoutDuration']}
    for key in ['maxPwdAge', 'minPwdAge', 'lockoutDuration']:
        policy[key] = interval_seconds(attrs.get(key.lower()))
    return {'policy': policy}


def sample(account, signal, kind):
    row = {**account.row, 'password_set': account.password, 'last_logon': iso(account.last_logon)}
    if kind == 'computers':
        row['os'] = account.operating_system
    if signal.evidence:
        row['evidence'] = signal.evidence(account)
    return row


class AccountSample:
    def __init__(self, signal):
        self.signal = signal
        self.count = 0
        self.items = []

    def add(self, account):
        self.count += 1
        item = (ORDERS[self.signal.order](account), self.count, account)
        if len(self.items) == SAMPLE_LIMIT:
            if item >= self.items[-1]:
                return
            self.items.pop()
        insort(self.items, item)

    def finding(self, kind):
        return {
            'count': self.count,
            'order': self.signal.order,
            'ldap_filter': f'(&{ENABLED_FILTER}{self.signal.ldap_filter})',
            'objects': [sample(account, self.signal, kind) for _, _, account in self.items],
        }


def account_summary(collection, kind, days=90):
    users = kind == 'users'
    signals = (USER_SIGNALS if users else COMPUTER_SIGNALS) + (stale_signal(collection.now - timedelta(days=days)),)
    entries = collection.read('get_domainuser' if users else 'get_domaincomputer', properties=USER_PROPERTIES if users else COMPUTER_PROPERTIES)
    matches = {signal.key: AccountSample(signal) for signal in signals}
    counts = Counter(total=len(entries), enabled=0, disabled=0, unknown=0, missing_logon=0, controllers=0)
    systems = Counter()
    controllers = []
    for entry in entries:
        account = Account.from_entry(entry)
        counts['unknown' if account.uac is None else 'enabled' if account.enabled else 'disabled'] += 1
        if account.enabled and account.last_logon is None:
            counts['missing_logon'] += 1
        if not users:
            systems[account.operating_system] += 1
            if account.flagged(CONTROLLER):
                counts['controllers'] += 1
                if len(controllers) < SAMPLE_LIMIT:
                    controllers.append({**account.row, 'host': text(account.attrs.get('dnshostname')), 'os': account.operating_system, 'enabled': account.enabled})
        if account.enabled:
            for signal in signals:
                if signal.matches(account):
                    matches[signal.key].add(account)
    return {
        'counts': dict(counts), 'inactive_days': days,
        'findings': {f'{kind}_{signal.key}': matches[signal.key].finding(kind) for signal in signals},
        'systems': [{'name': name, 'count': count} for name, count in sorted(systems.items(), key=lambda item: (-item[1], item[0]))],
        'controllers': controllers,
    }


def inventory_summary(collection, **_):
    entries = collection.read(
        'get_domainobject',
        ldap_filter='(|(objectClass=group)(objectClass=organizationalUnit)(objectClass=groupPolicyContainer)(objectClass=trustedDomain))',
        properties=['objectClass', 'name', 'distinguishedName', 'trustPartner', 'trustDirection', 'trustType', 'trustAttributes'],
    )
    counts = Counter(groups=0, ous=0, gpos=0, trusts=0)
    trusts = []
    for entry in entries:
        attrs = attributes(entry)
        classes = attrs.get('objectclass', [])
        if not isinstance(classes, list):
            classes = [classes]
        classes = {text(value).lower() for value in classes}
        for name, key in [('group', 'groups'), ('organizationalunit', 'ous'), ('grouppolicycontainer', 'gpos'), ('trusteddomain', 'trusts')]:
            if name in classes:
                counts[key] += 1
        if 'trusteddomain' in classes and len(trusts) < SAMPLE_LIMIT:
            trusts.append({
                **object_row(entry, attrs), 'partner': text(attrs.get('trustpartner')),
                'direction': number(attrs.get('trustdirection')),
                'type': number(attrs.get('trusttype')), 'attributes': number(attrs.get('trustattributes')),
            })
    ca_error = None
    try:
        counts['cas'], counts['published_templates'] = authority_summary(collection)
    except (ValueError, LDAPException) as error:
        counts['cas'] = counts['published_templates'] = None
        ca_error = str(error) or 'Certificate authorities are not readable in this session.'
    return {'counts': dict(counts), 'trusts': trusts, 'ca_error': ca_error}


def authority_summary(collection):
    try:
        authorities = collection.read('get_domainca', properties=['name', 'dNSHostName', 'certificateTemplates'], check_all=False)
    except LDAPNoSuchObjectResult:
        return 0, 0
    templates = set()
    for entry in authorities:
        published = attributes(entry).get('certificatetemplates') or []
        templates.update(text(name).lower() for name in (published if isinstance(published, list) else [published]))
    return len(authorities), len(templates)


def group_members(collection, group_dn):
    member_filter = f'(&(objectCategory=person)(objectClass=user)(memberOf:{IN_CHAIN}:={escape_filter_chars(group_dn)}))'
    return collection.read('get_domainobject', ldap_filter=member_filter, properties=ACCOUNT_PROPERTIES)


def privileged_account(entry, now, days):
    account = Account.from_entry(entry)
    active = account.last_logon or account.password_set
    old_password = account.password_never_set or bool(account.password_set and account.password_set < now - timedelta(days=PASSWORD_AGE_DAYS))
    return {
        **account.row, 'groups': [], 'protected': False, 'enabled': account.enabled,
        'last_logon': iso(account.last_logon), 'password_set': account.password,
        'never_expires': account.flagged(DONT_EXPIRE_PASSWORD),
        'stale': bool(account.enabled and active and active < now - timedelta(days=days)),
        'old_password': account.enabled and old_password,
    }


def privileged_summary(collection, days=90):
    domain = collection.read('get_domain', properties=['objectSid'], search_scope='BASE')
    domain_sid = sid(attributes(domain[0]).get('objectsid')) if domain else ''
    labels = {key if isinstance(key, str) else f'{domain_sid}-{key}': label for key, label in PRIVILEGED_GROUPS if isinstance(key, str) or domain_sid}
    protected_sid = f'{domain_sid}-{PROTECTED_USERS_RID}' if domain_sid else ''
    wanted = [*labels, *([protected_sid] if protected_sid else [])]
    found = {}
    for entry in collection.read('get_domainobject', ldap_filter='(|' + ''.join(f'(objectSid={value})' for value in wanted) + ')', properties=['name', 'distinguishedName', 'objectSid']):
        attrs = attributes(entry)
        found[sid(attrs.get('objectsid'))] = {'dn': text(entry.get('dn') or attrs.get('distinguishedname')), 'name': text(attrs.get('name'))}
    protected = {object_row(entry, attributes(entry))['dn'].lower() for entry in group_members(collection, found[protected_sid]['dn'])} if protected_sid in found else set()
    accounts = {}
    groups = []
    for group_sid, label in labels.items():
        if group_sid not in found:
            continue
        name = found[group_sid]['name'] or label
        members = group_members(collection, found[group_sid]['dn'])
        for entry in members:
            account = privileged_account(entry, collection.now, days)
            account = accounts.setdefault(account['dn'].lower(), account)
            account['groups'].append(name)
        sampled = nsmallest(SAMPLE_LIMIT, members, key=lambda entry: object_row(entry, attributes(entry))['name'].lower())
        groups.append({
            'name': name, 'dn': found[group_sid]['dn'], 'count': len(members),
            'accounts': [accounts[object_row(entry, attributes(entry))['dn'].lower()] for entry in sampled],
        })
    for key, account in accounts.items():
        account['protected'] = key in protected
    ordered = sorted(accounts.values(), key=lambda item: item['name'].lower())
    enabled = [item for item in ordered if item['enabled']]
    counts = {
        'accounts': len(ordered), 'enabled': len(enabled),
        'unprotected': sum(not item['protected'] for item in enabled),
        'stale': sum(item['stale'] for item in enabled),
        'old_password': sum(item['old_password'] for item in enabled),
        'never_expires': sum(item['never_expires'] for item in enabled),
    }
    return {
        'counts': counts, 'groups': groups, 'accounts': ordered[:SAMPLE_LIMIT],
        'protected_users': protected_sid in found, 'inactive_days': days, 'password_age_days': PASSWORD_AGE_DAYS,
    }


SECTIONS = {
    'domain': domain_summary,
    'users': lambda collection, **options: account_summary(collection, 'users', **options),
    'computers': lambda collection, **options: account_summary(collection, 'computers', **options),
    'inventory': inventory_summary,
    'privileged': privileged_summary,
}


def dashboard_section(powerview, section, fresh=False, days=90):
    if days not in INACTIVE_DAYS:
        raise ValueError(f'Inactivity threshold must be one of {", ".join(map(str, INACTIVE_DAYS))} days.')
    context = {'domain': powerview.domain, 'root_dn': powerview.root_dn, 'dc': powerview.dc_dnshostname}
    collection = Collection(powerview, fresh)
    result = SECTIONS[section](collection, days=days)
    if context['root_dn'] != powerview.root_dn:
        raise ValueError('The connected domain changed during collection. Refresh to retry.')
    return {
        **result, **context, 'sample_limit': SAMPLE_LIMIT,
        'collected_at': datetime.now(timezone.utc).isoformat(),
        'read_at': iso(collection.read_at), 'cached': collection.cached,
    }
