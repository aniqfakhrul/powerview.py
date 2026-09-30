from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone

from ldap3.core.exceptions import LDAPException, LDAPNoSuchObjectResult
from ldap3.protocol.formatters.formatters import format_sid
from ldap3.utils.conv import escape_filter_chars


SAMPLE_LIMIT = 100
INACTIVE_DAYS = (30, 60, 90, 180)
NEVER = 'never'
ACCOUNT_PROPERTIES = [
    'name', 'sAMAccountName', 'distinguishedName', 'userAccountControl',
    'lastLogonTimestamp',
]
PASSWORD_AGE_DAYS = 365
IN_CHAIN = '1.2.840.113556.1.4.1941'
PRIVILEGED_GROUPS = (
    ('S-1-5-32-544', 'Administrators'), (512, 'Domain Admins'), (519, 'Enterprise Admins'), (518, 'Schema Admins'),
    ('S-1-5-32-548', 'Account Operators'), ('S-1-5-32-551', 'Backup Operators'), ('S-1-5-32-549', 'Server Operators'), ('S-1-5-32-550', 'Print Operators'),
)
PROTECTED_USERS_RID = 525
PRIVILEGED_PROPERTIES = ['name', 'sAMAccountName', 'distinguishedName', 'userAccountControl', 'lastLogonTimestamp', 'pwdLastSet']
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
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)
    ticks = number(value)
    if ticks is not None:
        if ticks <= 0:
            return None
        try:
            result = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)
            return result if result.year > 1601 else None
        except OverflowError:
            return None
    try:
        result = datetime.fromisoformat(text(value).replace('Z', '+00:00'))
        return result.replace(tzinfo=timezone.utc) if result.tzinfo is None else result.astimezone(timezone.utc)
    except ValueError:
        return None


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


def object_row(entry, attrs):
    return {
        'dn': text(entry.get('dn') or attrs.get('distinguishedname')),
        'name': text(attrs.get('samaccountname') or attrs.get('name')) or 'Unnamed object',
    }


def read(powerview, method, fresh=False, **kwargs):
    entries = getattr(powerview, method)(raw=True, no_cache=fresh, no_vuln_check=True, **kwargs)
    if entries is None or entries is False:
        raise ValueError('The directory did not return a result. Check the session and permissions.')
    entries = list(entries)
    if any(not isinstance(entry, Mapping) or not isinstance(entry.get('attributes'), Mapping) for entry in entries):
        raise ValueError('The directory returned an unexpected result.')
    return entries


def domain_summary(powerview, fresh=False, **_):
    entries = read(powerview, 'get_domain', fresh, properties=DOMAIN_PROPERTIES, search_scope='BASE')
    if not entries:
        raise ValueError('The domain object is not readable in this session.')
    attrs = attributes(entries[0])
    policy = {key: number(attrs.get(key.lower())) for key in DOMAIN_PROPERTIES if key not in ['maxPwdAge', 'minPwdAge', 'lockoutDuration']}
    for key in ['maxPwdAge', 'minPwdAge', 'lockoutDuration']:
        policy[key] = interval_seconds(attrs.get(key.lower()))
    return {'policy': policy}


def account_summary(powerview, kind, now=None, fresh=False, days=90):
    now = now or datetime.now(timezone.utc)
    properties = ACCOUNT_PROPERTIES + (['adminCount', 'servicePrincipalName'] if kind == 'users' else [
        'dNSHostName', 'operatingSystem', 'msDS-AllowedToDelegateTo',
    ])
    entries = read(powerview, 'get_domainuser' if kind == 'users' else 'get_domaincomputer', fresh, properties=properties)
    keys = ['preauth', 'spn', 'password_not_required', 'never_expires', 'admin', 'stale'] if kind == 'users' else ['unconstrained', 'constrained', 'password_not_required', 'stale']
    findings = {f'{kind}_{key}': {'count': 0, 'objects': []} for key in keys}
    counts = Counter(total=len(entries), enabled=0, disabled=0, unknown=0, missing_logon=0, controllers=0)
    systems = Counter()
    controllers = []

    def add(key, row, evidence):
        finding = findings[f'{kind}_{key}']
        finding['count'] += 1
        if len(finding['objects']) < SAMPLE_LIMIT:
            finding['objects'].append({**row, 'evidence': evidence})

    for entry in entries:
        attrs = attributes(entry)
        row = object_row(entry, attrs)
        uac = number(attrs.get('useraccountcontrol'))
        enabled = uac is not None and not uac & 2
        counts['unknown' if uac is None else 'enabled' if enabled else 'disabled'] += 1
        is_dc = uac is not None and bool(uac & (8192 | 67108864))
        last_logon = timestamp(attrs.get('lastlogontimestamp'))
        if enabled and last_logon is None:
            counts['missing_logon'] += 1
        if kind == 'computers':
            os_name = text(attrs.get('operatingsystem')) or 'Not reported'
            systems[os_name] += 1
            if is_dc:
                counts['controllers'] += 1
                if len(controllers) < SAMPLE_LIMIT:
                    controllers.append({**row, 'host': text(attrs.get('dnshostname')), 'os': os_name, 'enabled': enabled})
        if not enabled:
            continue
        if last_logon and last_logon < now - timedelta(days=days):
            add('stale', row, f'Last replicated logon: {last_logon.date().isoformat()}')
        if uac & 32:
            add('password_not_required', row, 'PASSWD_NOTREQD is set')
        if kind == 'users':
            if uac & 4194304:
                add('preauth', row, 'DONT_REQ_PREAUTH is set')
            if attrs.get('serviceprincipalname') and row['name'].lower() != 'krbtgt':
                spns = attrs['serviceprincipalname']
                add('spn', row, text(spns) + (f' (+{len(spns) - 1} more)' if isinstance(spns, list) and len(spns) > 1 else ''))
            if uac & 65536:
                add('never_expires', row, 'DONT_EXPIRE_PASSWORD is set')
            if number(attrs.get('admincount')) == 1:
                add('admin', row, 'adminCount = 1')
        else:
            if uac & 524288 and not is_dc:
                add('unconstrained', row, 'TRUSTED_FOR_DELEGATION; not a domain controller')
            if attrs.get('msds-allowedtodelegateto'):
                add('constrained', row, text(attrs['msds-allowedtodelegateto']))
    return {
        'counts': dict(counts), 'findings': findings, 'inactive_days': days,
        'systems': [{'name': name, 'count': count} for name, count in sorted(systems.items(), key=lambda item: (-item[1], item[0]))],
        'controllers': controllers,
    }


def inventory_summary(powerview, fresh=False, **_):
    entries = read(
        powerview, 'get_domainobject', fresh,
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
        counts['cas'], counts['published_templates'] = authority_summary(powerview, fresh)
    except (ValueError, LDAPException) as error:
        counts['cas'] = counts['published_templates'] = None
        ca_error = str(error) or 'Certificate authorities are not readable in this session.'
    return {'counts': dict(counts), 'trusts': trusts, 'ca_error': ca_error}


def authority_summary(powerview, fresh=False):
    try:
        authorities = read(powerview, 'get_domainca', fresh, properties=['name', 'dNSHostName', 'certificateTemplates'], check_all=False)
    except LDAPNoSuchObjectResult:
        return 0, 0
    templates = set()
    for entry in authorities:
        published = attributes(entry).get('certificatetemplates') or []
        templates.update(text(name).lower() for name in (published if isinstance(published, list) else [published]))
    return len(authorities), len(templates)


def group_members(powerview, fresh, group_dn):
    member_filter = f'(&(objectCategory=person)(objectClass=user)(memberOf:{IN_CHAIN}:={escape_filter_chars(group_dn)}))'
    return read(powerview, 'get_domainobject', fresh, ldap_filter=member_filter, properties=PRIVILEGED_PROPERTIES)


def privileged_account(entry, now, days):
    attrs = attributes(entry)
    uac = number(attrs.get('useraccountcontrol'))
    enabled = uac is not None and not uac & 2
    last_logon = timestamp(attrs.get('lastlogontimestamp'))
    password_set = timestamp(attrs.get('pwdlastset'))
    active = last_logon or password_set
    return {
        **object_row(entry, attrs), 'groups': [], 'protected': False, 'enabled': enabled,
        'last_logon': last_logon.isoformat() if last_logon else None,
        'password_set': password_set.isoformat() if password_set else None,
        'never_expires': bool(uac and uac & 65536),
        'stale': bool(enabled and active and active < now - timedelta(days=days)),
        'old_password': bool(enabled and password_set and password_set < now - timedelta(days=PASSWORD_AGE_DAYS)),
    }


def privileged_summary(powerview, now=None, fresh=False, days=90):
    now = now or datetime.now(timezone.utc)
    domain = read(powerview, 'get_domain', fresh, properties=['objectSid'], search_scope='BASE')
    domain_sid = sid(attributes(domain[0]).get('objectsid')) if domain else ''
    labels = {key if isinstance(key, str) else f'{domain_sid}-{key}': label for key, label in PRIVILEGED_GROUPS if isinstance(key, str) or domain_sid}
    protected_sid = f'{domain_sid}-{PROTECTED_USERS_RID}' if domain_sid else ''
    wanted = [*labels, *([protected_sid] if protected_sid else [])]
    found = {}
    for entry in read(powerview, 'get_domainobject', fresh, ldap_filter='(|' + ''.join(f'(objectSid={value})' for value in wanted) + ')', properties=['name', 'distinguishedName', 'objectSid']):
        attrs = attributes(entry)
        found[sid(attrs.get('objectsid'))] = {'dn': text(entry.get('dn') or attrs.get('distinguishedname')), 'name': text(attrs.get('name'))}
    protected = {object_row(entry, attributes(entry))['dn'].lower() for entry in group_members(powerview, fresh, found[protected_sid]['dn'])} if protected_sid in found else set()
    accounts = {}
    groups = []
    for group_sid, label in labels.items():
        if group_sid not in found:
            continue
        name = found[group_sid]['name'] or label
        members = group_members(powerview, fresh, found[group_sid]['dn'])
        groups.append({'name': name, 'dn': found[group_sid]['dn'], 'count': len(members)})
        for entry in members:
            account = privileged_account(entry, now, days)
            account = accounts.setdefault(account['dn'].lower(), account)
            account['groups'].append(name)
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
    'users': lambda powerview, **options: account_summary(powerview, 'users', **options),
    'computers': lambda powerview, **options: account_summary(powerview, 'computers', **options),
    'inventory': inventory_summary,
    'privileged': privileged_summary,
}


def dashboard_section(powerview, section, fresh=False, days=90):
    if days not in INACTIVE_DAYS:
        raise ValueError(f'Inactivity threshold must be one of {", ".join(map(str, INACTIVE_DAYS))} days.')
    context = {'domain': powerview.domain, 'root_dn': powerview.root_dn, 'dc': powerview.dc_dnshostname}
    result = SECTIONS[section](powerview, fresh=fresh, days=days)
    if context['root_dn'] != powerview.root_dn:
        raise ValueError('The connected domain changed during collection. Refresh to retry.')
    return {
        **result, **context, 'sample_limit': SAMPLE_LIMIT,
        'collected_at': datetime.now(timezone.utc).isoformat(),
    }
