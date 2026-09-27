from collections import Counter
from collections.abc import Mapping
from datetime import datetime, timedelta, timezone


SAMPLE_LIMIT = 100
INACTIVE_DAYS = (30, 60, 90, 180)
NEVER = 'never'
ACCOUNT_PROPERTIES = [
    'name', 'sAMAccountName', 'distinguishedName', 'userAccountControl',
    'lastLogonTimestamp',
]
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
    return {'counts': dict(counts), 'trusts': trusts}


SECTIONS = {
    'domain': domain_summary,
    'users': lambda powerview, **options: account_summary(powerview, 'users', **options),
    'computers': lambda powerview, **options: account_summary(powerview, 'computers', **options),
    'inventory': inventory_summary,
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
