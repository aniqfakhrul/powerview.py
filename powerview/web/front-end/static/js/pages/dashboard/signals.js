export const sources = { domain: 'Domain policy', inventory: 'Directory inventory', users: 'Users', computers: 'Computers', privileged: 'Privileged access' };

export const thresholdSources = ['users', 'computers', 'privileged'];

export const groups = [['exposure', 'Credential exposure'], ['hygiene', 'Account hygiene']];

export const columns = {
  name: { label: 'Account' },
  password_set: { label: 'Password set', date: true },
  last_logon: { label: 'Last logon', date: true },
  os: { label: 'Operating system' },
  evidence: { mono: true },
};

export const orders = { password_set: 'oldest password first', last_logon: 'oldest logon first', name: 'by name' };

export const signals = [
  { key: 'users_preauth', source: 'users', group: 'exposure', label: 'No Kerberos pre-auth', flag: 'DONT_REQ_PREAUTH', columns: ['password_set', 'last_logon'], description: 'Enabled users with DONT_REQ_PREAUTH. Review exposure to offline password guessing; this flag alone does not establish that an account can be compromised.' },
  { key: 'users_spn', source: 'users', group: 'exposure', label: 'Kerberoastable users', flag: 'servicePrincipalName', evidence: 'Service principal name', columns: ['evidence', 'password_set'], description: 'Enabled users with service principal names, excluding krbtgt. Any domain user can request service tickets for these accounts and attempt to crack them offline, so weak passwords are the risk. Review password strength, rotation and ownership, and prefer managed service accounts.' },
  { key: 'computers_unconstrained', source: 'computers', group: 'exposure', label: 'Unconstrained delegation', flag: 'TRUSTED_FOR_DELEGATION', columns: ['os', 'last_logon'], description: 'Enabled computers with TRUSTED_FOR_DELEGATION, excluding domain controllers. Review delegated credential exposure and whether the service still needs this configuration.' },
  { key: 'computers_constrained', source: 'computers', group: 'exposure', label: 'Constrained delegation', flag: 'msDS-AllowedToDelegateTo', evidence: 'Delegation target', columns: ['evidence', 'last_logon'], description: 'Enabled computers with msDS-AllowedToDelegateTo. The first target is shown; inspect the object for all targets and review whether delegation is still needed.' },
  { key: 'users_never_expires', source: 'users', group: 'hygiene', label: 'Password never expires', flag: 'DONT_EXPIRE_PASSWORD', columns: ['password_set', 'last_logon'], description: 'Enabled users with DONT_EXPIRE_PASSWORD. Confirm that each exception has an owner and a suitable credential-management process.' },
  { key: 'users_password_not_required', source: 'users', group: 'hygiene', label: 'User password not required', flag: 'PASSWD_NOTREQD', columns: ['password_set', 'last_logon'], description: 'Enabled users with PASSWD_NOTREQD. Review why the flag is set. It does not mean that the current password is blank.' },
  { key: 'computers_password_not_required', source: 'computers', group: 'hygiene', label: 'Computer password not required', flag: 'PASSWD_NOTREQD', columns: ['password_set', 'last_logon'], description: 'Enabled computers with PASSWD_NOTREQD. Review provisioning and account ownership; the flag does not prove an empty machine password.' },
  { key: 'users_admin', source: 'users', group: 'hygiene', label: 'adminCount set', flag: 'adminCount = 1', columns: ['password_set', 'last_logon'], description: 'Enabled users with adminCount = 1. This marker may persist after privileged group membership is removed; compare with Privileged access and inspect current memberships.' },
  { key: 'users_stale', source: 'users', group: 'hygiene', label: 'User logon > {days} days', flag: 'lastLogonTimestamp', columns: ['last_logon', 'password_set'], description: 'Enabled users whose replicated lastLogonTimestamp is more than {days} days old. Replication makes this approximate. Missing timestamps are excluded; validate activity before disabling accounts.' },
  { key: 'computers_stale', source: 'computers', group: 'hygiene', label: 'Computer logon > {days} days', flag: 'lastLogonTimestamp', columns: ['last_logon', 'os'], description: 'Enabled computers whose replicated lastLogonTimestamp is more than {days} days old. Missing timestamps are excluded. Confirm decommissioning or offline status before taking action.' },
];
