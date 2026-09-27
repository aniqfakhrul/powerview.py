export const sources = { domain: 'Domain policy', inventory: 'Directory inventory', users: 'Users', computers: 'Computers' };

export const signals = [
  { key: 'users_preauth', source: 'users', label: 'No Kerberos pre-auth', description: 'Enabled users with DONT_REQ_PREAUTH. Review exposure to offline password guessing; this flag alone does not establish that an account can be compromised.' },
  { key: 'users_spn', source: 'users', label: 'Kerberoastable users', description: 'Enabled users with service principal names, excluding krbtgt. Review service-account password strength and ownership. An SPN is normal configuration, not a vulnerability by itself.' },
  { key: 'users_password_not_required', source: 'users', label: 'Password not required', description: 'Enabled users with PASSWD_NOTREQD. Review why the flag is set. It does not mean that the current password is blank.' },
  { key: 'users_never_expires', source: 'users', label: 'Password never expires', description: 'Enabled users with DONT_EXPIRE_PASSWORD. Confirm that each exception has an owner and a suitable credential-management process.' },
  { key: 'users_admin', source: 'users', label: 'Protected-account marker', description: 'Enabled users with adminCount = 1. This marker may persist after privileged group membership is removed; inspect current memberships and permissions.' },
  { key: 'users_stale', source: 'users', label: 'User logon > {days} days', description: 'Enabled users whose replicated lastLogonTimestamp is more than {days} days old. Replication makes this approximate. Missing timestamps are excluded; validate activity before disabling accounts.' },
  { key: 'computers_unconstrained', source: 'computers', label: 'Unconstrained delegation', description: 'Enabled computers with TRUSTED_FOR_DELEGATION, excluding domain controllers. Review delegated credential exposure and whether the service still needs this configuration.' },
  { key: 'computers_constrained', source: 'computers', label: 'Constrained delegation', description: 'Enabled computers with msDS-AllowedToDelegateTo. Evidence shows the first target SPN. Inspect the object for all targets and review whether delegation is still needed.' },
  { key: 'computers_password_not_required', source: 'computers', label: 'Machine password flag', description: 'Enabled computers with PASSWD_NOTREQD. Review provisioning and account ownership; the flag does not prove an empty machine password.' },
  { key: 'computers_stale', source: 'computers', label: 'Computer logon > {days} days', description: 'Enabled computers whose replicated lastLogonTimestamp is more than {days} days old. Missing timestamps are excluded. Confirm decommissioning or offline status before taking action.' },
];
