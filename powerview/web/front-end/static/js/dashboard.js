document.addEventListener('DOMContentLoaded', async () => {
    try {
        await Promise.all([
            fetchDomainInfo(),
            fetchDomainTrusts(),
            fetchDomainControllers(),
            fetchCAServers(),
            fetchDNSZones(),
            fetchDomainAdmins(),
            fetchCriticalItems()
        ]);
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showErrorAlert('Failed to load some dashboard components');
    }

    // ── Helpers ──

    function esc(str) {
        const d = document.createElement('div');
        d.appendChild(document.createTextNode(str));
        return d.innerHTML;
    }

    function showErrorInCard(containerId) {
        const el = document.getElementById(containerId);
        if (el) {
            el.innerHTML = `
                <div class="flex items-center gap-2 text-red-400 text-sm py-2">
                    <i class="fas fa-exclamation-triangle text-xs"></i>
                    <span>Failed to load</span>
                </div>`;
        }
    }

    function renderStatBlock(label, value) {
        return `
            <div class="text-center lg:text-right">
                <div class="dash-stat-value text-neutral-900 dark:text-white">${value}</div>
                <div class="dash-label text-neutral-400 dark:text-neutral-500 mt-0.5">${label}</div>
            </div>`;
    }

    function countClass(n) {
        if (n === 0) return 'finding-count-info';
        return n >= 3 ? 'finding-count-crit' : 'finding-count-warn';
    }

    function renderFinding(label, count, users) {
        const links = users.map(u =>
            `<a href="#" class="dash-link"
                onclick="handleLdapLinkClick(event, '${esc(u.dn)}')"
                data-dn="${esc(u.dn)}">${esc(u.name)}</a>`
        ).join(', ');

        return `
            <div class="finding-row">
                <span class="finding-count ${countClass(count)}">${count}</span>
                <div class="min-w-0 flex-1">
                    <p class="text-sm font-medium text-neutral-800 dark:text-neutral-200">${label}</p>
                    ${count > 0 ? `<p class="text-sm text-neutral-500 dark:text-neutral-400 mt-0.5 leading-relaxed">${links}</p>` : ''}
                </div>
            </div>`;
    }

    // ── Fetchers ──

    async function fetchDomainInfo() {
        try {
            const response = await fetch('/api/get/domain', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    properties: [
                        'objectSid', 'maxPwdAge', 'lockoutDuration',
                        'lockoutThreshold', 'distinguishedName',
                        'ms-DS-MachineAccountQuota'
                    ]
                })
            });

            await handleHttpError(response);
            const data = await response.json();

            if (!data.length) throw new Error('No domain data found');

            const d = data[0].attributes;
            const maq = d['ms-DS-MachineAccountQuota'];

            // Domain identity
            document.getElementById('domain-dn').textContent = d.distinguishedName;
            const sidEl = document.getElementById('domain-sid');
            sidEl.textContent = d.objectSid;

            // Password policy card
            document.getElementById('password-policy').innerHTML = `
                <div class="space-y-2">
                    <div class="flex items-center justify-between">
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">Max Password Age</span>
                        <span class="dash-mono text-neutral-900 dark:text-white">${esc(String(d.maxPwdAge))}</span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">Lockout Duration</span>
                        <span class="dash-mono text-neutral-900 dark:text-white">${esc(String(d.lockoutDuration))}</span>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">Lockout Threshold</span>
                        <span class="dash-mono text-neutral-900 dark:text-white">${d.lockoutThreshold} attempts</span>
                    </div>
                    <div class="flex items-center justify-between pt-2 border-t border-neutral-200 dark:border-neutral-700/50">
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">Machine Account Quota</span>
                        <span class="dash-mono font-bold ${maq > 0 ? 'text-yellow-500' : 'text-neutral-900 dark:text-white'}">${maq}</span>
                    </div>
                </div>`;
        } catch (error) {
            console.error('Error fetching domain info:', error);
            document.getElementById('domain-dn').innerHTML = '<span class="text-neutral-500">—</span>';
            document.getElementById('domain-sid').innerHTML = '';
            showErrorInCard('password-policy');
        }
    }

    async function fetchDomainControllers() {
        try {
            const response = await fetch('/api/get/domaincontroller', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ properties: ['dNSHostName', 'operatingSystem'] })
            });

            await handleHttpError(response);
            const data = await response.json();

            const countEl = document.getElementById('dc-count');
            const container = document.getElementById('domain-stats');

            if (!data || data.length === 0) {
                countEl.textContent = '0';
                container.innerHTML = '<p class="text-sm text-neutral-500 dark:text-neutral-400 py-2">No domain controllers found</p>';
                return;
            }

            countEl.textContent = data.length;

            // Feed stat strip
            const strip = document.getElementById('stat-strip');
            strip.innerHTML += renderStatBlock('DCs', data.length);

            container.innerHTML = data.map(dc => `
                <div class="infra-item">
                    <p class="text-sm text-neutral-900 dark:text-white">${esc(dc.attributes.dNSHostName)}</p>
                    ${dc.attributes.operatingSystem
                        ? `<p class="text-xs text-neutral-500 dark:text-neutral-400">${esc(dc.attributes.operatingSystem)}</p>`
                        : ''}
                </div>
            `).join('');
        } catch (error) {
            console.error('Error fetching domain controllers:', error);
            showErrorInCard('domain-stats');
        }
    }

    async function fetchDomainTrusts() {
        try {
            const response = await fetch('/api/get/domaintrust');
            await handleHttpError(response);
            const data = await response.json();

            const countEl = document.getElementById('trust-count');
            const container = document.getElementById('domain-trusts');

            if (data.length === 0) {
                countEl.textContent = '0';
                container.innerHTML = '<p class="text-sm text-neutral-500 dark:text-neutral-400 py-2">No domain trusts found</p>';
                return;
            }

            countEl.textContent = data.length;

            const strip = document.getElementById('stat-strip');
            strip.innerHTML += renderStatBlock('Trusts', data.length);

            container.innerHTML = data.map(trust => {
                const t = trust.attributes;
                const direction = Array.isArray(t.trustDirection) ? t.trustDirection.join(', ') : t.trustDirection;
                const type = Array.isArray(t.trustType) ? t.trustType.join(', ') : t.trustType;
                return `
                    <div class="infra-item">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white">${esc(t.name)}</p>
                        <div class="flex flex-wrap gap-x-3 gap-y-0.5 mt-0.5">
                            <span class="text-xs text-neutral-500 dark:text-neutral-400">${esc(String(direction))}</span>
                            <span class="text-xs text-neutral-500 dark:text-neutral-400">${esc(String(type))}</span>
                        </div>
                    </div>`;
            }).join('');
        } catch (error) {
            console.error('Error fetching domain trusts:', error);
            showErrorInCard('domain-trusts');
        }
    }

    async function fetchCAServers() {
        try {
            const response = await fetch('/api/get/domainca');
            await handleHttpError(response);
            const data = await response.json();

            const container = document.getElementById('ca-servers');

            if (data.length === 0) {
                container.innerHTML = '<p class="text-sm text-neutral-500 dark:text-neutral-400 py-2">No CA servers found</p>';
                return;
            }

            const strip = document.getElementById('stat-strip');
            strip.innerHTML += renderStatBlock('CAs', data.length);

            container.innerHTML = data.map(ca => `
                <div class="infra-item">
                    <p class="text-sm text-neutral-900 dark:text-white">${esc(ca.attributes.cn)}</p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">${esc(ca.attributes.dNSHostName)}</p>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error fetching CA servers:', error);
            showErrorInCard('ca-servers');
        }
    }

    async function fetchDNSZones() {
        try {
            const response = await fetch('/api/get/domaindnszone');
            await handleHttpError(response);
            const data = await response.json();

            const container = document.getElementById('dns-zones');

            if (!data || data.length === 0) {
                container.innerHTML = '<p class="text-sm text-neutral-500 dark:text-neutral-400 py-2">No DNS zones found</p>';
                return;
            }

            const strip = document.getElementById('stat-strip');
            strip.innerHTML += renderStatBlock('DNS', data.length);

            container.innerHTML = data.map(zone => `
                <div class="infra-item">
                    <p class="text-sm text-neutral-900 dark:text-white">${esc(zone.attributes.name)}</p>
                    <p class="text-xs text-neutral-500 dark:text-neutral-400">${esc(String(zone.attributes.whenChanged))}</p>
                </div>
            `).join('');
        } catch (error) {
            console.error('Error fetching DNS zones:', error);
            showErrorInCard('dns-zones');
        }
    }

    async function fetchDomainAdmins() {
        try {
            const response = await fetch('/api/get/domaingroupmember', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity: 'Domain Admins' })
            });
            await handleHttpError(response);
            const data = await response.json();

            const countEl = document.getElementById('admin-count');
            const container = document.getElementById('domain-admins');

            if (data.length === 0) {
                countEl.textContent = '0';
                container.innerHTML = '<p class="text-sm text-neutral-500 dark:text-neutral-400 py-2">No domain admins found</p>';
                return;
            }

            countEl.textContent = `${data.length} members`;

            container.innerHTML = `
                <div class="flex flex-wrap gap-2">
                    ${data.map(admin => `
                        <a href="#" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-sm
                            bg-neutral-100 dark:bg-neutral-700/60 text-neutral-800 dark:text-neutral-200
                            hover:bg-yellow-500/10 hover:text-yellow-700 dark:hover:text-yellow-400
                            transition-colors"
                            onclick="handleLdapLinkClick(event, '${esc(admin.attributes.MemberDistinguishedName)}')"
                            data-dn="${esc(admin.attributes.MemberDistinguishedName)}">
                            <i class="fas fa-user-shield text-[0.6rem] text-neutral-400 dark:text-neutral-500"></i>
                            ${esc(admin.attributes.MemberName)}
                        </a>
                    `).join('')}
                </div>`;
        } catch (error) {
            console.error('Error fetching domain admins:', error);
            showErrorInCard('domain-admins');
        }
    }

    async function fetchCriticalItems() {
        try {
            const [adminUsersResponse, kerberoastableResponse, computersResponse, constrainedDelegationResponse, inactiveUsersResponse] = await Promise.all([
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        args: { admincount: true, properties: ['samAccountName', 'memberOf'] }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        args: { spn: true, properties: ['samAccountName', 'adminCount'] }
                    })
                }),
                fetch('/api/get/domaincomputer', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        args: { unconstrained: true, properties: ['samAccountName'] }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        args: { trustedtoauth: true, properties: ['sAMAccountName'] }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        args: {
                            enabled: true,
                            properties: ['sAMAccountName', 'lastLogonTimestamp'],
                            ldapfilter: '(lastLogonTimestamp=-1)'
                        }
                    })
                })
            ]);

            const [adminUsers, kerberoastable, unconstrainedComputers, constrainedDelegation, inactiveUsers] = await Promise.all([
                adminUsersResponse.json(),
                kerberoastableResponse.json(),
                computersResponse.json(),
                constrainedDelegationResponse.json(),
                inactiveUsersResponse.json()
            ]);

            const domainAdmins = adminUsers.filter(user => {
                const m = user.attributes.memberOf;
                if (Array.isArray(m)) return m.some(g => g.toLowerCase().includes('cn=domain admins'));
                if (typeof m === 'string') return m.toLowerCase().includes('cn=domain admins');
                return false;
            });

            const kerberoastableAdmins = kerberoastable.filter(u => u.attributes.adminCount === 1);

            const toEntry = (list, nameKey) => list.map(u => ({
                dn: u.dn,
                name: u.attributes[nameKey] || u.attributes.sAMAccountName || u.attributes.samAccountName
            }));

            const findings = [
                { label: 'Kerberoastable Admins', data: toEntry(kerberoastableAdmins, 'sAMAccountName'), severity: 'crit' },
                { label: 'Kerberoastable Users', data: toEntry(kerberoastable, 'sAMAccountName') },
                { label: 'Unconstrained Delegation', data: toEntry(unconstrainedComputers, 'sAMAccountName') },
                { label: 'Constrained Delegation', data: toEntry(constrainedDelegation, 'sAMAccountName') },
                { label: 'Admin Count Users', data: toEntry(adminUsers, 'sAMAccountName') },
                { label: 'Inactive but Enabled', data: toEntry(inactiveUsers, 'sAMAccountName') },
            ];

            const total = findings.reduce((s, f) => s + f.data.length, 0);
            document.getElementById('findings-total').textContent = `${total} total`;

            const container = document.getElementById('critical-items');
            container.innerHTML = findings.map(f => renderFinding(f.label, f.data.length, f.data)).join('');

        } catch (error) {
            console.error('Error fetching critical items:', error);
            showErrorInCard('critical-items');
        }
    }
});
