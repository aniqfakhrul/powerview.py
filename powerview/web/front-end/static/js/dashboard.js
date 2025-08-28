document.addEventListener('DOMContentLoaded', async () => {
    // showLoadingIndicator();
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
    } finally {
        // hideLoadingIndicator();
    }

    async function fetchDomainInfo() {
        try {
            const [domainResponse, dcResponse] = await Promise.all([
                fetch('/api/get/domain', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        properties: [
                            'objectSid',
                            'maxPwdAge',
                            'lockoutDuration',
                            'lockoutThreshold',
                            'distinguishedName',
                            'ms-DS-MachineAccountQuota'
                        ]
                    })
                })
            ]);

            await handleHttpError(domainResponse);
            const domainData = await domainResponse.json();

            if (!domainData.length) {
                throw new Error('No domain data found');
            }

            const domain = domainData[0].attributes;
            const container = document.getElementById('domain-info');
            
            container.innerHTML = `
                <div class="space-y-3">
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Distinguished Name</p>
                        <p class="text-neutral-900 dark:text-white">${domain.distinguishedName}</p>
                    </div>
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Domain SID</p>
                        <p class="text-neutral-900 dark:text-white">${domain.objectSid}</p>
                    </div>
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Password Policy</p>
                        <p class="text-neutral-900 dark:text-white">Max Age: ${domain.maxPwdAge}</p>
                        <p class="text-neutral-900 dark:text-white">Lockout Duration: ${domain.lockoutDuration}</p>
                        <p class="text-neutral-900 dark:text-white">Lockout Threshold: ${domain.lockoutThreshold} attempts</p>
                    </div>
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Machine Account Quota</p>
                        <p class="text-neutral-900 dark:text-white ${domain['ms-DS-MachineAccountQuota'] > 0 ? 'text-yellow-500' : ''}">${domain['ms-DS-MachineAccountQuota']}</p>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error fetching domain info:', error);
            showErrorInCard('domain-info');
        }
    }

    async function fetchDomainControllers() {
        try {
            const response = await fetch('/api/get/domaincontroller', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    properties: ['dNSHostName', 'operatingSystem']
                })
            });

            await handleHttpError(response);
            const data = await response.json();
            
            const container = document.getElementById('domain-stats');
            if (!data || data.length === 0) {
                container.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No domain controllers found</p>';
                return;
            }

            container.innerHTML = `
                <div class="space-y-2 max-h-48 overflow-y-auto scrollbar">
                    ${data.map(dc => `
                        <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <p class="text-neutral-900 dark:text-white">${dc.attributes.dNSHostName}</p>
                            ${dc.attributes.operatingSystem ? 
                                `<p class="text-sm text-neutral-500 dark:text-neutral-400">${dc.attributes.operatingSystem}</p>` 
                                : ''}
                        </div>
                    `).join('')}
                </div>
            `;
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
            
            const container = document.getElementById('domain-trusts');
            if (data.length === 0) {
                container.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No domain trusts found</p>';
                return;
            }

            container.innerHTML = `
                <div class="space-y-2">
                    ${data.map(trust => `
                        <div class="flex flex-col p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <div class="flex items-center justify-between">
                                <div>
                                    <p class="text-neutral-900 dark:text-white">${trust.attributes.name}</p>
                                </div>
                            </div>
                            <div class="mt-2 text-sm">
                                <p class="text-neutral-500 dark:text-neutral-400">
                                    Type: ${trust.attributes.trustType.join(', ')}
                                </p>
                                <p class="text-neutral-500 dark:text-neutral-400">
                                    SID: ${trust.attributes.securityIdentifier}
                                </p>
                                <p class="text-neutral-500 dark:text-neutral-400">
                                    Direction: ${trust.attributes.trustDirection.join(', ')}
                                </p>
                                <p class="text-neutral-500 dark:text-neutral-400">
                                    Attributes: ${trust.attributes.trustAttributes}
                                </p>
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
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
                container.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No CA servers found</p>';
                return;
            }

            container.innerHTML = `
                <div class="space-y-2">
                    ${data.slice(0, 3).map(ca => `
                        <div class="flex items-center justify-between p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <div>
                                <p class="text-neutral-900 dark:text-white">${ca.attributes.cn}</p>
                                <p class="text-sm text-neutral-500 dark:text-neutral-400">${ca.attributes.dNSHostName}</p>
                            </div>
                            <i class="fas fa-certificate text-neutral-500 dark:text-neutral-400"></i>
                        </div>
                    `).join('')}
                    ${data.length > 3 ? `
                        <p class="text-sm text-neutral-500 dark:text-neutral-400 text-right">
                            And ${data.length - 3} more...
                        </p>
                    ` : ''}
                </div>
            `;
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
                container.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No DNS zones found</p>';
                return;
            }

            container.innerHTML = `
                <div class="space-y-2">
                    ${data.slice(0, 3).map(zone => `
                        <div class="flex items-center justify-between p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <div>
                                <p class="text-neutral-900 dark:text-white">${zone.attributes.name}</p>
                                <p class="text-sm text-neutral-500 dark:text-neutral-400">
                                    ${zone.attributes.whenChanged}
                                </p>
                            </div>
                            <i class="fas fa-globe text-neutral-500 dark:text-neutral-400"></i>
                        </div>
                    `).join('')}
                    ${data.length > 3 ? `
                        <p class="text-sm text-neutral-500 dark:text-neutral-400 text-right">
                            And ${data.length - 3} more...
                        </p>
                    ` : ''}
                </div>
            `;
        } catch (error) {
            console.error('Error fetching DNS zones:', error);
            showErrorInCard('dns-zones');
        }
    }

    async function fetchDomainAdmins() {
        try {
            const response = await fetch('/api/get/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    identity: 'Domain Admins',
                })
            });
            await handleHttpError(response);
            const data = await response.json();
            
            const container = document.getElementById('domain-admins');
            if (data.length === 0) {
                container.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No domain admins found</p>';
                return;
            }

            container.innerHTML = `
                <div class="space-y-2 max-h-48 overflow-y-auto scrollbar">
                    ${data.map(admin => `
                        <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <a href="#" 
                               class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                               onclick="handleLdapLinkClick(event, '${admin.attributes.MemberDistinguishedName}')"
                               data-dn="${admin.attributes.MemberDistinguishedName}">
                                ${admin.attributes.MemberName}
                            </a>
                            <p class="text-sm text-neutral-500 dark:text-neutral-400">${admin.attributes.MemberDomain}</p>
                        </div>
                    `).join('')}
                </div>
            `;
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
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        args: {
                            admincount: true,
                            properties: ['samAccountName', 'memberOf']
                        }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        args: {
                            spn: true,
                            properties: ['samAccountName', 'adminCount']
                        }
                    })
                }),
                fetch('/api/get/domaincomputer', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        args: {
                            unconstrained: true,
                            properties: ['samAccountName']
                        }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        args: {
                            trustedtoauth: true,
                            properties: ['sAMAccountName']
                        }
                    })
                }),
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        args: {
                            enabled: true,
                            properties: ['sAMAccountName', 'lastLogonTimestamp'],
                            ldapfilter: '(lastLogonTimestamp=-1)'
                        },
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
                const memberOf = user.attributes.memberOf;
                // Handle both string and array cases
                if (Array.isArray(memberOf)) {
                    return memberOf.some(group => group.toLowerCase().includes('cn=domain admins'));
                } else if (typeof memberOf === 'string') {
                    return memberOf.toLowerCase().includes('cn=domain admins');
                }
                return false;
            });    

            // Filter kerberoastable users to find those with adminCount=1
            const kerberoastableAdmins = kerberoastable.filter(user => user.attributes.adminCount === 1);

            const container = document.getElementById('critical-items');
            container.innerHTML = `
                <div class="space-y-4 overflow-y-auto scrollbar">
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Domain Admins (${domainAdmins.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${domainAdmins.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                onclick="handleLdapLinkClick(event, '${user.dn}')"
                                data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Users with Admin Count (${adminUsers.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${adminUsers.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                   onclick="handleLdapLinkClick(event, '${user.dn}')"
                                   data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Kerberoastable Users (${kerberoastable.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${kerberoastable.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                   onclick="handleLdapLinkClick(event, '${user.dn}')"
                                   data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Kerberoastable Admins (${kerberoastableAdmins.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${kerberoastableAdmins.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                   onclick="handleLdapLinkClick(event, '${user.dn}')"
                                   data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Unconstrained Delegation (${unconstrainedComputers.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${unconstrainedComputers.map(computer => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                   onclick="handleLdapLinkClick(event, '${computer.dn}')"
                                   data-dn="${computer.dn}">${computer.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Constrained Delegation (${constrainedDelegation.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${constrainedDelegation.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                onclick="handleLdapLinkClick(event, '${user.dn}')"
                                data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                    <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Inactive Users but still Enabled (${inactiveUsers.length})
                        </p>
                        <p class="text-sm text-neutral-600 dark:text-neutral-300">
                            ${inactiveUsers.map(user => `
                                <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                   onclick="handleLdapLinkClick(event, '${user.dn}')"
                                   data-dn="${user.dn}">${user.attributes.sAMAccountName}</a>
                            `).join(', ')}
                        </p>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error fetching critical items:', error);
            showErrorInCard('critical-items');
        }
    }

    function showErrorInCard(containerId) {
        const container = document.getElementById(containerId);
        if (container) {
            container.innerHTML = `
                <div class="text-red-500 dark:text-red-400">
                    <i class="fas fa-exclamation-circle"></i>
                    <span class="ml-2">Failed to load data</span>
                </div>
            `;
        }
    }
});
