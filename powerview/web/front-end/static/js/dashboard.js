document.addEventListener('DOMContentLoaded', async () => {
    showLoadingIndicator();
    try {
        await Promise.all([
            fetchDomainInfo(),
            fetchDomainTrusts(),
            fetchDomainStats(),
            fetchCAServers(),
            fetchDNSZones(),
            fetchDomainAdmins(),
            fetchCriticalItems()
        ]);
    } catch (error) {
        console.error('Error loading dashboard:', error);
        showErrorAlert('Failed to load some dashboard components');
    } finally {
        hideLoadingIndicator();
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
                }),
                fetch('/api/get/domaincontroller', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        properties: ['dNSHostName']
                    })
                })
            ]);

            await Promise.all([handleHttpError(domainResponse), handleHttpError(dcResponse)]);
            const [domainData, dcData] = await Promise.all([domainResponse.json(), dcResponse.json()]);

            if (!domainData.length || !dcData.length) {
                throw new Error('No domain or DC data found');
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
                        <p class="text-neutral-900 dark:text-white">Lockout Threshold: ${domain.lockoutThreshold}</p>
                    </div>
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Machine Account Quota</p>
                        <p class="text-neutral-900 dark:text-white ${domain['ms-DS-MachineAccountQuota'] > 0 ? 'text-yellow-500' : ''}">${domain['ms-DS-MachineAccountQuota']}</p>
                    </div>
                    <div>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Domain Controllers</p>
                        <div class="space-y-1">
                            ${dcData.map(dc => `
                                <p class="text-neutral-900 dark:text-white">${dc.attributes.dNSHostName}</p>
                            `).join('')}
                        </div>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error fetching domain info:', error);
            showErrorInCard('domain-info');
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
                        <div class="flex items-center justify-between p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <div>
                                <p class="text-neutral-900 dark:text-white">${trust.attributes.name}</p>
                                <p class="text-sm text-neutral-500 dark:text-neutral-400">${trust.attributes.trustType}</p>
                            </div>
                            <i class="fas fa-${trust.attributes.trustDirection === 'Bidirectional' ? 'exchange-alt' : 'arrow-right'} 
                                text-neutral-500 dark:text-neutral-400"></i>
                        </div>
                    `).join('')}
                </div>
            `;
        } catch (error) {
            console.error('Error fetching domain trusts:', error);
            showErrorInCard('domain-trusts');
        }
    }

    async function fetchDomainStats() {
        try {
            const [usersResponse, computersResponse, groupsResponse] = await Promise.all([
                fetch('/api/get/domainuser', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        properties: ['cn']
                    })
                }),
                fetch('/api/get/domaincomputer', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        properties: ['cn']
                    })
                }),
                fetch('/api/get/domaingroup', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        properties: ['cn']
                    })
                })
            ]);

            const [users, computers, groups] = await Promise.all([
                usersResponse.json(),
                computersResponse.json(),
                groupsResponse.json()
            ]);

            const container = document.getElementById('domain-stats');
            container.innerHTML = `
                <div class="grid grid-cols-3 gap-4">
                    <div class="text-center">
                        <p class="text-2xl font-bold text-neutral-900 dark:text-white">${users.length}</p>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Users</p>
                    </div>
                    <div class="text-center">
                        <p class="text-2xl font-bold text-neutral-900 dark:text-white">${computers.length}</p>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Computers</p>
                    </div>
                    <div class="text-center">
                        <p class="text-2xl font-bold text-neutral-900 dark:text-white">${groups.length}</p>
                        <p class="text-sm text-neutral-500 dark:text-neutral-400">Groups</p>
                    </div>
                </div>
            `;
        } catch (error) {
            console.error('Error fetching domain stats:', error);
            showErrorInCard('domain-stats');
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
                    identity: 'Domain Admins'
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
                <div class="space-y-2">
                    ${data.slice(0, 3).map(admin => `
                        <div class="p-2 rounded bg-neutral-50 dark:bg-neutral-700">
                            <p class="text-neutral-900 dark:text-white">${admin.attributes.MemberName}</p>
                            <p class="text-sm text-neutral-500 dark:text-neutral-400">${admin.attributes.MemberDomain}</p>
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
            console.error('Error fetching domain admins:', error);
            showErrorInCard('domain-admins');
        }
    }

    async function fetchCriticalItems() {
        try {
            const [usersResponse, computersResponse] = await Promise.all([
                fetch('/api/get/domainuser'),
                fetch('/api/get/domaincomputer')
            ]);

            const [adminUsers, unconstrainedComputers] = await Promise.all([
                usersResponse.json(),
                computersResponse.json()
            ]);

            const container = document.getElementById('critical-items');
            container.innerHTML = `
                <div class="space-y-4">
                    <div>
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Users with Admin Count
                        </p>
                        <p class="text-2xl font-bold text-red-500">${adminUsers.length}</p>
                    </div>
                    <div>
                        <p class="text-sm font-medium text-neutral-900 dark:text-white mb-2">
                            Unconstrained Delegation
                        </p>
                        <p class="text-2xl font-bold text-red-500">${unconstrainedComputers.length}</p>
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
