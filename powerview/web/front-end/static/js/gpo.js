document.addEventListener('DOMContentLoaded', async () => {
    let currentSelectedGPO = null;

    // Initialize the GPO tree view
    async function initialize() {
        try {
            showInitLoadingIndicator();
            
            // Get domain info first
            const domainInfo = await getDomainInfo();
            const rootDn = domainInfo.root_dn;
            const domain = domainInfo.domain;
            
            const treeView = document.getElementById('gpo-tree-view');
            treeView.innerHTML = ''; // Clear existing content

            // Create domain root node
            const domainContainer = document.createElement('div');
            domainContainer.className = 'mb-2';

            const domainDiv = document.createElement('div');
            domainDiv.classList.add(
                'flex', 
                'items-center', 
                'gap-2', 
                'hover:bg-neutral-100',
                'dark:hover:bg-neutral-800',
                'rounded', 
                'cursor-pointer',
                'text-sm',
            );

            // Add expand/collapse arrow
            const arrow = document.createElement('i');
            arrow.className = 'fa-solid fa-chevron-right text-neutral-400 transition-transform text-xs w-3';
            domainDiv.appendChild(arrow);

            // Add domain icon and name
            const icon = document.createElement('i');
            icon.className = 'fa-solid fa-network-wired text-neutral-500 dark:text-neutral-400';
            domainDiv.appendChild(icon);

            const nameSpan = document.createElement('span');
            nameSpan.className = 'text-neutral-900 dark:text-white';
            nameSpan.textContent = domain;
            domainDiv.appendChild(nameSpan);

            domainDiv.setAttribute('data-dn', rootDn);
            
            // Create subtree container
            const subtree = document.createElement('div');
            subtree.className = 'ml-6 mt-2 space-y-2 text-sm';

            let isExpanded = true; // Set initial state to expanded
            let contentLoaded = false;

            // Auto-expand function
            const expandDomain = async () => {
                if (!contentLoaded) {
                    try {
                        showLoadingIndicator();
                        
                        // First, check if domain has any directly linked GPOs
                        const domainData = await fetchItemsData(rootDn, 'BASE', ['gPLink']);
                        if (domainData && domainData.length > 0 && domainData[0].attributes.gPLink) {
                            const gpoLinks = parseGPOLink(domainData[0].attributes.gPLink);
                            if (gpoLinks && gpoLinks.length > 0) {
                                for (const link of gpoLinks) {
                                    const gpoResponse = await fetch('/api/get/domaingpo', {
                                        method: 'POST',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        },
                                        body: JSON.stringify({ identity: link.GUID })
                                    });
                                    
                                    const gpoData = await gpoResponse.json();
                                    if (gpoData && gpoData.length > 0) {
                                        createGPOSubNode(gpoData[0], subtree, link.IsEnforced);
                                    }
                                }
                            }
                        }

                        // Add "Group Policy Objects" container node
                        const gpoContainer = document.createElement('div');
                        gpoContainer.className = 'mb-2';

                        const gpoDiv = document.createElement('div');
                        gpoDiv.classList.add(
                            'flex', 
                            'items-center', 
                            'gap-2', 
                            'hover:bg-neutral-100',
                            'dark:hover:bg-neutral-800',
                            'rounded', 
                            'cursor-pointer',
                            'text-sm',
                        );

                        // Add expand/collapse arrow
                        const gpoArrow = document.createElement('i');
                        gpoArrow.className = 'fa-solid fa-chevron-right text-neutral-400 transition-transform text-xs w-3';
                        gpoDiv.appendChild(gpoArrow);

                        // Add GPO container icon and name
                        const gpoIcon = document.createElement('span');
                        gpoIcon.innerHTML = icons.policyIcon;
                        gpoDiv.appendChild(gpoIcon);

                        const gpoNameSpan = document.createElement('span');
                        gpoNameSpan.className = 'text-neutral-900 dark:text-white';
                        gpoNameSpan.textContent = 'Group Policy Objects';
                        gpoDiv.appendChild(gpoNameSpan);

                        // Create GPO subtree container
                        const gpoSubtree = document.createElement('div');
                        gpoSubtree.className = 'hidden ml-6 mt-2 space-y-2 text-sm';

                        let gpoIsExpanded = false;
                        let gposLoaded = false;

                        // Add click handler for GPO container
                        gpoDiv.addEventListener('click', async () => {
                            if (!gposLoaded) {
                                try {
                                    showLoadingIndicator();
                                    
                                    // Fetch all GPOs
                                    const response = await fetch('/api/get/domaingpo', {
                                        method: 'GET',
                                        headers: {
                                            'Content-Type': 'application/json',
                                        }
                                    });

                                    await handleHttpError(response);
                                    const gpos = await response.json();

                                    // Sort GPOs by displayName
                                    gpos.sort((a, b) => {
                                        const nameA = a.attributes.displayName?.toLowerCase() || '';
                                        const nameB = b.attributes.displayName?.toLowerCase() || '';
                                        return nameA.localeCompare(nameB);
                                    });

                                    // Create nodes for each GPO
                                    gpos.forEach(gpo => {
                                        createGPOSubNode(gpo, gpoSubtree, false);
                                    });

                                    gposLoaded = true;
                                } catch (error) {
                                    console.error('Error loading GPOs:', error);
                                    showErrorAlert('Failed to load GPOs');
                                } finally {
                                    hideLoadingIndicator();
                                }
                            }

                            // Toggle expansion
                            gpoIsExpanded = !gpoIsExpanded;
                            gpoArrow.style.transform = gpoIsExpanded ? 'rotate(90deg)' : '';
                            gpoSubtree.className = `ml-6 mt-2 space-y-2 ${gpoIsExpanded ? '' : 'hidden'}`;
                        });

                        gpoContainer.appendChild(gpoDiv);
                        gpoContainer.appendChild(gpoSubtree);
                        subtree.appendChild(gpoContainer);

                        // Then get and add all OUs
                        const response = await fetch('/api/get/domainou', {
                            method: 'GET',
                            headers: {
                                'Content-Type': 'application/json',
                            }
                        });

                        await handleHttpError(response);
                        const ous = await response.json();
                        
                        // Sort OUs by DN
                        ous.sort((a, b) => {
                            const dnA = a.dn?.toLowerCase() || '';
                            const dnB = b.dn?.toLowerCase() || '';
                            return dnA.localeCompare(dnB);
                        });

                        // Create tree nodes for each OU
                        for (const ou of ous) {
                            await createOUTreeNode(ou, subtree);
                        }

                        contentLoaded = true;
                    } catch (error) {
                        console.error('Error loading domain content:', error);
                        showErrorAlert('Failed to load domain content');
                    } finally {
                        hideLoadingIndicator();
                    }
                }

                // Set expanded state
                arrow.style.transform = 'rotate(90deg)';
                subtree.className = 'ml-6 mt-2 space-y-2 text-sm';
            };

            // Add click handler
            domainDiv.addEventListener('click', () => {
                isExpanded = !isExpanded;
                arrow.style.transform = isExpanded ? 'rotate(90deg)' : '';
                subtree.className = `ml-6 mt-2 space-y-2 ${isExpanded ? '' : 'hidden'}`;
            });

            domainContainer.appendChild(domainDiv);
            domainContainer.appendChild(subtree);
            treeView.appendChild(domainContainer);

            // Auto-expand the domain node
            await expandDomain();

        } catch (error) {
            console.error('Error initializing GPO view:', error);
            showErrorAlert('Failed to initialize GPO view');
        } finally {
            hideInitLoadingIndicator();
        }
    }

    async function createOUTreeNode(ou, parentElement) {
        const treeView = document.getElementById('gpo-tree-view');
        if (!treeView) return null;

        const ouContainer = document.createElement('div');
        ouContainer.className = 'mb-2';

        const ouDiv = document.createElement('div');
        ouDiv.classList.add(
            'flex', 
            'items-center', 
            'gap-2', 
            'hover:bg-neutral-100',
            'dark:hover:bg-neutral-800',
            'rounded', 
            'cursor-pointer',
            'text-sm',
        );

        // Add expand/collapse arrow
        const arrow = document.createElement('i');
        arrow.className = 'fa-solid fa-chevron-right text-neutral-400 transition-transform text-xs w-3';
        ouDiv.appendChild(arrow);

        // Add OU icon and name
        const icon = document.createElement('i');
        icon.className = 'fa-solid fa-building text-neutral-500 dark:text-neutral-400';
        ouDiv.appendChild(icon);

        const nameSpan = document.createElement('span');
        nameSpan.className = 'text-neutral-900 dark:text-white';
        nameSpan.textContent = ou.attributes.name || 'Unnamed OU';
        ouDiv.appendChild(nameSpan);

        ouDiv.setAttribute('data-dn', ou.dn);
        
        // Create subtree container (initially hidden)
        const subtree = document.createElement('div');
        subtree.className = 'hidden ml-6 mt-2 space-y-2 text-sm';

        let isExpanded = false;
        let gposLoaded = false;

        ouDiv.addEventListener('click', async () => {
            if (!gposLoaded) {
                try {
                    showLoadingIndicator();
                    // Fetch OU details to get gPLink attribute
                    const ouData = await fetchItemsData(ou.dn, 'BASE', ['gPLink']);
                    if (ouData && ouData.length > 0 && ouData[0].attributes.gPLink) {
                        const gpoLinks = parseGPOLink(ouData[0].attributes.gPLink);
                        if (gpoLinks && gpoLinks.length > 0) {
                            // Fetch GPO details for each linked GPO
                            for (const link of gpoLinks) {
                                const gpoResponse = await fetch('/api/get/domaingpo', {
                                    method: 'POST',
                                    headers: {
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify({ identity: link.GUID })
                                });
                                
                                const gpoData = await gpoResponse.json();
                                if (gpoData && gpoData.length > 0) {
                                    const gpo = gpoData[0];
                                    createGPOSubNode(gpo, subtree, link.IsEnforced);
                                }
                            }
                        } else {
                            const emptyMessage = document.createElement('div');
                            emptyMessage.className = 'text-neutral-500 dark:text-neutral-400 text-sm pl-2';
                            emptyMessage.textContent = 'No GPOs linked to this OU';
                            subtree.appendChild(emptyMessage);
                        }
                    }
                    gposLoaded = true;
                } catch (error) {
                    console.error('Error loading GPOs:', error);
                    showErrorAlert('Failed to load linked GPOs');
                } finally {
                    hideLoadingIndicator();
                }
            }

            // Toggle expansion
            isExpanded = !isExpanded;
            arrow.style.transform = isExpanded ? 'rotate(90deg)' : '';
            subtree.className = `ml-6 mt-2 space-y-2 ${isExpanded ? '' : 'hidden'}`;
        });

        ouContainer.appendChild(ouDiv);
        ouContainer.appendChild(subtree);
        parentElement.appendChild(ouContainer);
        return ouContainer;
    }

    function createGPOSubNode(gpo, parentElement, isEnforced) {
        const div = document.createElement('div');
        div.classList.add(
            'flex', 
            'items-center', 
            'gap-2', 
            'hover:bg-neutral-100',
            'dark:hover:bg-neutral-800',
            'rounded', 
            'cursor-pointer',
            'text-sm',
        );

        // Add GPO icon
        const icon = document.createElement('span');
        icon.innerHTML = icons.policyIcon;
        div.appendChild(icon);

        // Add GPO name with enforcement status
        const nameSpan = document.createElement('span');
        nameSpan.className = 'text-neutral-900 dark:text-white flex items-center gap-2';
        nameSpan.innerHTML = `
            ${gpo.attributes.displayName || 'Unnamed GPO'}
            ${isEnforced ? '<span class="text-xs bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300 px-2 py-0.5 rounded">Enforced</span>' : ''}
        `;

        div.appendChild(nameSpan);
        div.setAttribute('data-cn', gpo.attributes.cn);
        div.setAttribute('data-dn', gpo.dn);

        div.addEventListener('click', async (event) => {
            event.stopPropagation();
            // Handle GPO selection
            document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');
            currentSelectedGPO = gpo.attributes.cn;

            // Clear all tab panels
            clearTabPanels();

            showLoadingIndicator();
            try {
                await displayGPODetails(gpo.attributes.cn);
            } catch (error) {
                console.error('Error handling GPO node click:', error);
            } finally {
                hideLoadingIndicator();
            }
        });

        parentElement.appendChild(div);
        return div;
    }

    // Add this new function to clear tab panels
    function clearTabPanels() {
        // Clear Info panel
        const infoPanel = document.getElementById('tabpanelInfo');
        if (infoPanel) {
            infoPanel.innerHTML = '';
        }

        // Clear Settings panel
        const settingsPanel = document.getElementById('tabpanelSettings');
        if (settingsPanel) {
            settingsPanel.innerHTML = '';
        }

        // Clear Delegation panel
        const delegationPanel = document.getElementById('tabpanelDelegation');
        if (delegationPanel) {
            delegationPanel.innerHTML = '';
        }

        // Reset to Info tab
        selectGPOTab('info');
    }

    async function displayGPODetails(gpoGUID) {
        console.log(gpoGUID);
        try {
            const response = await fetch('/api/get/domaingpo', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identity: gpoGUID })
            });

            await handleHttpError(response);
            const gpoData = await response.json();
            console.log(gpoData);
            
            if (!gpoData || gpoData.length === 0) {
                showErrorAlert('No GPO data found');
                return;
            }

            const gpo = gpoData[0];
            
            // Hide the initial content
            const initialContent = document.querySelector('#gpo-content > .flex.items-center.justify-center');
            if (initialContent) {
                initialContent.style.display = 'none';
            }

            // Show tabs
            document.getElementById('gpo-tabs').style.display = 'flex';

            // Update info panel
            updateInfoPanel(gpo);

            // Show info tab by default
            selectGPOTab('info');

        } catch (error) {
            console.error('Error displaying GPO details:', error);
            showErrorAlert('Failed to load GPO details');
        }
    }

    function updateInfoPanel(gpo) {
        const infoPanel = document.getElementById('tabpanelInfo');
        const attributes = gpo.attributes;

        infoPanel.innerHTML = `
            <div class="bg-white dark:bg-neutral-800 rounded-lg">
                <!-- Header with buttons -->
                <div class="bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-white px-4 py-1 border-b border-neutral-200 dark:border-neutral-700 sticky top-0 z-10">
                    <div class="flex justify-between items-center">
                        <h3 class="font-medium">${attributes.displayName || 'GPO Details'}</h3>
                        <div class="flex gap-2">
                            <button class="px-2 py-1.5 text-sm font-medium rounded-md text-neutral-700 hover:text-neutral-900 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:text-white dark:hover:bg-neutral-800 transition-colors" 
                                    title="Details" 
                                    onclick="handleLdapLinkClick(event, '${gpo.dn}')">
                                <i class="fa-solid fa-pen-to-square"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Content -->
                <div class="p-4">
                    <dl class="grid grid-cols-2 gap-4">
                        ${Object.entries(attributes).map(([key, value]) => `
                            <div class="col-span-2">
                                <dt class="text-sm font-medium text-neutral-600 dark:text-neutral-400">${key}</dt>
                                <dd class="mt-1 flex items-center gap-2">
                                    <span class="text-sm text-neutral-900 dark:text-white break-all">${value}</span>
                                    <button onclick="copyToClipboard(event, '${value}')" 
                                            class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity">
                                        <i class="fas fa-copy fa-xs"></i>
                                    </button>
                                </dd>
                            </div>
                        `).join('')}
                    </dl>
                </div>
            </div>
        `;
    }

    // Add search functionality
    const searchInput = document.getElementById('gpo-search');
    searchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const ouNodes = document.querySelectorAll('#gpo-tree-view > div');
        
        ouNodes.forEach(node => {
            const ouName = node.querySelector('span').textContent.toLowerCase();
            const gpoNodes = node.querySelectorAll('.ml-6 > div');
            let hasMatch = ouName.includes(searchTerm);
            
            gpoNodes.forEach(gpoNode => {
                const gpoName = gpoNode.querySelector('span').textContent.toLowerCase();
                if (gpoName.includes(searchTerm)) {
                    hasMatch = true;
                    gpoNode.style.display = '';
                } else {
                    gpoNode.style.display = 'none';
                }
            });

            node.style.display = hasMatch ? '' : 'none';
        });
    });

    // Initialize the page
    initialize();
});

// Tab selection function
async function selectGPOTab(tabName) {
    const tabs = document.querySelectorAll('#gpo-tabs [role="tab"]');
    tabs.forEach(tab => {
        const isSelected = tab.getAttribute('aria-controls') === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`;
        tab.setAttribute('aria-selected', isSelected);
        
        // Remove all styling classes first
        tab.classList.remove(
            'font-bold', 
            'text-black', 
            'border-b-2', 
            'border-black', 
            'dark:border-yellow-500', 
            'dark:text-yellow-500',
            'text-neutral-600',
            'font-medium'
        );

        // Apply appropriate styling based on selection state
        if (isSelected) {
            tab.classList.add(
                'font-bold',
                'text-black',
                'border-b-2',
                'border-black',
                'dark:border-yellow-500',
                'dark:text-yellow-500'
            );
        } else {
            tab.classList.add(
                'text-neutral-600',
                'font-medium',
                'dark:text-neutral-300'
            );
        }
        tab.tabIndex = isSelected ? 0 : -1;
    });

    const tabPanels = document.querySelectorAll('#gpo-content [role="tabpanel"]');
    tabPanels.forEach(panel => {
        panel.style.display = panel.id === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}` ? 'block' : 'none';
    });

    const selectedGPO = document.querySelector('.selected');
    const identity = selectedGPO.getAttribute('data-dn');
    const cn = selectedGPO.getAttribute('data-cn');

    // Load specific tab content
    if (tabName === 'delegation') {
        if (selectedGPO) {
            if (identity) {
                await fetchAndDisplayDacl(identity);
            }
        }
    } else if (tabName === 'settings') {
        if (cn) {
            await fetchAndDisplaySettings(cn);
        }
    }
}

async function fetchAndDisplaySettings(cn) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domaingposettings', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: cn })
        });

        await handleHttpError(response);
        const settingsData = await response.json();
        
        const settingsPanel = document.getElementById('tabpanelSettings');
        if (!settingsData || settingsData.length === 0) {
            settingsPanel.innerHTML = `
                <div class="text-center text-neutral-500 dark:text-neutral-400 py-8">
                    <p>No settings configured for this GPO</p>
                </div>
            `;
            return;
        }

        const gpo = settingsData[0];
        settingsPanel.innerHTML = `
            <div class="bg-white dark:bg-neutral-800 rounded-lg">
                <!-- Header -->
                <div class="bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-white px-4 py-3 border-b border-neutral-200 dark:border-neutral-700 sticky top-0 z-10">
                    <div class="flex justify-between items-center">
                        <h3 class="font-medium">${gpo.attributes.displayName}</h3>
                    </div>
                </div>

                <!-- Content -->
                <div class="p-4 space-y-6">
                    <!-- Machine Configuration -->
                    ${renderConfigSection('Computer Configuration', gpo.attributes.machineConfig)}
                    
                    <!-- User Configuration -->
                    ${renderConfigSection('User Configuration', gpo.attributes.userConfig)}
                </div>
            </div>
        `;

    } catch (error) {
        console.error('Error fetching settings data:', error);
        const settingsPanel = document.getElementById('tabpanelSettings');
        settingsPanel.innerHTML = `
            <div class="text-center text-red-500 dark:text-red-400 py-8">
                <p>Failed to load GPO settings</p>
            </div>
        `;
    } finally {
        hideLoadingIndicator();
    }
}

function renderConfigSection(title, config) {
    if (!config || Object.keys(config).length === 0) {
        return `
            <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg">
                <div class="px-4 py-3 border-b border-neutral-200 dark:border-neutral-700">
                    <h4 class="text-sm font-medium text-neutral-900 dark:text-white flex items-center gap-2">
                        <i class="fa-solid ${title.includes('Computer') ? 'fa-desktop' : 'fa-user'} text-neutral-500 dark:text-neutral-400"></i>
                        ${title}
                    </h4>
                </div>
                <div class="p-4 text-center text-neutral-500 dark:text-neutral-400">
                    <p>No settings configured</p>
                </div>
            </div>
        `;
    }

    return `
        <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg">
            <div class="px-4 py-3 border-b border-neutral-200 dark:border-neutral-700">
                <h4 class="text-sm font-medium text-neutral-900 dark:text-white flex items-center gap-2">
                    <i class="fa-solid ${title.includes('Computer') ? 'fa-desktop' : 'fa-user'} text-neutral-500 dark:text-neutral-400"></i>
                    ${title}
                </h4>
            </div>
            <div class="p-4 space-y-4">
                ${Object.entries(config).map(([section, settings]) => renderSection(section, settings)).join('')}
            </div>
        </div>
    `;
}

function renderSection(section, settings) {
    if (section === 'Security') {
        return Object.entries(settings).map(([subsection, values]) => {
            if (subsection === 'Unicode' || subsection === 'Version') return '';
            
            return `
                <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg">
                    <div class="rounded-lg px-4 py-2 border-b border-neutral-200 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-800">
                        <h5 class="text-sm font-medium text-neutral-900 dark:text-white">${subsection}</h5>
                    </div>
                    <div class="p-4">
                        <dl class="grid grid-cols-1 gap-3">
                            ${Object.entries(values).map(([key, value]) => `
                                <div class="flex flex-col space-y-1">
                                    <dt class="text-sm text-neutral-500 dark:text-neutral-400 break-all">${formatRegistryKey(key)}</dt>
                                    <dd class="text-sm text-neutral-900 dark:text-white font-medium">${formatValue(value)}</dd>
                                </div>
                            `).join('')}
                        </dl>
                    </div>
                </div>
            `;
        }).join('');
    }
    
    return `
        <div class="border border-neutral-200 dark:border-neutral-700 rounded-lg">
            <div class="rounded-lg px-4 py-2 border-b border-neutral-200 dark:border-neutral-700 bg-neutral-50 dark:bg-neutral-800">
                <h5 class="text-sm font-medium text-neutral-900 dark:text-white">${section}</h5>
            </div>
            <div class="p-4">
                <pre class="text-sm text-neutral-900 dark:text-white">${JSON.stringify(settings, null, 2)}</pre>
            </div>
        </div>
    `;
}

function formatRegistryKey(key) {
    // Split the registry path into parts for better readability
    const parts = key.split('\\');
    if (parts.length > 1) {
        return parts.map((part, index) => {
            if (index === parts.length - 1) {
                return `<span class="text-neutral-900 dark:text-white">${part}</span>`;
            }
            return part;
        }).join('\\');
    }
    return key;
}

function formatValue(value) {
    // Handle registry values (e.g., "4,0")
    if (typeof value === 'string' && value.includes(',')) {
        const [type, val] = value.split(',');
        if (type === '4') { // REG_DWORD
            return `${val} (DWORD)`;
        }
    }
    return value;
}

async function fetchAndDisplayDacl(identity) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domainobjectacl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: identity, searchbase: identity, search_scope: 'BASE' })
        });

        await handleHttpError(response);
        const daclData = await response.json();
        updateDaclContent(daclData);
    } catch (error) {
        console.error('Error fetching DACL data:', error);
    } finally {
        hideLoadingIndicator();
    }
}

function updateDaclContent(daclData) {
    const delegationPanel = document.getElementById('tabpanelDelegation');
    delegationPanel.innerHTML = `
        <div class="p-4">
            <table class="w-full text-sm border-collapse">
                <thead>
                    <tr class="h-8 text-left text-neutral-600 dark:text-neutral-400">
                        <th class="px-3 py-2">Type</th>
                        <th class="px-3 py-2">Principal</th>
                        <th class="px-3 py-2">Access</th>
                        <th class="px-3 py-2">Inherited From</th>
                        <th class="px-3 py-2">Applies to</th>
                    </tr>
                </thead>
                <tbody id="dacl-rows" class="divide-y divide-neutral-200 dark:divide-neutral-700">
                </tbody>
            </table>
        </div>
    `;

    const daclRows = document.getElementById('dacl-rows');
    daclData.forEach(entry => {
        entry.attributes.forEach(attribute => {
            const row = document.createElement('tr');
            row.classList.add(
                'h-8',
                'result-item',
                'hover:bg-neutral-50',
                'dark:hover:bg-neutral-800',
                'border-b',
                'border-neutral-200',
                'dark:border-neutral-700',
                'dark:text-neutral-200',
                'text-neutral-600'
            );

            // Determine Allow or Deny based on ACEType
            const aceType = attribute.ACEType.includes('ALLOWED') ? icons.onIcon : icons.offIcon;

            // Format AccessMask to handle commas
            const formattedAccessMask = attribute.AccessMask ?
                attribute.AccessMask.split(',')
                    .map(mask => mask.trim())
                    .join('<br>')
                : '';

            // Replace "Pre-Windows 2000" with "Pre2k" in SecurityIdentifier
            const securityIdentifier = attribute.SecurityIdentifier ? 
                attribute.SecurityIdentifier.replace('Pre-Windows 2000', 'Pre2k') 
                : '';

            row.innerHTML = `
                <td class="px-3 py-2">${aceType}</td>
                <td class="px-3 py-2">${securityIdentifier}</td>
                <td class="px-3 py-2">${formattedAccessMask}</td>
                <td class="px-3 py-2">${attribute.InheritanceType || ''}</td>
                <td class="px-3 py-2">${attribute.ObjectAceType || ''}</td>
            `;

            daclRows.appendChild(row);
        });
    });
}
