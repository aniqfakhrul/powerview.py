function executePowerViewCommand() {
    const searchInput = document.querySelector('input[name="object-search"]').value;
    fetch('/api/get/domainobject', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ identity: searchInput })
    })
    .then(response => response.json())
    .then(data => {
        if (data && data.length > 0) {
            const dn = data[0].dn;
            const name = data[0].attributes.name;
            expandTreeView(dn, name);
        }
    })
    .catch(error => console.error('Error:', error));
}

function expandTreeView(dn, name) {
    const parts = dn.split(',');
    const treePath = parts.reverse().map(part => part.split('=')[1]);
    // Assuming you have a function to expand the tree based on the path
    expandTreePath(treePath);
}

function expandTreePath(treePath) {
    // Example logic to expand the tree
    let currentNode = document.getElementById('tree-view');
    treePath.forEach(part => {
        const node = currentNode.querySelector(`[data-name="${part}"]`);
        if (node) {
            node.classList.add('expanded'); // Assuming 'expanded' is a class that shows the node
            currentNode = node;
        }
    });
}

async function selectTab(tabName) {
    const tabs = ['general', 'members', 'dacl', 'trusts'];
    tabs.forEach(tab => {
        const button = document.querySelector(`button[aria-controls="tabpanel${tab.charAt(0).toUpperCase() + tab.slice(1)}"]`);
        const panel = document.getElementById(`tabpanel${tab.charAt(0).toUpperCase() + tab.slice(1)}`);
        
        if (tab === tabName) {
            // Active tab styling
            button.setAttribute('aria-selected', 'true');
            button.setAttribute('tabindex', '0');
            button.classList.add(
                'font-bold',
                'text-blue-600',
                'border-b-2',
                'border-blue-600',
                'dark:border-yellow-500',
                'dark:text-yellow-500'
            );
            panel.style.display = 'block';

            // Handle specific tab content
            if (tab === 'members') {
                const selectedNode = document.querySelector('.selected');
                if (selectedNode) {
                    const groupDn = selectedNode.getAttribute('data-identifier');
                    if (groupDn) {
                        fetchGroupMembers(groupDn).then(members => {
                            if (members) {
                                displayGroupMembers(members);
                            }
                        });
                    }
                }
            } else if (tab === 'dacl') {
                const selectedNode = document.querySelector('.selected');
                if (selectedNode) {
                    const identity = selectedNode.getAttribute('data-identifier');
                    if (identity) {
                        fetchAndDisplayDacl(identity);
                    }
                }
            } else if (tab === 'trusts') {
                const selectedNode = document.querySelector('.selected');
                if (selectedNode) {
                    const identity = selectedNode.getAttribute('data-identifier');
                    if (identity) {
                        fetchAndDisplayTrust(identity);
                    }
                }
            }
        } else {
            // Inactive tab styling
            button.setAttribute('aria-selected', 'false');
            button.setAttribute('tabindex', '-1');
            button.classList.remove(
                'font-bold',
                'text-blue-600',
                'border-b-2',
                'border-blue-600',
                'dark:border-yellow-500',
                'dark:text-yellow-500'
            );
            panel.style.display = 'none';
        }
    });
}

async function fetchGroupMembers(groupDn) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domaingroupmember', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: groupDn })
        });

        await handleHttpError(response);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching group members:', error);
        return null;
    } finally {
        hideLoadingIndicator();
    }
}

function displayGroupMembers(members) {
    const groupContent = document.getElementById('members-content');
    if (!groupContent) return;

    groupContent.innerHTML = `
        <table class="w-full text-sm border-collapse">
            <thead>
                <tr class="h-8 text-left text-neutral-600 dark:text-neutral-400">
                    <th class="px-3 py-2">Member Name</th>
                    <th class="px-3 py-2">Member SID</th>
                    <th class="px-3 py-2">Distinguished Name</th>
                </tr>
            </thead>
            <tbody class="divide-y divide-neutral-200 dark:divide-neutral-700">
                ${members.map(member => `
                    <tr class="h-8 result-item cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-800 hover:text-neutral-900 dark:hover:text-white border-b border-neutral-200 dark:border-neutral-700 dark:text-neutral-200 text-neutral-600 transition-colors" 
                        onclick="handleLdapLinkClick(event, '${member.attributes.MemberDistinguishedName}')">
                        <td class="px-3 py-2">${member.attributes.MemberName || ''}</td>
                        <td class="px-3 py-2">${member.attributes.MemberSID || ''}</td>
                        <td class="px-3 py-2">${member.attributes.MemberDistinguishedName || ''}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    `;
}


async function fetchAndDisplayDacl(identity, no_cache = false) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domainobjectacl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                identity: identity, 
                searchbase: identity, 
                search_scope: 'BASE',
                no_cache: no_cache 
            })
        });

        await handleHttpError(response);
        const daclData = await response.json();
        updateDaclContent(daclData);
    } catch (error) {
        console.error('Error fetching DACL data:', error);
        showErrorAlert('Failed to fetch DACL data');
    } finally {
        hideLoadingIndicator();
    }
}

function updateDaclContent(daclData) {
    const daclRows = document.getElementById('dacl-rows');
    daclRows.innerHTML = '';

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
            const securityIdentifier = attribute.SecurityIdentifier ? attribute.SecurityIdentifier.replace('Pre-Windows 2000', 'Pre2k') : '';

            row.innerHTML = `
                <td>${aceType}</td>
                <td>${securityIdentifier}</td>
                <td>${formattedAccessMask}</td>
                <td>${attribute.InheritanceType || ''}</td>
                <td>${attribute.ObjectAceType || ''}</td>
            `;

            daclRows.appendChild(row);
        });
    });
}

async function getDomainTrust(searchbase) {
    try {
        const response = await fetch('/api/get/domaintrust', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ searchbase: searchbase })
        });

        await handleHttpError(response);
        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching domain trusts:', error);
        return [];
    }
}

async function fetchAndDisplayTrust(searchbase) {
    showLoadingIndicator();
    try {
        const trusts = await getDomainTrust(searchbase);
        const trustsContent = document.getElementById('trusts-content');
        
        if (trusts && trusts.length > 0) {
            const trustsList = trusts.map(trust => `
                <div class="mb-4 p-4 bg-white dark:bg-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-700">
                    <div class="flex items-center justify-between mb-2">
                        <h3 class="text-lg font-medium text-neutral-900 dark:text-white">${trust.attributes.name}</h3>
                        <span class="text-sm text-neutral-500 dark:text-neutral-400">${trust.attributes.flatName}</span>
                    </div>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div>
                            <span class="font-medium text-neutral-700 dark:text-neutral-300">Trust Direction:</span>
                            <span class="ml-2 text-neutral-600 dark:text-neutral-400">${trust.attributes.trustDirection.join(', ')}</span>
                        </div>
                        <div>
                            <span class="font-medium text-neutral-700 dark:text-neutral-300">Trust Type:</span>
                            <span class="ml-2 text-neutral-600 dark:text-neutral-400">${trust.attributes.trustType.join(', ')}</span>
                        </div>
                    </div>
                </div>
            `).join('');

            trustsContent.innerHTML = trustsList;
        } else {
            trustsContent.innerHTML = '<p class="text-neutral-500 dark:text-neutral-400">No domain trusts found.</p>';
        }
    } catch (error) {
        console.error('Error displaying trusts:', error);
        showErrorAlert('Failed to load domain trusts');
    } finally {
        hideLoadingIndicator();
    }
}

function openExplorerAddObjectAclModal() {
    const modal = document.getElementById('add-object-acl-modal');
    const targetIdentityInput = document.getElementById('target-identity');
    const overlay = document.getElementById('modal-overlay');
    
    // Get the currently selected node's DN
    const selectedNode = document.querySelector('.selected');
    const currentIdentity = selectedNode ? selectedNode.getAttribute('data-identifier') : '';
    
    if (modal) {
        if (targetIdentityInput && currentIdentity) {
            targetIdentityInput.value = currentIdentity;
        }
        
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
        
        // Initialize close handlers if not already initialized
        initializeExplorerAddAclModal();
    }
}

function closeExplorerAddObjectAclModal() {
    const modal = document.getElementById('add-object-acl-modal');
    const overlay = document.getElementById('modal-overlay');
    
    if (modal) {
        modal.classList.add('hidden');
    }
    if (overlay) {
        overlay.classList.add('hidden');
    }

    // Clear form fields
    const form = document.getElementById('add-object-acl-form');
    if (form) {
        form.reset();
    }
}

function initializeExplorerAddAclModal() {
    // Handle close button click
    const closeButton = document.querySelector('[data-modal-hide="add-object-acl-modal"]');
    if (closeButton) {
        closeButton.addEventListener('click', closeExplorerAddObjectAclModal);
    }

    // Add form submit handler
    const form = document.getElementById('add-object-acl-form');
    if (form) {
        form.removeEventListener('submit', handleExplorerAclSubmit);
        form.addEventListener('submit', handleExplorerAclSubmit);
    }

    // Handle clicking outside the modal to close it
    const modal = document.getElementById('add-object-acl-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeExplorerAddObjectAclModal();
            }
        });
    }
}

async function handleExplorerAclSubmit(e) {
    e.preventDefault();
    
    const targetIdentity = document.getElementById('target-identity').value;
    const principalIdentity = document.getElementById('principal-identity').value;
    const rights = document.getElementById('acl-rights').value;
    const aceType = document.getElementById('ace-type').value;
    const inheritance = document.getElementById('inheritance').checked;

    const refreshCallback = async () => {
        closeExplorerAddObjectAclModal();
        await fetchAndDisplayDacl(targetIdentity, true);
    };

    await addDomainObjectAcl(
        targetIdentity, 
        principalIdentity, 
        rights, 
        aceType, 
        inheritance,
        refreshCallback
    );
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('tab-search');
    const clearButton = document.querySelector('.clear-input');
    const tabPanels = document.querySelectorAll('[role="tabpanel"]');

    // Store the current filter state
    let currentFilter = '';

    if (searchInput) {
        searchInput.addEventListener('input', () => {
            currentFilter = searchInput.value.toLowerCase();
            filterTabResults(currentFilter);
        });

        clearButton.addEventListener('click', () => {
            searchInput.value = '';   
            currentFilter = '';
            filterTabResults('');
        });
    }

    function filterTabResults(query) {
        const activeTabButton = document.querySelector('[role="tab"][aria-selected="true"]');
        if (!activeTabButton) return;

        const activePanelId = activeTabButton.getAttribute('aria-controls');
        const activePanel = document.getElementById(activePanelId);

        if (activePanel) {
            const items = activePanel.querySelectorAll('.result-item');
            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(query)) {
                    item.classList.remove('hidden');
                } else {
                    item.classList.add('hidden');
                }
            });
        }
    }

    selectTab('general');
});