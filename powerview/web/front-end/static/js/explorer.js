function executePowerViewCommand() {
    const searchInput = document.querySelector('input[name="object-search"]').value;
    console.log(searchInput);
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
    const tabs = ['general', 'members', 'dacl'];
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

            // If members tab is selected, fetch and display members
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


async function fetchAndDisplayDacl(identity) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domainobjectacl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: identity })
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