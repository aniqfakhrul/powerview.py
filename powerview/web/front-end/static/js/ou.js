// Move selectOUTab to global scope
async function selectOUTab(tabName) {
    const tabs = document.querySelectorAll('#ou-tabs [role="tab"]');
    tabs.forEach(tab => {
        const isSelected = tab.getAttribute('aria-controls') === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`;
        tab.setAttribute('aria-selected', isSelected);
        if (isSelected) {
            tab.classList.add('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
            tab.classList.remove('text-neutral-600', 'font-medium');
        } else {
            tab.classList.remove('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
            tab.classList.add('text-neutral-600', 'font-medium');
        }
    });

    const tabPanels = document.querySelectorAll('#ou-content [role="tabpanel"]');
    tabPanels.forEach(panel => {
        panel.style.display = panel.id === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}` ? 'block' : 'none';
    });

    // Load specific tab content
    if (tabName === 'descendants') {
        const selectedOU = document.querySelector('.selected');
        if (selectedOU) {
            const identity = selectedOU.getAttribute('data-dn');
            await loadOUDescendants(identity);
        }
    } else if (tabName === 'linkedGpo') {
        const selectedOU = document.querySelector('.selected');
        if (selectedOU) {
            const identity = selectedOU.getAttribute('data-dn');
            const ouData = await fetchItemsData(identity, 'BASE', ['gPLink']);
            if (ouData && ouData.length > 0 && ouData[0].attributes.gPLink) {
                const gpoIds = parseGPOLink(ouData[0].attributes.gPLink);
                if (gpoIds && gpoIds.length > 0) {
                    await loadLinkedGPOs(gpoIds);
                }
            } else {
                // Show empty state if no GPOs are linked
                const gpoPanel = document.getElementById('tabpanelLinkedGpo');
                gpoPanel.innerHTML = `
                    <div class="flex items-center justify-center h-64 text-neutral-500">
                        <div class="text-center">
                            <i class="fa-solid fa-shield-halved mb-2 text-2xl"></i>
                            <p>No Group Policy Objects linked to this OU</p>
                        </div>
                    </div>
                `;
            }
        }
    }
}

function showDeleteModal(identity) {
    const modal = document.getElementById('popup-modal');
    const overlay = document.getElementById('modal-overlay');
    document.getElementById('identity-to-delete').textContent = identity;
    
    modal.removeAttribute('aria-hidden');
    modal.classList.remove('hidden');
    overlay.classList.remove('hidden');

    const firstButton = modal.querySelector('button');
    if (firstButton) {
        firstButton.focus();
    }
}


async function loadLinkedGPOs(gpoLinks) {
    try {
        showLoadingIndicator();
        
        // Clear the panel first
        const gpoPanel = document.getElementById('tabpanelLinkedGpo');
        gpoPanel.innerHTML = '';
        
        const properties = ['objectClass', 'displayName', 'distinguishedName', 'gPCFileSysPath'];
        
        // Fetch data for all GPO IDs
        const allData = await Promise.all(gpoLinks.map(link => 
            fetchGPOData(link.GUID, 'SUBTREE', properties)
        ));
        
        // Flatten and filter out any null results
        const data = allData.flat().filter(Boolean);
        
        if (data && data.length > 0) {
            // Create container
            const container = document.createElement('div');
            container.className = 'bg-white dark:bg-neutral-800 rounded-lg';

            const tableContainer = document.createElement('div');
            tableContainer.className = 'overflow-x-auto';

            const table = document.createElement('table');
            table.className = 'w-full text-sm text-neutral-600 dark:text-neutral-300';

            // Create header
            const thead = document.createElement('thead');
            thead.className = 'text-left border-b border-neutral-200 dark:border-neutral-700';
            
            const headerRow = document.createElement('tr');
            ['Name', 'Status', 'Enforcement', 'Distinguished Name'].forEach(text => {
                const th = document.createElement('th');
                th.className = 'px-4 py-2';
                th.textContent = text;
                headerRow.appendChild(th);
            });

            thead.appendChild(headerRow);
            table.appendChild(thead);

            // Create tbody
            const tbody = document.createElement('tbody');
            tbody.className = 'divide-y divide-neutral-200 dark:divide-neutral-700';

            data.forEach((gpo, index) => {
                const gpoLink = gpoLinks[index];
                const tr = document.createElement('tr');
                tr.className = 'border-b border-neutral-200 dark:border-neutral-700 hover:bg-neutral-50 dark:hover:bg-neutral-700 cursor-pointer result-item';
                tr.onclick = (event) => handleLdapLinkClick(event, gpo.dn);

                // Name cell
                const nameCell = document.createElement('td');
                nameCell.className = 'px-4 py-2';
                nameCell.textContent = gpo.attributes.displayName || '';
                tr.appendChild(nameCell);

                // Status cell
                const statusCell = document.createElement('td');
                statusCell.className = 'px-4 py-2';
                statusCell.textContent = gpo.enabled ? 'Enabled' : 'Disabled';
                tr.appendChild(statusCell);

                // Enforcement cell
                const enforcementCell = document.createElement('td');
                enforcementCell.className = 'px-4 py-2';
                enforcementCell.textContent = gpoLink.IsEnforced ? 'Enforced' : 'Not Enforced';
                tr.appendChild(enforcementCell);

                // DN cell with copy button
                const dnCell = document.createElement('td');
                dnCell.className = 'px-4 py-2';
                const dnContainer = document.createElement('div');
                dnContainer.className = 'flex items-center gap-2 group';
                
                const dnSpan = document.createElement('span');
                dnSpan.className = 'break-all';
                dnSpan.textContent = gpo.dn;
                
                const copyButton = document.createElement('button');
                copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
                copyButton.onclick = (event) => copyToClipboard(event, gpo.dn);
                copyButton.title = 'Copy to clipboard';
                copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                
                dnContainer.appendChild(dnSpan);
                dnContainer.appendChild(copyButton);
                dnCell.appendChild(dnContainer);
                tr.appendChild(dnCell);

                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            tableContainer.appendChild(table);
            container.appendChild(tableContainer);
            gpoPanel.appendChild(container);
        } else {
            gpoPanel.innerHTML = `
                <div class="flex items-center justify-center h-64 text-neutral-500">
                    <div class="text-center">
                        <i class="fa-solid fa-shield-halved mb-2 text-2xl"></i>
                        <p>No Group Policy Objects linked to this OU</p>
                    </div>
                </div>
            `;
        }
    } catch (error) {
        console.error('Error loading GPOs:', error);
        showErrorAlert('Failed to load linked GPOs');
    } finally {
        hideLoadingIndicator();
    }
}

async function fetchGPOData(identity, search_scope='BASE', properties=['*']) {
    try {
        const response = await fetch('/api/get/domaingpo', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                identity: identity,
                properties: properties,
                search_scope: search_scope
            })
        });

        await handleHttpError(response);

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching GPO data:', error);
        return null;
    } finally {
    }
}

async function loadOUDescendants(identity) {
    try {
        showLoadingIndicator();
        // Add 'objectClass' to the properties as it's needed for the icon
        const properties = ['objectClass', ...selectedProperties];
        const data = await fetchItemsData(identity, 'SUBTREE', properties);
        
        const tbody = document.getElementById('descendants-rows');
        const thead = document.getElementById('descendants-header');
        
        // Update table headers
        const headerRow = thead.querySelector('tr');
        headerRow.innerHTML = `
            <th class="px-3 py-2">Type</th>
            ${Array.from(selectedProperties).map(prop => 
                `<th class="px-3 py-2">${prop.charAt(0).toUpperCase() + prop.slice(1)}</th>`
            ).join('')}
        `;

        tbody.innerHTML = '';

        if (data && Array.isArray(data)) {
            const descendants = data.filter(item => 
                item.attributes?.distinguishedName?.toLowerCase() !== identity.toLowerCase()
            );

            descendants.forEach(item => {
                if (!item.attributes) return;

                const row = document.createElement('tr');
                row.classList.add(
                    'h-8',
                    'result-item',
                    'dark:hover:bg-neutral-800',
                    'border-b',
                    'border-neutral-200',
                    'dark:border-neutral-700',
                    'dark:text-neutral-200',
                    'text-neutral-600',
                    'cursor-pointer',
                );

                const objectClass = item.attributes.objectClass || [];
                const icon = getObjectClassIcon(objectClass);
                
                // Add type column with icon
                const typeCell = document.createElement('td');
                typeCell.className = 'px-3 py-2';
                typeCell.innerHTML = icon;
                row.appendChild(typeCell);

                // Add other property columns with copy buttons
                selectedProperties.forEach(prop => {
                    const td = document.createElement('td');
                    td.className = 'px-3 py-2 relative group';
                    
                    const wrapper = document.createElement('div');
                    wrapper.className = 'flex items-center gap-2';
                    
                    const value = item.attributes[prop] || '';
                    const textSpan = document.createElement('span');
                    if (Array.isArray(value)) {
                        textSpan.innerHTML = value.join('<br>');
                    } else {
                        textSpan.textContent = value;
                    }
                    
                    const copyButton = document.createElement('button');
                    copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
                    copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                    copyButton.title = 'Copy to clipboard';
                    
                    copyButton.addEventListener('click', async (event) => {
                        event.stopPropagation(); // Prevent row click
                        const textToCopy = Array.isArray(value) ? value.join('\n') : value;
                        
                        try {
                            if (navigator.clipboard && window.isSecureContext) {
                                await navigator.clipboard.writeText(textToCopy);
                            } else {
                                const textArea = document.createElement('textarea');
                                textArea.value = textToCopy;
                                textArea.style.position = 'fixed';
                                textArea.style.left = '-999999px';
                                textArea.style.top = '-999999px';
                                document.body.appendChild(textArea);
                                textArea.focus();
                                textArea.select();
                                
                                try {
                                    document.execCommand('copy');
                                    textArea.remove();
                                } catch (err) {
                                    console.error('Fallback: Oops, unable to copy', err);
                                    textArea.remove();
                                    throw new Error('Copy failed');
                                }
                            }
                            
                            copyButton.innerHTML = '<i class="fas fa-check fa-xs"></i>';
                            setTimeout(() => {
                                copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                            }, 1000);
                        } catch (err) {
                            console.error('Failed to copy text: ', err);
                            showErrorAlert('Failed to copy to clipboard');
                        }
                    });
                    
                    wrapper.appendChild(textSpan);
                    wrapper.appendChild(copyButton);
                    td.appendChild(wrapper);
                    row.appendChild(td);
                });

                row.addEventListener('click', (event) => {
                    handleLdapLinkClick(event, item.attributes.distinguishedName);
                });

                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading descendants:', error);
    } finally {
        hideLoadingIndicator();
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    initialize();

    async function initialize() {
        try {
            showInitLoadingIndicator();
            // Clear existing content
            const treeView = document.getElementById('ou-tree-view');
            if (treeView) {
                treeView.innerHTML = '';
            }

            // Get domain info
            const domainInfo = await getDomainInfo();
            const rootDn = domainInfo.root_dn;
            const domain = domainInfo.domain;
            
            // Populate property dropdown with hardcoded properties
            populatePropertyDropdown();
            
            // Create and add root node
            const rootNode = await createOUTreeNode(rootDn, domain, true);
            if (rootNode) {
                // Automatically expand root node
                rootNode.click();
            }
        } catch (error) {
            console.error('Error initializing OU view:', error);
        } finally {
            hideInitLoadingIndicator();
        }
    }

    async function fetchOUData(searchbase, search_scope = 'LEVEL') {
        try {
            showLoadingIndicator();
            const response = await fetch('/api/get/domainou', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ properties: ['*'], searchbase, search_scope })
            });

            await handleHttpError(response);
            return await response.json();
        } catch (error) {
            console.error('Error fetching OU data:', error);
            return null;
        } finally {
            hideLoadingIndicator();
        }
    }

    async function createOUTreeNode(dn, ouname='', isRoot = false) {
        const treeView = document.getElementById('ou-tree-view');
        if (!treeView) return null;

        const div = document.createElement('div');
        div.classList.add(
            'flex', 
            'items-center', 
            'gap-1', 
            'hover:bg-neutral-100',
            'dark:hover:bg-neutral-800',
            'rounded', 
            'cursor-pointer',
            'text-sm',
        );

        const icon = isRoot ? icons.adIcon : icons.ouIcon;
        div.innerHTML = `${icon}<span class="text-neutral-900 dark:text-white">${ouname || dn}</span>`;
        div.setAttribute('data-dn', dn);

        div.addEventListener('click', async (event) => {
            event.stopPropagation();

            // Handle selection
            document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');

            // Show loading indicator
            showLoadingIndicator();

            try {
                // Fetch and display OU details first
                const ouData = await fetchItemsData(dn, 'BASE', ['*']);
                if (ouData && ouData.length > 0) {
                    displayOUDetails(ouData[0]);
                }

                // Check for existing subtree
                let subtreeContainer = div.nextElementSibling;
                if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
                    subtreeContainer.remove();
                } else {
                    await toggleOUSubtree(dn, div);
                }
            } catch (error) {
                console.error('Error handling OU node click:', error);
            } finally {
                hideLoadingIndicator();
            }
        });

        // Add the node to the tree view if it's the root node
        if (isRoot) {
            treeView.appendChild(div);
        }

        return div;
    }

    async function toggleOUSubtree(searchbase, parentElement) {
        try {
            const data = await fetchOUData(searchbase);
            
            if (data && data.length > 0) {
                const subtreeContainer = document.createElement('div');
                subtreeContainer.classList.add('subtree', 'ml-6', 'space-y-1', 'text-sm');

                for (const ou of data) {
                    const ouNode = await createOUTreeNode(ou.dn, ou.attributes.name);
                    if (ouNode) {
                        subtreeContainer.appendChild(ouNode);
                    }
                }

                // Only append if there are child nodes
                if (subtreeContainer.children.length > 0) {
                    parentElement.insertAdjacentElement('afterend', subtreeContainer);
                }
            }
        } catch (error) {
            console.error('Error toggling OU subtree:', error);
        }
    }

    async function deleteOU(identity, searchbase) {
        try {
            showLoadingIndicator();
            const response = await fetch('/api/remove/domainou', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    identity: identity
                })
            });
    
            await handleHttpError(response);
            
            if (response.ok) {
                showSuccessAlert(`Successfully deleted ${identity}`);
                return true;
            }
        } catch (error) {
            console.error('Error deleting domain object:', error);
            showErrorAlert(`Failed to delete ${identity}`);
            return false;
        } finally {
            hideLoadingIndicator();
        }
        return false;
    }

    async function displayOUDetails(ou) {
        const contentDiv = document.getElementById('ou-content');
        if (!contentDiv) return;

        // Hide the initial content
        const initialContent = contentDiv.querySelector('.flex.items-center.justify-center');
        if (initialContent) {
            initialContent.style.display = 'none';
        }

        // Show tabs
        document.getElementById('ou-tabs').style.display = 'flex';

        // Show/hide Linked GPO tab based on gPLink attribute
        const linkedGpoTab = document.querySelector('[aria-controls="tabpanelLinkedGpo"]');
        if (linkedGpoTab) {
            if (ou.attributes.gPLink) {
                linkedGpoTab.classList.remove('hidden');
            } else {
                linkedGpoTab.classList.add('hidden');
                // If the GPO tab was selected, switch to info tab
                if (linkedGpoTab.getAttribute('aria-selected') === 'true') {
                    selectOUTab('info');
                }
            }
        }

        // Update info panel
        const infoPanel = document.getElementById('tabpanelInfo');
        infoPanel.innerHTML = `
            <div class="bg-white dark:bg-neutral-800 rounded-lg">
                <!-- Header with buttons -->
                <div class="bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-white px-4 py-1 border-b border-neutral-200 dark:border-neutral-700 sticky top-0 z-10">
                    <div class="flex justify-between items-center">
                        <h3 class="font-medium">${ou.attributes.name || 'Details'}</h3>
                        <div class="flex gap-2">
                            <button class="px-2 py-1.5 text-sm font-medium rounded-md text-neutral-700 hover:text-neutral-900 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:text-white dark:hover:bg-neutral-800 transition-colors" 
                                    title="Details" 
                                    onclick="handleLdapLinkClick(event, '${ou.dn}')">
                                <i class="fa-solid fa-pen-to-square"></i>
                            </button>
                            <button class="px-2 py-1.5 text-sm font-medium rounded-md text-red-600 hover:text-red-700 hover:bg-red-50 dark:text-red-400 dark:hover:text-red-300 dark:hover:bg-red-900/20 transition-colors" 
                                    title="Delete" 
                                    onclick="showDeleteModal('${ou.dn}')">
                                <i class="fa-solid fa-trash-can"></i>
                            </button>
                        </div>
                    </div>
                </div>
                <!-- Content -->
                <div class="p-4">
                    <dl class="grid grid-cols-1 gap-3">
                        ${Object.entries(ou.attributes).map(([key, value]) => {
                            const isDistinguishedName = Array.isArray(value) ? 
                                value.some(isValidDistinguishedName) : 
                                isValidDistinguishedName(value);

                            if (isDistinguishedName) {
                                if (Array.isArray(value)) {
                                    return `
                                        <div class="flex result-item hover:bg-neutral-50 dark:hover:bg-neutral-800 rounded group">
                                            <dt class="text-sm font-medium text-neutral-600 dark:text-neutral-400 w-1/3">${key}</dt>
                                            <dd class="text-sm text-neutral-900 dark:text-white w-2/3 break-all">
                                                ${value.map(v => `
                                                    <div class="flex items-center gap-2 group">
                                                        <a href="#" 
                                                           class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                                           onclick="handleLdapLinkClick(event, '${v}')"
                                                           data-identity="${v}">
                                                            ${v}
                                                        </a>
                                                        <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800"
                                                                onclick="copyToClipboard(event, '${v}')"
                                                                title="Copy to clipboard">
                                                            <i class="fas fa-copy fa-xs"></i>
                                                        </button>
                                                    </div>
                                                `).join('<br>')}
                                            </dd>
                                        </div>
                                    `;
                                } else {
                                    return `
                                        <div class="flex result-item hover:bg-neutral-50 dark:hover:bg-neutral-800 rounded group">
                                            <dt class="text-sm font-medium text-neutral-600 dark:text-neutral-400 w-1/3">${key}</dt>
                                            <dd class="text-sm text-neutral-900 dark:text-white w-2/3 break-all">
                                                <div class="flex items-center gap-2 group">
                                                    <a href="#" 
                                                       class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300"
                                                       onclick="handleLdapLinkClick(event, '${value}')"
                                                       data-identity="${value}">
                                                        ${value}
                                                    </a>
                                                    <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800"
                                                            onclick="copyToClipboard(event, '${value}')"
                                                            title="Copy to clipboard">
                                                        <i class="fas fa-copy fa-xs"></i>
                                                    </button>
                                                </div>
                                            </dd>
                                        </div>
                                    `;
                                }
                            } else {
                                return `
                                    <div class="flex result-item hover:bg-neutral-50 dark:hover:bg-neutral-800 rounded group">
                                        <dt class="text-sm font-medium text-neutral-600 dark:text-neutral-400 w-1/3">${key}</dt>
                                        <dd class="text-sm text-neutral-900 dark:text-white w-2/3 break-all">
                                            <div class="flex items-center gap-2">
                                                <span>${Array.isArray(value) ? value.join('<br>') : value}</span>
                                                <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800"
                                                        onclick="copyToClipboard(event, '${Array.isArray(value) ? value.join('\\n') : value}')"
                                                        title="Copy to clipboard">
                                                    <i class="fas fa-copy fa-xs"></i>
                                                </button>
                                            </div>
                                        </dd>
                                    </div>
                                `;
                            }
                        }).join('')}
                    </dl>
                </div>
            </div>
        `;

        // Add the copyToClipboard function to window scope
        window.copyToClipboard = async (event, text) => {
            event.stopPropagation();
            const button = event.currentTarget;
            
            try {
                if (navigator.clipboard && window.isSecureContext) {
                    await navigator.clipboard.writeText(text);
                } else {
                    const textArea = document.createElement('textarea');
                    textArea.value = text;
                    textArea.style.position = 'fixed';
                    textArea.style.left = '-999999px';
                    textArea.style.top = '-999999px';
                    document.body.appendChild(textArea);
                    textArea.focus();
                    textArea.select();
                    
                    try {
                        document.execCommand('copy');
                        textArea.remove();
                    } catch (err) {
                        console.error('Fallback: Oops, unable to copy', err);
                        textArea.remove();
                        throw new Error('Copy failed');
                    }
                }
                
                // Show success feedback
                button.innerHTML = '<i class="fas fa-check fa-xs"></i>';
                setTimeout(() => {
                    button.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                }, 1000);
            } catch (err) {
                console.error('Failed to copy text: ', err);
                showErrorAlert('Failed to copy to clipboard');
            }
        };

        // Show info tab by default
        selectOUTab('info');
    }

    const searchInput = document.getElementById('ou-tab-search');
    const clearButton = document.querySelector('.clear-input');

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

    // Add event listener for confirm delete button
    document.getElementById('confirm-delete')?.addEventListener('click', async () => {
        const identity = document.getElementById('identity-to-delete').textContent;
        if (identity) {
            const success = await deleteOU(identity);
            if (success) {
                location.reload(); // Or implement a more elegant refresh
            }
            
            // Hide the modal
            document.getElementById('popup-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
        }
    });

    document.querySelectorAll('[data-modal-hide]').forEach(button => {
        button.addEventListener('click', () => {
            const modalId = button.getAttribute('data-modal-hide');
            const modal = document.getElementById(modalId);
            
            modal.setAttribute('aria-hidden', 'true');
            modal.classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');

            const triggerElement = document.querySelector(`[data-modal-target="${modalId}"]`);
            if (triggerElement) {
                triggerElement.focus();
            }
        });
    });

    initializePropertySelector();
});

// Add these functions
function initializePropertySelector() {
    const dropdownButton = document.getElementById('property-dropdown-button');
    const dropdownMenu = document.getElementById('property-dropdown-menu');

    // Toggle dropdown
    dropdownButton?.addEventListener('click', () => {
        dropdownMenu.classList.toggle('hidden');
    });

    // Close dropdown when clicking outside
    document.addEventListener('click', (event) => {
        if (!dropdownButton?.contains(event.target) && !dropdownMenu?.contains(event.target)) {
            dropdownMenu?.classList.add('hidden');
        }
    });

    // Handle property selection
    document.querySelectorAll('.property-checkbox').forEach(checkbox => {
        checkbox.addEventListener('change', () => {
            if (checkbox.checked) {
                selectedProperties.add(checkbox.value);
            } else {
                selectedProperties.delete(checkbox.value);
            }
            
            // Refresh the descendants view if we're on that tab
            const descendantsTab = document.querySelector('[aria-controls="tabpanelDescendants"]');
            if (descendantsTab?.getAttribute('aria-selected') === 'true') {
                const selectedOU = document.querySelector('.selected');
                if (selectedOU) {
                    const identity = selectedOU.getAttribute('data-dn');
                    loadOUDescendants(identity);
                }
            }
        });
    });
}

// Add at the beginning of the file
let selectedProperties = new Set(['name', 'distinguishedName']);

// Add this new function
function populatePropertyDropdown() {
    const dropdownMenu = document.getElementById('property-dropdown-menu');
    if (!dropdownMenu) return;

    const dropdownContent = document.createElement('div');
    dropdownContent.className = 'p-2 space-y-1';

    // Define all properties
    const properties = [
        { name: 'name', label: 'Name', default: true },
        { name: 'distinguishedName', label: 'Distinguished Name', default: true },
        { name: 'sAMAccountName', label: 'SAM Account Name', default: false },
        { name: 'description', label: 'Description', default: false },
        { name: 'title', label: 'Title', default: false },
        { name: 'department', label: 'Department', default: false },
        { name: 'member', label: 'Members', default: false },
        { name: 'memberOf', label: 'Member Of', default: false }
    ];

    // Create checkboxes for all properties
    properties.forEach(prop => {
        dropdownContent.appendChild(createPropertyCheckbox(prop.name, prop.label, prop.default));
    });

    // Clear existing content and append new
    dropdownMenu.innerHTML = '';
    dropdownMenu.appendChild(dropdownContent);
}

function createPropertyCheckbox(propertyName, labelText, isChecked) {
    const label = document.createElement('label');
    label.className = 'flex items-center px-2 py-1 rounded hover:bg-neutral-100 dark:hover:bg-neutral-700';
    
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.className = 'property-checkbox mr-2';
    checkbox.value = propertyName;
    checkbox.checked = isChecked;
    
    const span = document.createElement('span');
    span.className = 'text-sm text-neutral-700 dark:text-neutral-300';
    span.textContent = labelText;
    
    label.appendChild(checkbox);
    label.appendChild(span);
    
    // Add event listener for the checkbox
    checkbox.addEventListener('change', () => {
        if (checkbox.checked) {
            selectedProperties.add(propertyName);
        } else {
            selectedProperties.delete(propertyName);
        }
        
        // Refresh the descendants view if we're on that tab
        const descendantsTab = document.querySelector('[aria-controls="tabpanelDescendants"]');
        if (descendantsTab?.getAttribute('aria-selected') === 'true') {
            const selectedOU = document.querySelector('.selected');
            if (selectedOU) {
                const identity = selectedOU.getAttribute('data-dn');
                loadOUDescendants(identity);
            }
        }
    });
    
    return label;
}
