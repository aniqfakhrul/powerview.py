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

    if (tabName === 'descendants') {
        const selectedOU = document.querySelector('.selected');
        if (selectedOU) {
            const identity = selectedOU.getAttribute('data-dn');
            await loadOUDescendants(identity);
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

async function loadOUDescendants(identity) {
    try {
        showLoadingIndicator();
        const data = await fetchItemsData(identity);
        
        const tbody = document.getElementById('descendants-rows');
        tbody.innerHTML = '';

        if (data && Array.isArray(data)) {
            // Filter out the searched OU from the list
            const descendants = data.filter(item => 
                item.attributes?.distinguishedName?.toLowerCase() !== identity.toLowerCase()
            );

            descendants.forEach(item => {
                if (!item.attributes) return;

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
                    'text-neutral-600',
                    'cursor-pointer'
                );

                const objectClass = item.attributes.objectClass || [];
                const icon = getObjectClassIcon(objectClass);
                
                row.innerHTML = `
                    <td class="px-3 py-2">${icon}</td>
                    <td class="px-3 py-2">${item.attributes.name || ''}</td>
                    <td class="px-3 py-2">${item.attributes.distinguishedName || ''}</td>
                `;

                // Add click event to the entire row
                row.addEventListener('click', () => {
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

            const domainInfo = await getDomainInfo();
            const rootDn = domainInfo.root_dn;
            
            // Create and add root node
            const rootNode = await createOUTreeNode(rootDn, true);
            if (rootNode) {
                // Automatically expand root node
                await toggleOUSubtree(rootDn, rootNode);
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

    async function createOUTreeNode(dn, isRoot = false) {
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
        );

        const icon = isRoot ? icons.adIcon : icons.ouIcon;
        div.innerHTML = `${icon}<span class="text-neutral-900 dark:text-white">${dn}</span>`;
        div.setAttribute('data-dn', dn);

        div.addEventListener('click', async (event) => {
            event.stopPropagation();

            // Handle selection
            document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');

            // Show loading indicator
            showLoadingIndicator();

            try {
                // Check for existing subtree
                let subtreeContainer = div.nextElementSibling;
                if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
                    subtreeContainer.remove();
                } else {
                    // Fetch and display OU details
                    const ouData = await fetchOUData(dn, 'BASE');
                    if (ouData && ouData.length > 0) {
                        displayOUDetails(ouData[0]);
                        await toggleOUSubtree(dn, div);
                    }
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
                subtreeContainer.classList.add('subtree', 'ml-6', 'space-y-1');

                for (const ou of data) {
                    const ouNode = await createOUTreeNode(ou.dn);
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

    function displayOUDetails(ou) {
        const contentDiv = document.getElementById('ou-content');
        if (!contentDiv) return;

        // Hide the initial content
        const initialContent = contentDiv.querySelector('.flex.items-center.justify-center');
        if (initialContent) {
            initialContent.style.display = 'none';
        }

        // Show tabs
        document.getElementById('ou-tabs').style.display = 'flex';

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
                        ${Object.entries(ou.attributes).map(([key, value]) => `
                            <div class="flex result-item hover:bg-neutral-50 dark:hover:bg-neutral-800 rounded">
                                <dt class="text-sm font-medium text-neutral-600 dark:text-neutral-400 w-1/3">${key}</dt>
                                <dd class="text-sm text-neutral-900 dark:text-white w-2/3 break-all">
                                    ${Array.isArray(value) ? value.join('<br>') : value}
                                </dd>
                            </div>
                        `).join('')}
                    </dl>
                </div>
            </div>
        `;

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
});
