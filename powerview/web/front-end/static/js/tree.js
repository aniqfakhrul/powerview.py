document.addEventListener('DOMContentLoaded', () => {
    async function initialize() {
        try {
                    const [domainInfoResponse, serverInfoResponse] = await Promise.all([
            fetch('/api/get/domaininfo', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            }),
            fetch('/api/server/info', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            })
        ]);

        await handleHttpError(domainInfoResponse);
        await handleHttpError(serverInfoResponse);

        const domainInfo = await domainInfoResponse.json();
        const serverInfo = await serverInfoResponse.json();
        const rootDn = domainInfo.root_dn;
        const domainName = domainInfo.domain;
        const flatName = domainInfo.flatName;

        const domainSpan = document.querySelector('span#domain-name');
        if (domainSpan) {
            domainSpan.textContent = flatName;
        }

        function getIconForNamingContext(dn) {
            if (dn === rootDn) {
                return icons.adIcon;
            } else if (dn.includes('CN=Configuration')) {
                return icons.adIcon;
            } else if (dn.includes('CN=Schema')) {
                return icons.defaultIcon;
            } else if (dn.includes('DomainDnsZones') || dn.includes('ForestDnsZones')) {
                return icons.adIcon;
            } else {
                return icons.defaultIcon;
            }
        }

        const rootNodes = serverInfo.raw.namingContexts.map(dn => ({
            dn: dn,
            icon: getIconForNamingContext(dn)
        }));

        const systemDn = `CN=System,${rootDn}`;
        const systemNodeExists = rootNodes.find(node => node.dn === systemDn);
        if (!systemNodeExists) {
            rootNodes.push({ dn: systemDn, icon: icons.defaultIcon });
        }

            for (const node of rootNodes) {
                const exists = await checkDistinguishedNameExists(node.dn);
                if (exists) {
                    const treeNode = createTreeNode(node.dn, node.icon);
                    if (node.dn === rootDn) {
                        // Check for domain trusts
                        const trusts = await getDomainTrust(node.dn);
                        if (trusts && trusts.length > 0) {
                            // Add trust tag
                            const trustTag = document.createElement('span');
                            trustTag.className = 'ml-2 text-xs font-medium px-2 py-0.5 rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300';
                            trustTag.textContent = 'Trust';
                            treeNode.appendChild(trustTag);

                            // Show Trusts tab
                            const trustsTab = document.querySelector('[aria-controls="tabpanelTrusts"]');
                            if (trustsTab) {
                                trustsTab.style.display = '';
                            }
                        }

                        // Mark the root node as selected
                        document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
                        treeNode.classList.add('selected');
                        treeNode.setAttribute('data-identifier', node.dn);


                        // Automatically expand the rootDn node
                        toggleSubtree(node.dn, treeNode);

                        // Fetch and display the rootDn details in the results panel
                        const rootDnData = await fetchItemData(rootDn, 'BASE');
                        if (rootDnData) {
                            populateResultsPanel(rootDnData);
                        }
                    }
                }
            }
        } catch (error) {
            console.error('Error during initialization:', error);
        }
    }

    async function checkDistinguishedNameExists(identity) {
        try {
            const response = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchbase: identity, search_scope: 'BASE' })
            });

            if (!response.ok) {
                return false;
            }

            const data = await response.json();
            return data && data.length > 0;
        } catch (error) {
            console.error('Error checking distinguished name:', error);
            return false;
        }
    }

    function createTreeNode(dn, icon) {
        const treeView = document.getElementById('tree-view');
        if (!treeView) return;

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

        div.innerHTML += `${icon}<span class="text-neutral-900 dark:text-white">${dn}</span>`;

        div.addEventListener('click', async (event) => {
            event.stopPropagation();

            // Reset to the "General" tab
            selectTab('general');

            // Mark this node as selected
            document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
            div.classList.add('selected');

            const itemData = await fetchItemData(dn, 'BASE');
            if (itemData) {
                populateResultsPanel(itemData);

                // Show/hide Members tab for groups
                const membersTab = document.querySelector('[aria-controls="tabpanelMembers"]');
                if (membersTab) {
                    if (itemData.attributes.objectClass && itemData.attributes.objectClass.includes('group')) {
                        membersTab.style.display = '';
                    } else {
                        membersTab.style.display = 'none';
                    }
                }

                // Show/hide Trusts tab for domains
                const trustsTab = document.querySelector('[aria-controls="tabpanelTrusts"]');
                if (trustsTab) {
                    if (itemData.attributes.objectClass && itemData.attributes.objectClass.includes('domain')) {
                        trustsTab.style.display = '';
                    } else {
                        trustsTab.style.display = 'none';
                    }
                }
                
                toggleSubtree(dn, div);
            }
        });

        treeView.appendChild(div);
        return div;
    }

    
    async function toggleSubtree(searchbase, parentElement, no_cache=false) {
        const spinner = document.getElementById(`spinner-${convertDnToId(searchbase)}`);
        if (spinner) {
            spinner.classList.remove('hidden'); // Show the spinner
        }

        let subtreeContainer = parentElement.nextElementSibling;
        if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
            subtreeContainer.remove();
            if (spinner) {
                spinner.classList.add('hidden'); // Hide the spinner if subtree is removed
            }
            return; // Exit the function to prevent fetching data again
        }

        try {
            const response = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchbase: searchbase, search_scope: 'LEVEL', no_cache: no_cache })
            });

            await handleHttpError(response);

            const data = await response.json();

            if (Array.isArray(data)) {
                displaySubtree(data, parentElement);
            } else if (data && typeof data === 'object') {
                displaySubtree([data], parentElement);
            } else {
                console.error('Unexpected data format:', data);
            }
        } catch (error) {
            console.error('Error fetching subtree:', error);
        } finally {
            if (spinner) {
                spinner.classList.add('hidden'); // Hide the spinner after processing
            }
        }
    }

    async function getDomainGroupMember(groupName) {
        try {
            const response = await fetch('/api/get/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identity: groupName })
            });

            if (!response.ok) {
                throw new Error('Failed to fetch group members');
            }

            const data = await response.json();
            console.log('Group Members:', data);
        } catch (error) {
            console.error('Error fetching group members:', error);
        }
    }

    function displaySubtree(dataArray, parentElement) {
        const subtreeContainer = document.createElement('div');
        subtreeContainer.classList.add(
            'ml-6', 
            'subtree',
            'space-y-1'
        );

        dataArray.forEach(obj => {
            const objDiv = document.createElement('div');
            objDiv.classList.add(
                'flex', 
                'items-center', 
                'gap-1', 
                'hover:bg-neutral-100',
                'dark:hover:bg-neutral-800',
                'rounded', 
                'cursor-pointer',
            );

            let iconSVG = icons.defaultIcon;
            let objectClassLabel = 'Object'; // Default label

            // Ensure obj.attributes.objectClass is an array before using includes
            if (Array.isArray(obj.attributes.objectClass)) {
                if (obj.attributes.objectClass.includes('group')) {
                    iconSVG = icons.groupIcon;
                    objectClassLabel = 'Group';
                } else if (obj.attributes.objectClass.includes('container')) {
                    iconSVG = icons.containerIcon; // Use fa-box-open for containers
                    objectClassLabel = 'Container';
                } else if (obj.attributes.objectClass.includes('computer')) {
                    iconSVG = icons.computerIcon; // Use fa-desktop for computers
                    objectClassLabel = 'Computer';
                } else if (obj.attributes.objectClass.includes('user')) {
                    iconSVG = icons.userIcon;
                    objectClassLabel = 'User';
                } else if (obj.attributes.objectClass.includes('organizationalUnit')) {
                    iconSVG = icons.ouIcon; // Use fa-building for organizational units
                    objectClassLabel = 'Organizational Unit';
                } else if (obj.attributes.objectClass.includes('builtinDomain')) {
                    iconSVG = icons.builtinIcon;
                    objectClassLabel = 'Builtin';
                } else {
                    objectClassLabel = obj.attributes.objectClass[obj.attributes.objectClass.length - 1];
                }

                if (obj.attributes.adminCount === 1) {
                    iconSVG += icons.keyIcon;
                }
            }

            const escapedDn = convertDnToId(obj.dn);

            // Assign a data-identifier attribute to each tree node
            objDiv.setAttribute('data-identifier', obj.dn);

            objDiv.innerHTML = `${iconSVG}<span class="cursor-pointer text-neutral-900 dark:text-white">${obj.attributes.name || obj.dn}</span>${getSpinnerSVG(escapedDn)}`;

            // Set the title attribute to show the object class on hover
            objDiv.setAttribute('title', objectClassLabel);

            objDiv.addEventListener('click', async (event) => {
                event.stopPropagation();

                // Reset to the "General" tab
                selectTab('general');

                // Mark this node as selected
                document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
                objDiv.classList.add('selected');

                // Show/hide Members tab for groups
                const membersTab = document.querySelector('[aria-controls="tabpanelMembers"]');
                if (membersTab) {
                    if (obj.attributes.objectClass && obj.attributes.objectClass.includes('group')) {
                        membersTab.style.display = '';
                    } else {
                        membersTab.style.display = 'none';
                    }
                }

                // Show/hide Trusts tab for domains
                const trustsTab = document.querySelector('[aria-controls="tabpanelTrusts"]');
                if (trustsTab) {
                    if (obj.attributes.objectClass && obj.attributes.objectClass.includes('domain')) {
                        trustsTab.style.display = '';
                    } else {
                        trustsTab.style.display = 'none';
                    }
                }

                // Show the spinner on the right side of the node
                showLoadingIndicator();
                let childSubtreeContainer = objDiv.nextElementSibling;
                if (childSubtreeContainer && childSubtreeContainer.classList.contains('subtree')) {
                    childSubtreeContainer.remove();
                    hideLoadingIndicator();
                    return;
                }

                const itemData = await fetchItemData(obj.dn, 'BASE');
                if (itemData) {
                    populateResultsPanel(itemData);
                    toggleSubtree(obj.dn, objDiv);
                }

                hideLoadingIndicator();
            });

            subtreeContainer.appendChild(objDiv);
        });

        parentElement.insertAdjacentElement('afterend', subtreeContainer);
    }

    function populateResultsPanel(item) {
        const resultsPanel = document.getElementById("general-content");
        const attributes = item.attributes;
        
        const searchInput = document.getElementById('tab-search');
        const currentSearchQuery = searchInput ? searchInput.value.toLowerCase() : '';

        // Create the header div with buttons
        const headerDiv = document.createElement('div');
        headerDiv.className = 'bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-white px-4 py-1 border-b border-neutral-200 dark:border-neutral-700 sticky top-0 z-10';
        
        // Create flex container for header content
        const headerContent = document.createElement('div');
        headerContent.className = 'flex justify-between items-center';
        
        // Create title
        const headerH3 = document.createElement('h3');
        headerH3.className = 'font-medium';
        headerH3.textContent = attributes.name || 'Details';

        // Create buttons container
        const buttonsDiv = document.createElement('div');
        buttonsDiv.className = 'flex gap-2';

        // Add User button
        if (Array.isArray(attributes.objectClass) && (attributes.objectClass.includes('container') || attributes.objectClass.includes('organizationalUnit') || attributes.objectClass.includes('builtinDomain') || attributes.objectClass.includes('domain'))) {
            const addUserButton = document.createElement('button');
            addUserButton.className = 'px-2 py-1.5 text-sm font-medium rounded-md text-blue-600 hover:text-blue-700 hover:bg-blue-50 dark:text-yellow-500 dark:hover:text-yellow-400 dark:hover:bg-yellow-900/20 transition-colors';
            addUserButton.innerHTML = icons.userIcon;
            addUserButton.setAttribute('title', 'Add User');
            addUserButton.onclick = () => handleCreateUser(item.dn);
            buttonsDiv.appendChild(addUserButton);
        }

        // Add Group button
        if (Array.isArray(attributes.objectClass) && (attributes.objectClass.includes('container') || attributes.objectClass.includes('organizationalUnit') || attributes.objectClass.includes('builtinDomain') || attributes.objectClass.includes('domain'))) {
            const addGroupButton = document.createElement('button');
            addGroupButton.className = 'px-2 py-1.5 text-sm font-medium rounded-md text-blue-600 hover:text-blue-700 hover:bg-blue-50 dark:text-yellow-500 dark:hover:text-yellow-400 dark:hover:bg-yellow-900/20 transition-colors';
            addGroupButton.innerHTML = icons.groupIcon;
            addGroupButton.setAttribute('title', 'Add Group');
            addGroupButton.onclick = () => handleCreateGroup(item.dn);
            buttonsDiv.appendChild(addGroupButton);
        }

        // Add "Add User to Group" button only if object is a group
        if (Array.isArray(attributes.objectClass) && (attributes.objectClass.includes('group') || attributes.objectClass.includes('user'))) {
            const addUserToGroupButton = document.createElement('button');
            addUserToGroupButton.className = 'px-2 py-1.5 text-sm font-medium rounded-md text-blue-600 hover:text-blue-700 hover:bg-blue-50 dark:text-yellow-500 dark:hover:text-yellow-400 dark:hover:bg-yellow-900/20 transition-colors';
            addUserToGroupButton.innerHTML = '<i class="fa-solid fa-user-plus"></i>';
            addUserToGroupButton.setAttribute('title', 'Add User to Group');
            addUserToGroupButton.onclick = () => handleAddGroupMember(item);
            buttonsDiv.appendChild(addUserToGroupButton);
        }

        if (Array.isArray(attributes.objectClass) && attributes.objectClass.includes('group')) {
            const removeUserButton = document.createElement('button');
            removeUserButton.className = 'px-2 py-1 text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300';
            removeUserButton.innerHTML = '<i class="fas fa-user-minus"></i>';
            removeUserButton.title = 'Delete user from group';
            removeUserButton.onclick = () => handleRemoveGroupMember(item);
            buttonsDiv.appendChild(removeUserButton);
        }

        // Create Details button
        const detailsButton = document.createElement('button');
        detailsButton.className = 'px-2 py-1.5 text-sm font-medium rounded-md text-neutral-700 hover:text-neutral-900 hover:bg-neutral-100 dark:text-neutral-300 dark:hover:text-white dark:hover:bg-neutral-800 transition-colors';
        detailsButton.innerHTML = '<i class="fa-solid fa-pen-to-square"></i>';
        detailsButton.setAttribute('title', 'Edit');
        detailsButton.onclick = (event) => handleLdapLinkClick(event, item.dn);

        // Create Delete button
        const deleteButton = document.createElement('button');
        deleteButton.className = 'px-2 py-1.5 text-sm font-medium rounded-md text-red-600 hover:text-red-700 hover:bg-red-50 dark:text-red-400 dark:hover:text-red-300 dark:hover:bg-red-900/20 transition-colors';
        deleteButton.innerHTML = '<i class="fa-solid fa-trash-can"></i>';
        deleteButton.setAttribute('title', 'Delete');
        deleteButton.onclick = () => showDeleteModal(item.dn);

        // Assemble the header
        buttonsDiv.appendChild(detailsButton);
        buttonsDiv.appendChild(deleteButton);
        headerContent.appendChild(headerH3);
        headerContent.appendChild(buttonsDiv);
        headerDiv.appendChild(headerContent);

        // Create the content div
        const contentDiv = document.createElement('div');
        contentDiv.className = 'p-4 space-y-2';

        const dl = document.createElement('dl');
        dl.className = 'grid grid-cols-1 gap-1';

        for (const [key, value] of Object.entries(attributes)) {
            const isDistinguishedName = Array.isArray(value) ? value.some(isValidDistinguishedName) : isValidDistinguishedName(value);

            const flexDiv = document.createElement('div');
            flexDiv.className = 'flex result-item hover:bg-neutral-50 dark:hover:bg-neutral-800 rounded';

            // Apply initial visibility based on current search
            if (currentSearchQuery) {
                const textContent = `${key}${Array.isArray(value) ? value.join(' ') : value}`.toLowerCase();
                if (!textContent.includes(currentSearchQuery)) {
                    flexDiv.classList.add('hidden');
                }
            }

            const dt = document.createElement('dt');
            dt.className = 'text-sm font-medium text-neutral-600 dark:text-neutral-400 w-1/3';
            dt.textContent = key;
            flexDiv.appendChild(dt);

            const dd = document.createElement('dd');
            dd.className = 'text-sm text-neutral-900 dark:text-white w-2/3 break-all';

            if (isDistinguishedName) {
                if (Array.isArray(value)) {
                    value.forEach(v => {
                        const wrapper = document.createElement('div');
                        wrapper.className = 'flex items-center gap-2 group';

                        const link = document.createElement('a');
                        link.href = '#';
                        link.className = 'text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300';
                        link.dataset.identity = v;
                        link.onclick = (event) => handleLdapLinkClick(event, v);
                        link.textContent = v;
                        
                        const copyButton = createCopyButton(v);
                        
                        wrapper.appendChild(link);
                        wrapper.appendChild(copyButton);
                        dd.appendChild(wrapper);
                    });
                } else {
                    const wrapper = document.createElement('div');
                    wrapper.className = 'flex items-center gap-2 group';

                    const link = document.createElement('a');
                    link.href = '#';
                    link.className = 'text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300';
                    link.dataset.identity = value;
                    link.onclick = (event) => handleLdapLinkClick(event, value);
                    link.textContent = value;
                    
                    const copyButton = createCopyButton(value);
                    
                    wrapper.appendChild(link);
                    wrapper.appendChild(copyButton);
                    dd.appendChild(wrapper);
                }
            } else {
                const wrapper = document.createElement('div');
                wrapper.className = 'flex items-center gap-2 group';
                
                const textSpan = document.createElement('span');
                if (Array.isArray(value)) {
                    const formattedValue = value.map(v => isByteData(v) ? convertToBase64(v) : v);
                    textSpan.innerHTML = formattedValue.join('<br>');
                    const copyButton = createCopyButton(formattedValue.join('\n'));
                    wrapper.appendChild(textSpan);
                    wrapper.appendChild(copyButton);
                } else {
                    const formattedValue = isByteData(value) ? convertToBase64(value) : value;
                    textSpan.textContent = formattedValue;
                    const copyButton = createCopyButton(formattedValue);
                    wrapper.appendChild(textSpan);
                    wrapper.appendChild(copyButton);
                }
                
                dd.appendChild(wrapper);
            }

            flexDiv.appendChild(dd);
            dl.appendChild(flexDiv);
        }

        contentDiv.appendChild(dl);
        resultsPanel.innerHTML = '';
        resultsPanel.appendChild(headerDiv);
        resultsPanel.appendChild(contentDiv);
    }

    // Helper function to create copy button
    function createCopyButton(text) {
        const copyButton = document.createElement('button');
        copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
        copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
        copyButton.title = 'Copy to clipboard';
        
        copyButton.addEventListener('click', async (event) => {
            event.stopPropagation();
            
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
                
                copyButton.innerHTML = '<i class="fas fa-check fa-xs"></i>';
                setTimeout(() => {
                    copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                }, 1000);
            } catch (err) {
                console.error('Failed to copy text: ', err);
                showErrorAlert('Failed to copy to clipboard');
            }
        });
        
        return copyButton;
    }

    function getSelectedIdentity() {
        const selectedElement = document.querySelector('.selected');
        return selectedElement ? selectedElement.getAttribute('data-identifier') : null;
    }

    function setupTabEventDelegation() {
        const tabList = document.querySelector('[role="tablist"]');
        if (!tabList) return;

        tabList.addEventListener('click', (event) => {
            const clickedTab = event.target.closest('[role="tab"]');
            if (!clickedTab) return;

            // Update the active state of tabs
            tabList.querySelectorAll('[role="tab"]').forEach(tab => {
                tab.setAttribute('aria-selected', tab === clickedTab ? 'true' : 'false');
            });

            // Update the visibility of tab panels
            const tabPanels = document.querySelectorAll('[role="tabpanel"]');
            tabPanels.forEach(panel => {
                panel.style.display = panel.id === clickedTab.getAttribute('aria-controls') ? 'block' : 'none';
            });
        });
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

    // Add event listener for confirm delete button
    document.getElementById('confirm-delete')?.addEventListener('click', async () => {
        const identity = document.getElementById('identity-to-delete').textContent;
        if (identity) {
            const selectedNode = document.querySelector('.selected');
            if (selectedNode) {
                // Get the parent subtree container
                const subtreeContainer = selectedNode.closest('.subtree');
                if (!subtreeContainer) {
                    console.error('No parent subtree found');
                    return;
                }

                // Get the parent node (the div before the subtree container)
                const parentNode = subtreeContainer.previousElementSibling;
                if (!parentNode) {
                    console.error('No parent node found');
                    return;
                }

                const parentDn = parentNode.getAttribute('data-identifier');

                const success = await deleteDomainObject(identity, identity);
                if (success && parentDn) {
                    // Select the parent node
                    document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
                    parentNode.classList.add('selected');
                    
                    // Refresh the parent's subtree
                    await refreshCurrentSubtree();
                }
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

    async function removeDomainGroupMember(identity, member) {
        try {
            const response = await fetch('/api/remove/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    identity: identity,
                    members: member
                })
            });

            await handleHttpError(response);

            const success = await response.json();
            if (success) {
                showSuccessAlert(`Removed ${member} from ${identity}`);
            } else {
                showErrorAlert(success.message);
            }
        } catch (error) {
            console.error('Error removing group member:', error);
            showErrorAlert('Failed to remove group member. Please try again.');
        }
    }

    async function addDomainGroupMember(groupname, member) {
        try {
            const response = await fetch('/api/add/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    identity: groupname, 
                    members: member
                })
            });

            await handleHttpError(response);

            const success = await response.json();
            if (success) {
                showSuccessAlert(`Added ${member} to ${groupname}`);
            } else {
                showErrorAlert(success.message);
            }
        } catch (error) {
            console.error('Error adding group member:', error);
            showErrorAlert('Failed to add group member. Please try again.');
        }
    }

    async function addGroup(groupname, basedn) {
        try {
            const response = await fetch('/api/add/domaingroup', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    groupname, 
                    basedn: basedn || ''
                })
            });

            await handleHttpError(response);

            const success = await response.json();
            if (success) {
                showSuccessAlert(`Added group ${groupname} to ${basedn}`);
            } else {
                showErrorAlert(success.message);
            }
            
            // Refresh the current subtree to show the new group
            await refreshCurrentSubtree();
        } catch (error) {
            console.error('Error adding group:', error);
            showErrorAlert('Failed to add group. Please try again.');
        }
    }
    
    async function addUser(username, password, basedn) {
        try {
            const response = await fetch('/api/add/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ 
                    username, 
                    userpass: password,
                    basedn: basedn || ''
                })
            });

            await handleHttpError(response);

            const success = await response.json();
            if (success) {
                showSuccessAlert(`Added user ${username} to ${basedn}`);
            } else {
                showErrorAlert(success.message);
            }
            
            // Refresh the current subtree to show the new user
            await refreshCurrentSubtree();
        } catch (error) {
            console.error('Error adding user:', error);
            showErrorAlert('Failed to add user. Please try again.');
        }
    }

    async function showAddGroupModal(containerDn) {
        const modal = document.getElementById('add-group-modal');
        const overlay = document.getElementById('modal-overlay');
        const basednInput = document.getElementById('group-base-dn');
        const groupnameInput = document.getElementById('new-groupname');
    
        if (basednInput) {
            basednInput.value = containerDn;
        }
        
        try {
            // Show the modal
            modal.removeAttribute('aria-hidden');
            modal.classList.remove('hidden');
            overlay.classList.remove('hidden');
    
            // Focus on the groupname input
            if (groupnameInput) {
                setTimeout(() => {
                    groupnameInput.focus();
                }, 100); // Small delay to ensure modal is fully visible
            }
        } catch (error) {
            console.error('Error initializing Add Group Modal:', error);
            showErrorAlert('Failed to initialize Add Group Modal');
        }
    }

    document.getElementById('add-group-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const groupname = document.getElementById('new-groupname')?.value;
        const basedn = document.getElementById('group-base-dn')?.value;

        if (!groupname || !basedn) {
            showErrorAlert('Please fill in all fields');
            return;
        }

        try {
            await addGroup(groupname, basedn);
            
            // Close the modal
            document.getElementById('add-group-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
            
            // Clear the form
            document.getElementById('add-group-form').reset();
        } catch (error) {
            console.error('Error adding group:', error);
            showErrorAlert('Failed to add group');
        }
    });

    async function showRemoveGroupMemberModal(item) {
        const modal = document.getElementById('remove-group-member-modal');
        const overlay = document.getElementById('modal-overlay');
        const groupNameInput = document.getElementById('remove-group-name');
        const memberSelect = document.getElementById('remove-member');

        // Clear previous values
        groupNameInput.value = '';
        memberSelect.innerHTML = '';

        if (item.attributes.name) {
            groupNameInput.value = item.attributes.name;
        }

        // Populate the member dropdown if members exist
        if (item.attributes.member) {
            // Convert to array if it's a single string
            const members = Array.isArray(item.attributes.member) ? 
                item.attributes.member : [item.attributes.member];

            members.forEach(member => {
                const option = document.createElement('option');
                option.value = member;
                option.textContent = member.split(',')[0].replace('CN=', ''); // Show only the CN part
                memberSelect.appendChild(option);
            });
        }

        try {
            // Show the modal
            modal.removeAttribute('aria-hidden');
            modal.classList.remove('hidden');
            overlay.classList.remove('hidden');

            // Add event listener for form submission
            const form = document.getElementById('remove-group-member-form');
            form.onsubmit = async (e) => {
                e.preventDefault();
                const groupname = groupNameInput.value;
                const member = memberSelect.value;
                
                if (!groupname || !member) {
                    showErrorAlert('Please select a member to remove');
                    return;
                }

                try {
                    await removeDomainGroupMember(groupname, member);
                    modal.classList.add('hidden');
                    overlay.classList.add('hidden');
                    form.reset();
                    
                    // Refresh both the tree view and results panel
                    const selectedNode = document.querySelector('.selected');
                    if (selectedNode) {
                        const dn = selectedNode.getAttribute('data-identifier');
                        // Fetch updated data and refresh the results panel
                        const updatedData = await fetchItemData(dn, 'BASE');
                        if (updatedData) {
                            populateResultsPanel(updatedData);
                        }
                    }
                    
                    // Also refresh the tree view
                    await refreshCurrentSubtree();
                } catch (error) {
                    console.error('Error removing group member:', error);
                    showErrorAlert('Failed to remove group member');
                }
            };
        } catch (error) {
            console.error('Error initializing Remove Group Member Modal:', error);
            showErrorAlert('Failed to initialize Remove Group Member Modal');
        }
    }

    // Add event listeners for modal close buttons
    document.querySelectorAll('[data-modal-hide="remove-group-member-modal"]').forEach(button => {
        button.addEventListener('click', () => {
            document.getElementById('remove-group-member-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
        });
    });

    async function showAddGroupMemberModal(item) {
        const modal = document.getElementById('add-group-member-modal');
        const overlay = document.getElementById('modal-overlay');
        const groupNameInput = document.getElementById('group-name');
        const memberInput = document.getElementById('new-member');
    
        // clear the inputs
        groupNameInput.value = '';
        memberInput.value = '';
    
        // Check if item has objectClass array
        if (item.attributes.objectClass && Array.isArray(item.attributes.objectClass)) {
            if (item.attributes.objectClass.includes('group')) {
                // If item is a group, fill in group name
                if (groupNameInput) {
                    groupNameInput.value = item.attributes.name;
                }
            } else if (item.attributes.objectClass.includes('user')) {
                // If item is a user, fill in member name
                if (memberInput) {
                    memberInput.value = item.attributes.name;
                }
            }
        }
    
        try {
            // Show the modal
            modal.removeAttribute('aria-hidden');
            modal.classList.remove('hidden');
            overlay.classList.remove('hidden');
    
            // Focus on appropriate input based on object type
            if (item.attributes.objectClass?.includes('group')) {
                if (memberInput) {
                    setTimeout(() => {
                        memberInput.focus();
                    }, 100);
                }
            } else if (item.attributes.objectClass?.includes('user')) {
                if (groupNameInput) {
                    setTimeout(() => {
                        groupNameInput.focus(); 
                    }, 100);
                }
            }
        } catch (error) {
            console.error('Error initializing Add Group Member Modal:', error);
            showErrorAlert('Failed to initialize Add Group Member Modal');
        }
    }

    document.getElementById('add-group-member-form')?.addEventListener('submit', async (event) => {
        event.preventDefault();
        const groupname = document.getElementById('group-name')?.value;
        const member = document.getElementById('new-member')?.value;
        if (!groupname || !member) {
            showErrorAlert('Please fill in all fields');
            return;
        }
    
        try {
            await addDomainGroupMember(groupname, member);
            
            // Close the modal
            document.getElementById('add-group-member-modal')?.classList.add('hidden');
            document.getElementById('modal-overlay')?.classList.add('hidden');
            
            // Clear the form
            document.getElementById('add-group-member-form').reset();
    
            // Refresh both the tree view and results panel
            const selectedNode = document.querySelector('.selected');
            if (selectedNode) {
                const dn = selectedNode.getAttribute('data-identifier');
                // Fetch updated data and refresh the results panel
                const updatedData = await fetchItemData(dn, 'BASE');
                if (updatedData) {
                    populateResultsPanel(updatedData);
                }
            }
            
            // Also refresh the tree view
            await refreshCurrentSubtree();
        } catch (error) {
            console.error('Error adding group member:', error);
            showErrorAlert('Failed to add group member');
        }
    });

    async function showAddUserModal(containerDn) {
        const modal = document.getElementById('add-user-modal');
        const overlay = document.getElementById('modal-overlay');
        const basednInput = document.getElementById('user-base-dn');
        const usernameInput = document.getElementById('new-username');

        if (basednInput) {
            basednInput.value = containerDn;
        }
        
        try {
            // Show the modal
            modal.removeAttribute('aria-hidden');
            modal.classList.remove('hidden');
            overlay.classList.remove('hidden');

            // Focus on the username input
            if (usernameInput) {
                setTimeout(() => {
                    usernameInput.focus();
                }, 100); // Small delay to ensure modal is fully visible
            }
        } catch (error) {
            console.error('Error initializing Add User Modal:', error);
            showErrorAlert('Failed to initialize Add User Modal');
        }
    }

    document.getElementById('add-user-form')?.addEventListener('submit', (event) => {
        event.preventDefault();
        const username = document.getElementById('new-username')?.value;
        const password = document.getElementById('new-password')?.value;
        const basedn = document.getElementById('user-base-dn')?.value;
        if (!username || !password) {
            showErrorAlert('Please fill in all fields');
            return;
        }

        addUser(username, password, basedn);
        document.getElementById('add-user-modal')?.classList.add('hidden');
        document.getElementById('modal-overlay')?.classList.add('hidden');
    });

    // Add these functions to handle user and group creation
    function handleCreateUser(containerDn) {
        console.log('Create user in container:', containerDn);
        showAddUserModal(containerDn);
    }

    function handleCreateGroup(containerDn) {
        console.log('Create group in container:', containerDn);
        showAddGroupModal(containerDn);
    }

    function handleAddGroupMember(item) {
        console.log('Add member to group:', item.attributes.name);
        showAddGroupMemberModal(item);
    }

    function handleRemoveGroupMember(item) {
        console.log('Remove member from group:', item.attributes.name);
        showRemoveGroupMemberModal(item);
    }

    async function refreshCurrentSubtree() {
        const selectedNode = document.querySelector('.selected');
        if (!selectedNode) return;

        const dn = selectedNode.getAttribute('data-identifier');
        const parentDiv = selectedNode.closest('div');
        
        // Find and remove the existing subtree
        const existingSubtree = selectedNode.nextElementSibling;
        if (existingSubtree && existingSubtree.classList.contains('subtree')) {
            existingSubtree.remove();
        }

        // Re-fetch and display the subtree
        try {
            showLoadingIndicator();
            await toggleSubtree(dn, parentDiv, no_cache=true);
        } catch (error) {
            console.error('Error refreshing subtree:', error);
        } finally {
            hideLoadingIndicator();
        }
    }

    // Call this function after the DOM is fully loaded
    initialize();
    setupTabEventDelegation();

    // Update the search functionality
    const searchInput = document.getElementById('object-tree-search');
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            const searchTerm = e.target.value.toLowerCase();
            const treeNodes = document.querySelectorAll('#tree-view > div');
            
            treeNodes.forEach(node => {
                // Always show parent nodes to maintain structure
                node.style.display = '';
                
                // Find the subtree container
                const subtree = node.querySelector('.subtree');
                if (subtree) {
                    const childNodes = subtree.querySelectorAll(':scope > div');
                    let hasVisibleChildren = false;
                    
                    childNodes.forEach(childNode => {
                        const childText = childNode.querySelector('span')?.textContent.toLowerCase() || '';
                        if (childText.includes(searchTerm)) {
                            childNode.style.display = '';
                            hasVisibleChildren = true;
                        } else {
                            childNode.style.display = 'none';
                        }
                    });

                    // Show/hide subtree based on whether it has visible children
                    subtree.style.display = hasVisibleChildren || searchTerm === '' ? '' : 'none';
                }
            });
        });
    }
});