document.addEventListener('DOMContentLoaded', () => {
    async function initialize() {
        try {
            const domainInfoResponse = await fetch('/api/get/domaininfo', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            await handleHttpError(domainInfoResponse);

            const domainInfo = await domainInfoResponse.json();
            const rootDn = domainInfo.root_dn;
            const domainName = domainInfo.domain;
            const flatName = domainInfo.flatName;

            const domainSpan = document.querySelector('span#domain-name');
            if (domainSpan) {
                domainSpan.textContent = flatName;
            }

            const rootNodes = [
                { dn: rootDn, icon: icons.adIcon },
                { dn: `CN=Configuration,${rootDn}`, icon: icons.adIcon },
                { dn: `CN=Schema,CN=Configuration,${rootDn}`, icon: icons.defaultIcon },
                { dn: `DC=DomainDnsZones,${rootDn}`, icon: icons.adIcon },
                { dn: `DC=ForestDnsZones,${rootDn}`, icon: icons.adIcon }
            ];

            for (const node of rootNodes) {
                const exists = await checkDistinguishedNameExists(node.dn);
                if (exists) {
                    const treeNode = createTreeNode(node.dn, node.icon);
                    if (node.dn === rootDn) {
                        // Mark the root node as selected
                        document.querySelectorAll('.selected').forEach(el => el.classList.remove('selected'));
                        treeNode.classList.add('selected');

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

    function resetToGeneralTab() {
        const generalTabButton = document.querySelector('button[aria-controls="tabpanelGeneral"]');
        const tabList = document.querySelector('[role="tablist"]');
        const tabPanels = document.querySelectorAll('[role="tabpanel"]');
    
        if (generalTabButton) {
            // Set the "General" tab as active
            tabList.querySelectorAll('[role="tab"]').forEach(tab => {
                if (tab === generalTabButton) {
                    tab.setAttribute('aria-selected', 'true');
                    tab.setAttribute('tabindex', '0');
                    tab.classList.add('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
                } else {
                    tab.setAttribute('aria-selected', 'false');
                    tab.setAttribute('tabindex', '-1');
                    tab.classList.remove('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
                    tab.classList.add('text-neutral-600', 'font-medium', 'dark:text-neutral-300', 'dark:hover:border-b-neutral-300', 'dark:hover:text-white', 'hover:border-b-2', 'hover:border-b-neutral-800', 'hover:text-neutral-900');
                }
            });
    
            // Show the "General" tab panel and hide others
            tabPanels.forEach(panel => {
                if (panel.id === 'tabpanelDacl') {
                    const daclRows = panel.querySelector('#dacl-rows');
                    if (daclRows) {
                        daclRows.innerHTML = '';
                    }
                }
                panel.style.display = panel.id === generalTabButton.getAttribute('aria-controls') ? 'block' : 'none';
            });
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

            // Show the spinner when a tree node is clicked
            // showLoadingIndicator();

            let subtreeContainer = div.nextElementSibling;
            if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
                subtreeContainer.remove();
                hideLoadingIndicator(); // Hide the spinner if subtree is removed
                return;
            }

            const itemData = await fetchItemData(dn, 'BASE');
            if (itemData) {
                populateResultsPanel(itemData);
                toggleSubtree(dn, div);
            }

            // Hide the spinner after processing
            // hideLoadingIndicator();
        });

        treeView.appendChild(div);
        return div; // Return the created tree node
    }

    
    async function toggleSubtree(searchbase, parentElement) {
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
                body: JSON.stringify({ searchbase: searchbase, search_scope: 'LEVEL' })
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

                const membersTab = document.querySelector('[aria-controls="tabpanelMembers"]');
                if (membersTab) {
                    if (obj.attributes.objectClass && obj.attributes.objectClass.includes('group')) {
                        membersTab.style.display = '';
                    } else {
                        membersTab.style.display = 'none';
                    }
                }

                // Show the spinner on the right side of the node
                showLoadingIndicator();
                let childSubtreeContainer = objDiv.nextElementSibling;
                if (childSubtreeContainer && childSubtreeContainer.classList.contains('subtree')) {
                    childSubtreeContainer.remove();
                    hideLoadingIndicator(); // Hide the spinner if subtree is removed
                    return;
                }

                const itemData = await fetchItemData(obj.dn, 'BASE');
                if (itemData) {
                    populateResultsPanel(itemData);
                    toggleSubtree(obj.dn, objDiv);
                }

                // Hide the spinner after processing
                hideLoadingIndicator();
            });

            subtreeContainer.appendChild(objDiv);
        });

        parentElement.insertAdjacentElement('afterend', subtreeContainer);
    }

    function populateResultsPanel(item) {
        const resultsPanel = document.getElementById("general-content");
        const attributes = item.attributes;
        
        // Store the current search query before clearing the content
        const searchInput = document.getElementById('tab-search');
        const currentSearchQuery = searchInput ? searchInput.value.toLowerCase() : '';

        // Create the header div
        const headerDiv = document.createElement('div');
        headerDiv.className = 'bg-white dark:bg-neutral-800 text-sm text-neutral-900 dark:text-white px-4 py-3 border-b border-neutral-200 dark:border-neutral-700 sticky top-0 z-10';
        
        const headerH3 = document.createElement('h3');
        headerH3.className = 'font-medium';
        headerH3.textContent = attributes.name || 'Details';
        headerDiv.appendChild(headerH3);

        // Create the content div
        const contentDiv = document.createElement('div');
        contentDiv.className = 'p-4 space-y-2';

        const dl = document.createElement('dl');
        dl.className = 'grid grid-cols-1 gap-3';

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
            dd.className = 'mt-1 text-sm text-neutral-900 dark:text-white w-2/3 break-all';

            if (isDistinguishedName) {
                if (Array.isArray(value)) {
                    value.forEach(v => {
                        const link = document.createElement('a');
                        link.href = '#';
                        link.className = 'text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300';
                        link.dataset.identity = v;
                        link.onclick = (event) => handleLdapLinkClick(event, v);
                        link.textContent = v;
                        dd.appendChild(link);
                        dd.appendChild(document.createElement('br'));
                    });
                } else {
                    const link = document.createElement('a');
                    link.href = '#';
                    link.className = 'text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300';
                    link.dataset.identity = value;
                    link.onclick = (event) => handleLdapLinkClick(event, value);
                    link.textContent = value;
                    dd.appendChild(link);
                }
            } else {
                if (Array.isArray(value)) {
                    dd.innerHTML = value.map(v => isByteData(v) ? convertToBase64(v) : v).join('<br>');
                } else {
                    dd.innerHTML = isByteData(value) ? convertToBase64(value) : value;
                }
            }

            flexDiv.appendChild(dd);
            dl.appendChild(flexDiv);
        }

        contentDiv.appendChild(dl);

        // Clear previous content and append new elements
        resultsPanel.innerHTML = '';
        resultsPanel.appendChild(headerDiv);
        resultsPanel.appendChild(contentDiv);
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

            // Check if the clicked tab is the DACL tab
            if (clickedTab.getAttribute('aria-controls') === 'tabpanelDacl') {
                const selectedIdentity = getSelectedIdentity();
                if (selectedIdentity) {
                    fetchAndDisplayDacl(selectedIdentity);
                }
            }

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

    // Call this function after the DOM is fully loaded
    initialize();
    setupTabEventDelegation();
});