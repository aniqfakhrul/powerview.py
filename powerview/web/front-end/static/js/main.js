async function executePowerViewCommand(ldapFilter) {
    const commandInput = document.getElementById('ldap-filter');
    if (!commandInput) return;

    const command = commandInput.value.trim();
    if (!command) {
        alert('Please enter a PowerView command.');
        return;
    }

    try {
        const response = await fetch('/api/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ command: command })
        });

        const result = await response.json();

        await handleHttpError(response);

        console.log('Command execution result:', result);

        // Unhide the tableview and populate the table
        const tableView = document.getElementById('tableview');
        const contentArea = document.getElementById('content-area');
        if (tableView) {
            tableView.removeAttribute('hidden');
            contentArea.setAttribute('hidden', true);
        }
        populateTableView(result.result, tableView); // Assuming result.users contains the user data
    } catch (error) {
        console.error('Error executing command:', error);
        alert('Failed to execute command. Please check the console for more details.');
    }
}

async function fetchItemData(identity, search_scope = 'LEVEL') {
    // showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ searchbase: identity, properties: ['*'], search_scope: search_scope })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data[0];
    } catch (error) {
        console.error('Error fetching item data:', error);
        return null;
    } finally {
        // hideLoadingIndicator();
    }
}

function showLoadingIndicator() {
    const boxOverlaySpinner = document.getElementById('box-overlay-spinner');
    boxOverlaySpinner.classList.remove('hidden'); // Show the spinner
}

function showInitLoadingIndicator() {
    const boxOverlaySpinner = document.getElementById('box-overlay-spinner-init');
    boxOverlaySpinner.classList.remove('hidden'); // Show the spinner
}

function hideLoadingIndicator() {
    const boxOverlaySpinner = document.getElementById('box-overlay-spinner');
    boxOverlaySpinner.classList.add('hidden'); // Hide the spinner
}

function hideInitLoadingIndicator() {
    const boxOverlaySpinner = document.getElementById('box-overlay-spinner-init');
    boxOverlaySpinner.classList.add('hidden'); // Hide the spinner
}

function isValidDistinguishedName(value) {
    const dnPattern = /^(CN|OU|DC)=/i; // Simple pattern to identify a DN
    return dnPattern.test(value);
}

function parseGPOLink(gPLink) {
    // Check if gPLink is an array and use the first element, or use the string directly
    const gpLinkStr = Array.isArray(gPLink) ? gPLink[0] : gPLink;
    
    if (!gpLinkStr) return null;

    const gpoLinks = [];
    
    // Regular expression to match GUIDs (36 characters)
    const guidRegex = /[a-zA-Z0-9-]{36}/g;
    const guids = [...gpLinkStr.matchAll(guidRegex)].map(match => match[0]);
    
    // Regular expression to match enforcement status
    const statusRegex = /[;][0-4]{1}/g;
    const statuses = [...gpLinkStr.matchAll(statusRegex)].map(match => match[0]);
    
    // Create array of GPO objects with GUID and enforcement status
    for (let i = 0; i < guids.length; i++) {
        gpoLinks.push({
            GUID: guids[i],
            IsEnforced: statuses[i] === ';2' || statuses[i] === ';3'
        });
    }
    
    return gpoLinks.length > 0 ? gpoLinks : null;
}

// Helper function to detect byte data
function isByteData(value) {
    return typeof value === 'string' && 
           value.includes('\u0000') && 
           value.includes('\u0001') &&
           value.length > 10;
}

// Helper function to create DN link
function createDnLink(value) {
    const link = document.createElement('a');
    link.href = '#';
    link.className = 'text-blue-400 hover:text-blue-600 block';
    link.dataset.identity = value;
    link.onclick = (event) => handleLdapLinkClick(event, value);
    link.textContent = value;
    return link;
}

function escapeSelector(selector) {
    return selector.replace(/([!"#$%&'()*+,.\/:;<=>?@[\\\]^`{|}~])/g, '\\$1');
}

function convertDnToId(distinguishedName) {
    // Replace commas and equal signs with underscores
    return distinguishedName.replace(/[,=]/g, '_');
}

function convertToBase64(inputString) {
    try {
        return btoa(encodeURIComponent(inputString).replace(/%([0-9A-F]{2})/g,
            function (match, p1) {
                return String.fromCharCode('0x' + p1);
            }));
    } catch (error) {
        console.error('Error converting to Base64:', error);
        return null;
    }
}


function stripCurlyBrackets(guid) {
    return guid.replace(/[{}]/g, '');
}

async function getDomainInfo() {
    try {
        const response = await fetch('/api/get/domaininfo', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        await handleHttpError(response);

        const domainInfo = await response.json();
        return domainInfo;
    } catch (error) {
        console.error('Error fetching domain info:', error);
    }
}

async function handleObjectClick(event, identity) {
    event.preventDefault();
    
    try {
        showLoadingIndicator();
        
        const response = await fetch('/api/get/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                identity: identity, 
                properties: ['*'],
                search_scope: 'BASE' 
            })
        });

        await handleHttpError(response);
        
        const data = await response.json();
        
        if (data && data.length > 0) {
            const attributes = data[0].attributes;
            showLdapAttributesModal(attributes, identity);
        } else {
            showErrorAlert(`No data found for ${identity}`);
        }
    } catch (error) {
        console.error('Error fetching LDAP attributes:', error);
        showErrorAlert('Failed to fetch LDAP attributes');
    } finally {
        hideLoadingIndicator();
    }
}

async function handleLdapLinkClick(event, identity) {
    event.preventDefault();
    
    try {
        showLoadingIndicator();
        
        const response = await fetch('/api/get/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                searchbase: identity, 
                properties: ['*'],
                search_scope: 'BASE' 
            })
        });

        await handleHttpError(response);
        
        const data = await response.json();
        
        if (data && data.length > 0) {
            const attributes = data[0].attributes;
            showLdapAttributesModal(attributes, identity);
        } else {
            showErrorAlert(`No data found for ${identity}`);
        }
    } catch (error) {
        console.error('Error fetching LDAP attributes:', error);
        showErrorAlert('Failed to fetch LDAP attributes');
    } finally {
        hideLoadingIndicator();
    }
}

function populateDetailsPanel(item) {
    const detailsPanel = document.getElementById("details-panel");
    detailsPanel.innerHTML = ''; // Clear existing content

    // Create header
    const headerDiv = document.createElement('div');
    headerDiv.className = 'flex items-center justify-between gap-2 p-4 border-b sticky top-0 bg-white z-10';

    const headerContentDiv = document.createElement('div');
    headerContentDiv.className = 'flex items-center gap-2';

    const svgIcon = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svgIcon.setAttribute('class', 'w-5 h-5 text-blue-500');
    svgIcon.setAttribute('fill', 'none');
    svgIcon.setAttribute('stroke', 'currentColor');
    svgIcon.setAttribute('viewBox', '0 0 24 24');
    svgIcon.innerHTML = '<path d="M12 8v4l3 3"></path><circle cx="12" cy="12" r="10"></circle>';

    const headerTitle = document.createElement('h2');
    headerTitle.className = 'text-lg font-semibold';
    headerTitle.textContent = item.attributes.name;

    headerContentDiv.appendChild(svgIcon);
    headerContentDiv.appendChild(headerTitle);
    headerDiv.appendChild(headerContentDiv);

    const closeButton = document.createElement('button');
    closeButton.id = 'close-details-panel';
    closeButton.className = 'text-gray-500 hover:text-gray-700';
    closeButton.innerHTML = '<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path></svg>';
    closeButton.addEventListener('click', () => {
        detailsPanel.classList.add('hidden');
    });

    headerDiv.appendChild(closeButton);
    detailsPanel.appendChild(headerDiv);

    // Create content
    const contentDiv = document.createElement('div');
    contentDiv.className = 'divide-y';

    const attributesDiv = document.createElement('div');
    attributesDiv.className = 'p-4';

    const attributes = item.attributes;
    for (const [key, value] of Object.entries(attributes)) {
        const attributeDiv = document.createElement('div');
        attributeDiv.className = 'mb-4';

        const keySpan = document.createElement('span');
        keySpan.className = 'text-sm font-medium text-gray-500 block';
        keySpan.textContent = key;

        attributeDiv.appendChild(keySpan);

        if (Array.isArray(value)) {
            value.forEach(val => {
                const valueSpan = document.createElement('span');
                valueSpan.className = 'text-sm text-gray-900 block';
                valueSpan.textContent = val;
                attributeDiv.appendChild(valueSpan);
            });
        } else {
            const valueSpan = document.createElement('span');
            valueSpan.className = 'text-sm text-gray-900 block';
            valueSpan.textContent = value;
            attributeDiv.appendChild(valueSpan);
        }

        attributesDiv.appendChild(attributeDiv);
    }

    contentDiv.appendChild(attributesDiv);
    detailsPanel.appendChild(contentDiv);

    detailsPanel.classList.remove('hidden'); // Ensure the details panel is visible
}

function populateTableView(entries, tableView) {
    const thead = tableView.querySelector('thead');
    const tbody = tableView.querySelector('tbody');
    tbody.innerHTML = '';
    if (entries.length > 0) {
        // Get attribute keys from the first user to create table headers
        const attributeKeys = Object.keys(entries[0].attributes);

        // Create table headers
        thead.innerHTML = ''; // Clear existing headers
        const headerRow = document.createElement('tr');
        attributeKeys.forEach(key => {
            const th = document.createElement('th');
            th.scope = 'col';
            th.className = 'p-2';
            th.textContent = key;
            headerRow.appendChild(th);
        });

        // Add an extra header for actions
        const actionTh = document.createElement('th');
        actionTh.scope = 'col';
        actionTh.className = 'p-2';
        actionTh.textContent = 'Action';
        headerRow.appendChild(actionTh);

        thead.appendChild(headerRow);

        // Populate table rows
        entries.forEach(entry => {
            const tr = document.createElement('tr');
            tr.classList.add('ldap-link', 'hover:bg-gray-100');
            tr.dataset.identity = entry.dn;
            tr.onclick = (event) => handleLdapLinkClick(event);

            attributeKeys.forEach(key => {
                const td = document.createElement('td');
                td.className = 'p-2 whitespace-nowrap';
                const value = entry.attributes[key];
                if (key === 'adminCount') {
                    const statusTd = document.createElement('td');
                    statusTd.className = 'p-2 whitespace-nowrap';
                    const statusSpan = document.createElement('span');
                    if (value === 1) {
                        statusSpan.className = 'px-1 inline-flex text-xs leading-4 font-semibold rounded-md bg-green-100 text-green-800';
                        statusSpan.textContent = 'True';
                    } else {
                        statusSpan.textContent = '';
                    }
                    statusTd.appendChild(statusSpan);
                    tr.appendChild(statusTd);
                } else {
                    if (Array.isArray(value)) {
                        td.innerHTML = value.join('<br>');
                    } else {
                        td.textContent = value;
                    }
                    tr.appendChild(td);
                }
            });

            // Add action buttons
            const actionTd = document.createElement('td');
            actionTd.className = 'p-2 whitespace-nowrap';
            const editButton = document.createElement('button');
            editButton.className = 'px-1 py-0.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-500 focus:outline-none focus:shadow-outline-blue active:bg-blue-600 transition duration-150 ease-in-out';
            editButton.textContent = 'Edit';
            actionTd.appendChild(editButton);

            const deleteButton = document.createElement('button');
            deleteButton.className = 'ml-1 px-1 py-0.5 text-xs font-medium text-white bg-red-600 rounded-md hover:bg-red-500 focus:outline-none focus:shadow-outline-red active:bg-red-600 transition duration-150 ease-in-out';
            deleteButton.textContent = 'Delete';
            deleteButton.addEventListener('click', (event) => {
                event.stopPropagation();
                showDeleteModal(entry.attributes.cn, tr);
            });
            actionTd.appendChild(deleteButton);

            tr.appendChild(actionTd);

            tbody.appendChild(tr);
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    const footerYear = document.querySelector('#footer-year');
    if (footerYear) {
        footerYear.textContent = currentYear();
    }

    // Initialize alert handlers
    function initializeAlertHandlers() {
        // Handle all alert close buttons
        document.querySelectorAll('[data-dismiss-target]').forEach(button => {
            button.addEventListener('click', () => {
                const targetId = button.getAttribute('data-dismiss-target');
                const alert = document.querySelector(targetId);
                if (alert) {
                    alert.classList.add('hidden');
                }
            });
        });

        // Handle clicking outside alerts (optional)
        document.addEventListener('click', (event) => {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                if (alert.contains(event.target)) return;
                if (!alert.classList.contains('hidden')) {
                    alert.classList.add('hidden');
                }
            });
        });
    }

    // Add to initialization
    initializeAlertHandlers();
    checkConnectionStatus();
    setInterval(checkConnectionStatus, 300000);

    function currentYear() {
        return new Date().getFullYear();
    }

    async function fetchGroupMembers(groupName) {
        try {
            const response = await fetch('/api/get/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identity: groupName })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            return data;
        } catch (error) {
            console.error('Error fetching group members:', error);
            return null;
        }
    }

    async function checkConnectionStatus() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // Set timeout to 5 seconds

        try {
            const response = await fetch('/api/connectioninfo', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                signal: controller.signal
            });

            const profileMenu = document.getElementById('profile-menu');
            const statusElement = profileMenu.querySelector('#connection-status-display');
            const addressElement = profileMenu.querySelector('#connection-address-display');
            const nameserverElement = profileMenu.querySelector('#nameserver-address-display');
            const domainElement = profileMenu.querySelector('#connection-domain-display');
            const usernameElement = profileMenu.querySelector('#username-display');

            if (response.ok) {
                const data = await response.json();
                usernameElement.textContent = `${data.username}@${data.domain}`;
                addressElement.textContent = `${data.protocol}://${data.ldap_address}`;
                nameserverElement.textContent = `NS: ${data.nameserver}`;
                if (data.status === 'OK') {
                    statusElement.textContent = 'Connected';
                    statusElement.classList.remove('text-red-400');
                    statusElement.classList.add('text-green-400');
                } else {
                    statusElement.textContent = 'Disconnected';
                    statusElement.classList.remove('text-green-400');
                    statusElement.classList.add('text-red-400');
                }
            } else {
                throw new Error('Failed to fetch status');
            }
        } catch (error) {
            const profileMenu = document.getElementById('profile-menu');
            if (profileMenu) {
                const statusElement = profileMenu.querySelector('#connection-status-display');
                if (statusElement) {
                    statusElement.textContent = 'Disconnected';
                    statusElement.classList.remove('text-green-400');
                    statusElement.classList.add('text-red-400');
                }
            }
            console.error('Error checking connection status:', error);
        } finally {
            clearTimeout(timeoutId);
        }
    }

    initializeDisconnectButton();
    initializeClearCacheButton();
});

function createAttributeEntry(name, value, identity) {
    const wrapper = document.createElement('div');
    wrapper.className = 'flex flex-col space-y-2';
    wrapper.id = `${name}-wrapper`;

    const labelDiv = document.createElement('div');
    labelDiv.className = 'flex justify-between items-center';

    const label = document.createElement('label');
    label.className = 'block text-sm font-medium text-gray-900 dark:text-white';
    label.textContent = name;

    labelDiv.appendChild(label);

    const inputsContainer = document.createElement('div');
    inputsContainer.className = 'flex flex-col gap-2';

    const mainInputWrapper = document.createElement('div');
    mainInputWrapper.className = 'relative flex gap-2';

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'rounded-md border border-neutral-300 bg-neutral-50 px-2 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:cursor-not-allowed disabled:opacity-75 dark:border-neutral-700 dark:bg-neutral-900/50 dark:focus-visible:outline-yellow-500 w-full whitespace-pre pr-24';
    
    // Convert array to newline-separated string if needed
    if (Array.isArray(value)) {
        input.value = value.join('\n');
    } else {
        input.value = value;
    }
    input.disabled = true;

    // Create buttons container inside input
    const buttonsDiv = document.createElement('div');
    buttonsDiv.className = 'absolute right-2 top-1/2 -translate-y-1/2 flex gap-3 items-center';

    const editButton = document.createElement('button');
    editButton.type = 'button';
    editButton.className = 'text-blue-600 hover:text-blue-700';
    editButton.innerHTML = '<i class="fas fa-edit fa-xs"></i>';

    const addButton = document.createElement('button');
    addButton.type = 'button';
    addButton.className = 'text-green-600 hover:text-green-700';
    addButton.innerHTML = '<i class="fas fa-plus fa-xs"></i>';

    const deleteButton = document.createElement('button');
    deleteButton.type = 'button';
    deleteButton.className = 'text-red-600 hover:text-red-700';
    deleteButton.innerHTML = icons.deleteIcon;

    buttonsDiv.appendChild(editButton);
    buttonsDiv.appendChild(addButton);
    buttonsDiv.appendChild(deleteButton);

    mainInputWrapper.appendChild(input);
    mainInputWrapper.appendChild(buttonsDiv);
    inputsContainer.appendChild(mainInputWrapper);
    
    wrapper.appendChild(labelDiv);
    wrapper.appendChild(inputsContainer);

    // Edit button click handler with visibility toggle
    editButton.addEventListener('click', async () => {
        const isEditing = input.disabled;
        
        if (isEditing) {
            // Switching to edit mode
            input.disabled = false;
            editButton.innerHTML = '<i class="fas fa-save fa-xs"></i>'; // Change to save icon
            
            // Hide add and delete buttons
            addButton.style.display = 'none';
            deleteButton.style.display = 'none';
            
            // Create and add cancel button
            const cancelButton = document.createElement('button');
            cancelButton.type = 'button';
            cancelButton.className = 'text-gray-600 hover:text-gray-700';
            cancelButton.innerHTML = '<i class="fas fa-times fa-xs"></i>';
            
            editButton.insertAdjacentElement('afterend', cancelButton);
            
            cancelButton.addEventListener('click', () => {
                input.value = originalValue;
                input.disabled = true;
                editButton.innerHTML = '<i class="fas fa-edit fa-xs"></i>';
                // Show add and delete buttons again
                addButton.style.display = '';
                deleteButton.style.display = '';
                cancelButton.remove();
            });

            input.focus();
        } else {
            // Attempting to save
            const newValue = input.value;
            if (newValue !== originalValue) {
                let success;
                
                // Special handling for distinguishedName
                if (name.toLowerCase() === 'distinguishedname') {
                    success = await updateDistinguishedName(identity, newValue);
                } else {
                    success = await updateLdapAttribute(identity, name, newValue);
                }

                if (success) {
                    input.disabled = true;
                    editButton.innerHTML = '<i class="fas fa-edit fa-xs"></i>';
                    // Show add and delete buttons again
                    addButton.style.display = '';
                    deleteButton.style.display = '';
                    // Remove cancel button
                    const cancelButton = editButton.nextElementSibling;
                    if (cancelButton && cancelButton.innerHTML.includes('fa-times')) {
                        cancelButton.remove();
                    }
                    showSuccessAlert(`Successfully updated attribute: ${name}`);
                }
            } else {
                // No changes made, just switch back to view mode
                input.disabled = true;
                editButton.innerHTML = '<i class="fas fa-edit fa-xs"></i>';
                // Show add and delete buttons again
                addButton.style.display = '';
                deleteButton.style.display = '';
                // Remove cancel button
                const cancelButton = editButton.nextElementSibling;
                if (cancelButton && cancelButton.innerHTML.includes('fa-times')) {
                    cancelButton.remove();
                }
            }
        }
    });

    // Add button click handler
    addButton.addEventListener('click', () => {
        const appendWrapper = document.createElement('div');
        appendWrapper.className = 'flex gap-2';

        const appendInput = document.createElement('input');
        appendInput.type = 'text';
        appendInput.className = 'rounded-md border border-neutral-300 bg-neutral-50 px-2 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black disabled:cursor-not-allowed disabled:opacity-75 dark:border-neutral-700 dark:bg-neutral-900/50 dark:focus-visible:outline-yellow-500 w-full whitespace-pre';
        appendInput.placeholder = 'Enter value to append';

        const saveButton = document.createElement('button');
        saveButton.type = 'button';
        saveButton.className = 'px-3 py-2 bg-green-600 text-white text-sm font-medium rounded-lg hover:bg-green-700';
        saveButton.textContent = 'Save';

        const cancelButton = document.createElement('button');
        cancelButton.type = 'button';
        cancelButton.className = 'px-3 py-2 bg-gray-400 text-white text-sm font-medium rounded-lg hover:bg-gray-500';
        cancelButton.textContent = 'Cancel';

        saveButton.addEventListener('click', async () => {
            const newValue = appendInput.value.trim();
            if (!newValue) {
                showErrorAlert('Please enter a value to append');
                return;
            }

            try {
                showLoadingIndicator();
                const response = await fetch('/api/set/domainobject', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        identity: identity,
                        append: `${name}=${newValue}`
                    })
                });

                await handleHttpError(response);

                if (response.ok) {
                    // Update the main input value to include the new value
                    const currentValue = input.value;
                    input.value = currentValue ? `${currentValue}\n${newValue}` : newValue;
                    appendWrapper.remove();
                    showSuccessAlert(`Successfully appended value to ${name}`);
                }
            } catch (error) {
                console.error('Error appending value:', error);
                showErrorAlert(`Failed to append value to ${name}`);
            } finally {
                hideLoadingIndicator();
            }
        });

        cancelButton.addEventListener('click', () => {
            appendWrapper.remove();
        });

        appendWrapper.appendChild(appendInput);
        appendWrapper.appendChild(saveButton);
        appendWrapper.appendChild(cancelButton);
        inputsContainer.appendChild(appendWrapper);
        appendInput.focus();
    });

    // Store the original value for reset
    const originalValue = Array.isArray(value) ? value.join('\n') : value;

    // Existing delete functionality
    deleteButton.addEventListener('click', async () => {
        if (confirm(`Are you sure you want to delete the attribute "${name}"?`)) {
            const success = await deleteLdapAttribute(identity, name);
            if (success) {
                wrapper.remove(); // Remove the attribute entry from the DOM
            }
        }
    });

    return wrapper;
}

// Add this new function to handle attribute deletion
async function deleteLdapAttribute(identity, attributeName) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/set/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identity: identity,
                clear: attributeName
            })
        });

        await handleHttpError(response);
        
        if (response.ok) {
            console.log(`Successfully deleted ${attributeName}`);
            return true;
        }
    } catch (error) {
        console.error('Error deleting LDAP attribute:', error);
        showErrorAlert(`Failed to delete ${attributeName}`);
        return false;
    } finally {
        hideLoadingIndicator();
    }
    return false;
}

function populateLdapAttributesModal(attributes, identity) {
    const container = document.getElementById('existing-attributes');
    container.className = 'grid grid-cols-1 md:grid-cols-2 gap-4 auto-rows-auto';

    // Sort attributes alphabetically
    const sortedAttributes = Object.entries(attributes).sort((a, b) => 
        a[0].toLowerCase().localeCompare(b[0].toLowerCase())
    );

    sortedAttributes.forEach(([name, value]) => {
        const attributeEntry = createAttributeEntry(name, value, identity);
        // Add classes to make long content span full width
        if (value && value.length > 100) {  // Adjust threshold as needed
            attributeEntry.className = 'col-span-full flex flex-col space-y-2';
        } else {
            attributeEntry.className = 'flex flex-col space-y-2';
        }
        container.appendChild(attributeEntry);
    });
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    const overlay = document.getElementById('modal-overlay');
    
    if (modal) {
        modal.classList.add('hidden');
        // Remove event listeners when closing
        const closeButton = modal.querySelector(`[data-modal-hide="${modalId}"]`);
        if (closeButton) {
            closeButton.removeEventListener('click', () => closeModal(modalId));
        }
        document.removeEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                closeModal(modalId);
            }
        });
    }
    if (overlay) {
        overlay.classList.add('hidden');
    }
}

// Add this function to handle filtering
function handleModalSearch() {
    const searchInput = document.getElementById('modal-tab-search');
    const clearButton = searchInput.nextElementSibling;

    function filterContent() {
        const searchTerm = searchInput.value.toLowerCase();
        // Find the active tab by checking which tab panel is currently visible
        const activeTabPanel = document.querySelector('#ldap-attributes-modal [role="tabpanel"]:not([style*="display: none"])');
        const activeTabId = activeTabPanel?.id;

        if (!activeTabId) return;

        switch (activeTabId) {
            case 'tabpanelInfo':
                // Filter attributes
                const attributes = document.querySelectorAll('#existing-attributes > div');
                attributes.forEach(attr => {
                    const label = attr.querySelector('label')?.textContent.toLowerCase() || '';
                    const value = attr.querySelector('input')?.value.toLowerCase() || '';
                    const matches = label.includes(searchTerm) || value.includes(searchTerm);
                    attr.style.display = matches ? '' : 'none';
                });
                break;

            case 'tabpanelDescendants':
                // Filter descendants table rows without affecting the header
                const rows = document.querySelectorAll('#descendants-rows tr');
                rows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
                break;

            case 'tabpanelDacl':
                // Filter DACL table rows without affecting the header
                const daclRows = document.querySelectorAll('#modal-dacl-rows tr');
                daclRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
                break;

            case 'tabpanelLoggedon':
                // Filter logon users table rows
                const logonRows = document.querySelectorAll('#logonusers-rows tr');
                logonRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
                break;

            case 'tabpanelSessions':
                // Filter sessions table rows
                const sessionRows = document.querySelectorAll('#sessions-rows tr');
                sessionRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
                break;

            case 'tabpanelMembers':
                // Filter members table rows
                const memberRows = document.querySelectorAll('#modal-members-content tr');
                memberRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
                break;
        }
    }

    // Add event listeners
    searchInput.addEventListener('input', filterContent);
    
    // Clear button functionality
    clearButton.addEventListener('click', () => {
        searchInput.value = '';
        filterContent();
    });

    // Clear search when switching tabs
    const tabButtons = document.querySelectorAll('#ldap-attributes-modal [role="tab"]');
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            searchInput.value = '';
            filterContent();
        });
    });
}

// Update showLdapAttributesModal to initialize the search functionality
async function showLdapAttributesModal(attributes = {}, identity) {
    const modal = document.getElementById('ldap-attributes-modal');
    const overlay = document.getElementById('modal-overlay');
    const container = document.getElementById('existing-attributes');
    const spinner = modal.querySelector('#box-overlay-spinner');
    
    if (modal && overlay) {
        container.innerHTML = '';

        // Update modal title to show identity
        const modalTitle = modal.querySelector('h3');
        if (modalTitle) {
            modalTitle.textContent = identity;
        }

        const isGroup = attributes.objectClass && 
            Array.isArray(attributes.objectClass) && 
            attributes.objectClass.includes('group');
        // Show/hide Members tab based on objectClass
        const membersTab = modal.querySelector('[aria-controls="tabpanelMembers"]');
        if (membersTab) {
            membersTab.style.display = isGroup ? '' : 'none';
        }

        // Show/hide Member Of tab based on memberOf attribute
        const memberOfTab = modal.querySelector('[aria-controls="tabpanelMemberof"]');
        if (memberOfTab) {
            // Handle both array and string cases for memberOf
            const hasMemberOf = attributes.memberOf && 
                (Array.isArray(attributes.memberOf) ? attributes.memberOf.length > 0 : true);
            memberOfTab.style.display = hasMemberOf ? '' : 'none';
            
            if (hasMemberOf) {
                // Convert single string to array if needed
                const memberOfArray = Array.isArray(attributes.memberOf) ? 
                    attributes.memberOf : [attributes.memberOf];
                // Initialize the Member Of tab content
                displayModalMemberOf(memberOfArray);
            }
        }

        const isComputer = attributes.objectClass && 
                          Array.isArray(attributes.objectClass) && 
                          attributes.objectClass.includes('computer');
        // Show/hide Sessions and Logon Users tabs based on objectClass
        const sessionsTab = modal.querySelector('[aria-controls="tabpanelSessions"]');
        const loggedonTab = modal.querySelector('[aria-controls="tabpanelLoggedon"]');
        if (sessionsTab && loggedonTab) {
            sessionsTab.style.display = isComputer ? '' : 'none';
            loggedonTab.style.display = isComputer ? '' : 'none';
        }

        // Show the modal and overlay
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
        spinner.classList.remove('hidden');

        // Add event listener to close the modal
        const closeButton = modal.querySelector('[data-modal-hide="ldap-attributes-modal"]');
        if (closeButton) {
            closeButton.addEventListener('click', () => closeModal('ldap-attributes-modal'));
        }

        // Add event listener for Escape key
        const handleEscape = (e) => {
            if (e.key === 'Escape') {
                closeModal('ldap-attributes-modal');
            }
        };
        document.addEventListener('keydown', handleEscape);
        
        try {
            // Populate the modal with existing attributes
            await populateLdapAttributesModal(attributes, identity);

            // Initialize the add new attribute functionality
            handleAddNewAttribute(identity);

            // Initialize tabs
            selectModalTab('info');

            // Initialize search functionality
            handleModalSearch();
        } finally {
            spinner.classList.add('hidden');
        }
    }
}

// Add this new function to handle the API call
async function updateLdapAttribute(identity, attributeName, newValue) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/set/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identity: identity,
                _set: `${attributeName}=${newValue}`
            })
        });

        await handleHttpError(response);
        
        if (response.ok) {
            console.log(`Successfully updated ${attributeName}`);
            return true;
        }
    } catch (error) {
        console.error('Error updating LDAP attribute:', error);
        showErrorAlert(`Failed to update ${attributeName}`);
        return false;
    } finally {
        hideLoadingIndicator();
    }
    return false;
}

// Add this function to handle the new attribute addition
function handleAddNewAttribute(identity) {
    const addButton = document.getElementById('add-new-attribute');
    const nameInput = document.getElementById('new-attribute-name');
    const valueInput = document.getElementById('new-attribute-value');

    addButton.addEventListener('click', async () => {
        const attributeName = nameInput.value.trim();
        const attributeValue = valueInput.value.trim();

        if (!attributeName || !attributeValue) {
            showErrorAlert('Both attribute name and value are required');
            return;
        }
        const success = await updateLdapAttribute(identity, attributeName, attributeValue);
        
        if (success) {
            // Create and add the new attribute entry to the existing list
            const newEntry = createAttributeEntry(attributeName, attributeValue, identity);
            document.getElementById('existing-attributes').appendChild(newEntry);
            
            // Clear the input fields
            nameInput.value = '';
            valueInput.value = '';
            
            // Show success message
            showSuccessAlert(`Successfully added attribute: ${attributeName}`);
        }
    });
}

// Add a success alert function if you don't have one
function showSuccessAlert(message) {
    // Implementation depends on your alert system
    console.log('Success:', message);
    // Example: You might want to show a toast notification or some other UI feedback
}

async function fetchConstants(constantType) {
    try {
        showLoadingIndicator();
        const response = await fetch(`/api/constants?get=${constantType}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        await handleHttpError(response);

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error(`Error fetching ${constantType} constants:`, error);
        showErrorAlert(`Failed to fetch ${constantType} constants`);
        return null;
    } finally {
        hideLoadingIndicator();
    }
}

// Add this function to handle modal tab switching
async function selectModalTab(tabName) {
    // Update tab buttons
    const tabButtons = document.querySelectorAll('#ldap-attributes-modal [role="tab"]');
    tabButtons.forEach(button => {
        const isSelected = button.getAttribute('aria-controls') === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}`;
        button.setAttribute('aria-selected', isSelected);
        button.setAttribute('tabindex', isSelected ? '0' : '-1');
        button.className = isSelected
            ? 'h-min px-4 py-2 text-sm font-bold text-black border-b-2 border-black dark:border-yellow-500 dark:text-yellow-500'
            : 'h-min px-4 py-2 text-sm text-neutral-600 font-medium dark:text-neutral-300 dark:hover:border-b-neutral-300 dark:hover:text-white hover:border-b-2 hover:border-b-neutral-800 hover:text-neutral-900';
    });

    // Update tab panels
    const tabPanels = document.querySelectorAll('#ldap-attributes-modal [role="tabpanel"]');
    tabPanels.forEach(panel => {
        panel.style.display = panel.id === `tabpanel${tabName.charAt(0).toUpperCase() + tabName.slice(1)}` ? 'block' : 'none';
    });

    const ldapAttributeModal = document.getElementById('ldap-attributes-modal');
    if (!ldapAttributeModal) return;

    try {
        // Load specific tab content
        switch (tabName) {
            case 'descendants':
                await loadDescendants();
                break;
                
            case 'dacl':
                const daclTabContent = document.getElementById('modal-dacl-rows');
                daclTabContent.innerHTML = '';

                const daclIdentity = ldapAttributeModal.querySelector('h3')?.textContent;
                if (daclIdentity) {
                    await fetchAndDisplayModalDacl(daclIdentity);
                    updateDaclTabContent();
                }
                break;
                
            case 'members':
                const memberIdentity = ldapAttributeModal.querySelector('h3')?.textContent;
                if (memberIdentity) {
                    await fetchAndDisplayModalMembers(memberIdentity);
                }
                break;
                
            case 'sessions':
                const dnsHostnameSessionsInput = ldapAttributeModal.querySelector('#dNSHostName-wrapper input');
                const dnsHostnameSessions = dnsHostnameSessionsInput?.value;
                if (dnsHostnameSessions) {
                    await fetchAndDisplayModalSessions(dnsHostnameSessions);
                } else {
                    showErrorAlert('DNS Hostname not found for this computer');
                }
                break;
                
            case 'loggedon':
                const dnsHostnameLogonUsersInput = ldapAttributeModal.querySelector('#dNSHostName-wrapper input');
                const dnsHostnameLogonUsers = dnsHostnameLogonUsersInput?.value;
                if (dnsHostnameLogonUsers) {
                    await fetchAndDisplayModalLogonUsers(dnsHostnameLogonUsers);
                } else {
                    showErrorAlert('DNS Hostname not found for this computer');
                }
                break;
        }
    } catch (error) {
        console.error(`Error loading ${tabName} tab content:`, error);
        showErrorAlert(`Failed to load ${tabName} tab content`);
        showModalTab('info');
    }
}

async function fetchAndDisplayModalDacl(identity) {
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
        updateModalDaclContent(daclData);
    } catch (error) {
        console.error('Error fetching DACL data:', error);
        showErrorAlert('Failed to fetch DACL data');
    } finally {
        hideLoadingIndicator();
    }
}

function updateModalDaclContent(daclData) {
    const daclRows = document.getElementById('modal-dacl-rows');
    if (!daclRows) return;

    daclRows.innerHTML = '';

    if (!daclData || !Array.isArray(daclData)) return;

    daclData.forEach(entry => {
        if (!entry.attributes) return;

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

            const aceType = attribute.ACEType?.includes('ALLOWED') ? icons.onIcon : icons.offIcon;
            const formattedAccessMask = attribute.AccessMask ? 
                attribute.AccessMask.split(',')
                    .map(mask => mask.trim())
                    .join('<br>') 
                : '';
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

function getObjectClassIcon(objectClasses) {
    // Ensure objectClasses is an array and convert to lowercase for comparison
    const classes = Array.isArray(objectClasses) 
        ? objectClasses.map(c => c.toLowerCase())
        : [objectClasses?.toLowerCase()].filter(Boolean);

    let icon = icons.defaultIcon; // Default icon

    if (classes.includes('group')) {
        icon = icons.groupIcon;
    } else if (classes.includes('container')) {
        icon = icons.containerIcon;
    } else if (classes.includes('computer')) {
        icon = icons.computerIcon;
    } else if (classes.includes('user')) {
        icon = icons.userIcon;
    } else if (classes.includes('organizationalunit')) {
        icon = icons.ouIcon;
    } else if (classes.includes('builtindomain')) {
        icon = icons.builtinIcon;
    }

    // Check for adminCount attribute if needed
    // Note: You'll need to modify this if you want to check adminCount
    // as it's not part of the objectClass array
    
    return icon;
}

async function fetchItemsData(identity, search_scope = 'SUBTREE', properties = ['name', 'objectClass', 'distinguishedName']) {
    try {
        // showLoadingIndicator();
        const response = await fetch('/api/get/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                searchbase: identity, 
                properties: properties, 
                search_scope: search_scope 
            })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        return data;
    } catch (error) {
        console.error('Error fetching items data:', error);
        return null;
    } finally {
        // hideLoadingIndicator();
    }
}

// Add these functions to handle property filtering
function initializePropertyFilter() {
    const selectedProperties = ['name', 'distinguishedName'];
    const container = document.getElementById('selected-properties');
    const newPropertyInput = document.getElementById('new-property');
    const searchButton = document.getElementById('search-filter');

    function renderProperties() {
        container.innerHTML = selectedProperties.map(prop => `
            <span class="px-2 py-1 bg-neutral-100 dark:bg-neutral-800 rounded-md text-sm flex items-center gap-1">
                ${prop}
                <button class="hover:text-red-500" onclick="removeProperty('${prop}')">
                    <i class="fas fa-times fa-xs"></i>
                </button>
            </span>
        `).join('');
    }

    window.removeProperty = (prop) => {
        const index = selectedProperties.indexOf(prop);
        if (index > -1 && selectedProperties.length > 1) {
            selectedProperties.splice(index, 1);
            renderProperties();
        }
    };

    newPropertyInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter' && e.target.value.trim()) {
            const newProp = e.target.value.trim();
            if (!selectedProperties.includes(newProp)) {
                selectedProperties.push(newProp);
                renderProperties();
                e.target.value = '';
            }
        }
    });

    searchButton.addEventListener('click', async () => {
        const identity = document.querySelector('#ldap-attributes-modal h3').textContent;
        await loadDescendantsWithProperties(identity, selectedProperties);
    });

    renderProperties();
}

async function loadDescendantsWithProperties(identity, properties) {
    const tbody = document.getElementById('descendants-rows');
    const thead = document.getElementById('descendants-header');
    tbody.innerHTML = '';
    thead.innerHTML = '';

    // Ensure objectClass is included in the API request
    const apiProperties = properties.includes('objectClass') ? 
        properties : 
        ['objectClass', ...properties];

    try {
        const data = await fetchItemsData(identity, 'SUBTREE', apiProperties);
        
        if (data && Array.isArray(data)) {
            // Create header row with icon column
            const headerRow = document.createElement('tr');
            headerRow.className = 'h-8';
            
            // Always add icon column header
            const iconTh = document.createElement('th');
            iconTh.className = 'text-left w-8';
            iconTh.textContent = ''; // Empty header for icon column
            headerRow.appendChild(iconTh);

            // Add other property headers, excluding objectClass
            properties.forEach(prop => {
                if (prop !== 'objectClass') {
                    const th = document.createElement('th');
                    th.className = 'text-left';
                    th.textContent = prop;
                    headerRow.appendChild(th);
                }
            });
            thead.appendChild(headerRow);

            // Create data rows
            data.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800 cursor-pointer';
                
                // Always add icon column
                const iconTd = document.createElement('td');
                iconTd.className = 'py-2';
                
                // Get objectClass array and convert to lowercase for comparison
                const objectClasses = Array.isArray(item.attributes.objectClass) 
                    ? item.attributes.objectClass.map(c => c.toLowerCase())
                    : [item.attributes.objectClass?.toLowerCase()];

                let icon = '';
                if (objectClasses.includes('computer')) {
                    icon = icons.computerIcon;
                } else if (objectClasses.includes('user')) {
                    icon = icons.userIcon;
                } else if (objectClasses.includes('organizationalunit')) {
                    icon = icons.ouIcon;
                } else if (objectClasses.includes('group')) {
                    icon = icons.groupIcon;
                } else if (objectClasses.includes('container')) {
                    icon = icons.containerIcon;
                } else {
                    icon = icons.defaultIcon;
                }
                
                iconTd.innerHTML = icon;
                row.appendChild(iconTd);
                
                // Add other property columns, excluding objectClass
                properties.forEach(prop => {
                    if (prop !== 'objectClass') {
                        const td = document.createElement('td');
                        td.className = 'py-2';
                        let value = item.attributes[prop];
                        if (Array.isArray(value)) {
                            value = value[0]; // Take first value for array properties
                        }
                        td.textContent = value || '';
                        row.appendChild(td);
                    }
                });

                row.addEventListener('click', () => handleLdapLinkClick(event, item.dn));
                tbody.appendChild(row);
            });
        }
    } catch (error) {
        console.error('Error loading descendants:', error);
        showErrorAlert('Failed to load descendants');
    }
}

// Update loadDescendants to use the new function
async function loadDescendants() {
    const identity = document.querySelector('#ldap-attributes-modal h3').textContent;
    await loadDescendantsWithProperties(identity, ['name', 'distinguishedName']);
    initializePropertyFilter();
}

// Add this function to handle opening the Add Object ACL modal
function openAddObjectAclModal() {
    const modal = document.getElementById('add-object-acl-modal');
    const targetIdentityInput = document.getElementById('target-identity');
    const overlay = document.getElementById('modal-overlay');
    
    // Pre-fill the target identity if it exists
    const currentIdentity = document.querySelector('#ldap-attributes-modal h3')?.textContent;
    
    if (modal) {
        if (targetIdentityInput && currentIdentity) {
            targetIdentityInput.value = currentIdentity;
        }
        
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
        
        // Initialize close handlers
        initializeAddAclModal();
    }
}

// Update the DACL tab panel button to use this function
function updateDaclTabContent() {
    const addButton = document.querySelector('[onclick="document.getElementById(\'add-object-acl-modal\').classList.remove(\'hidden\')"]');
    if (addButton) {
        addButton.setAttribute('onclick', 'openAddObjectAclModal()');
    }
}

// Add this function to handle closing the Add Object ACL modal
function closeAddObjectAclModal() {
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

// Add this to your initialization code (e.g., in showLdapAttributesModal or a separate init function)
function initializeAddAclModal() {
    // Handle close button click
    const closeButton = document.querySelector('[data-modal-hide="add-object-acl-modal"]');
    if (closeButton) {
        closeButton.addEventListener('click', closeAddObjectAclModal);
    }

    // Add form submit handler
    const form = document.getElementById('add-object-acl-form');
    if (form) {
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const targetIdentity = document.getElementById('target-identity').value;
            const principalIdentity = document.getElementById('principal-identity').value;
            const rights = document.getElementById('acl-rights').value;
            const aceType = document.getElementById('ace-type').value;
            const inheritance = document.getElementById('inheritance').checked;

            await addDomainObjectAcl(targetIdentity, principalIdentity, rights, aceType, inheritance);
        });
    }

    // Optional: Handle clicking outside the modal to close it
    const modal = document.getElementById('add-object-acl-modal');
    if (modal) {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeAddObjectAclModal();
            }
        });
    }
}

// Add this function to handle the API request for adding ACL
async function addDomainObjectAcl(targetIdentity, principalIdentity, rights, aceType, inheritance) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/add/domainobjectacl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                targetidentity: targetIdentity,
                principalidentity: principalIdentity,
                rights: rights,
                ace_type: aceType,
                inheritance: inheritance
            })
        });

        await handleHttpError(response);

        if (response.ok) {
            showSuccessAlert('Successfully added ACL');
            closeAddObjectAclModal();
            
            // Force refresh of DACL tab content
            const identity = document.querySelector('#ldap-attributes-modal h3').textContent;
            if (identity) {
                // Make sure we're on the DACL tab
                await selectModalTab('dacl');
                // Fetch and display updated DACL data
                await fetchAndDisplayModalDacl(identity);
            }
            return true;
        }
    } catch (error) {
        console.error('Error adding ACL:', error);
        showErrorAlert('Failed to add ACL');
        return false;
    } finally {
        hideLoadingIndicator();
    }
    return false;
}

// Add new function to handle members display
async function fetchAndDisplayModalMembers(identity) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/domaingroupmember', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: identity })
        });

        await handleHttpError(response);
        const members = await response.json();
        displayModalGroupMembers(members);
    } catch (error) {
        console.error('Error fetching group members:', error);
        showErrorAlert('Failed to fetch group members');
    } finally {
        hideLoadingIndicator();
    }
}

function displayModalGroupMembers(members) {
    const membersContent = document.getElementById('modal-members-content');
    if (!membersContent) return;

    membersContent.innerHTML = '';

    if (!members || !Array.isArray(members) || members.length === 0) {
        membersContent.innerHTML = '<p class="text-neutral-600 dark:text-neutral-400">No members found</p>';
        return;
    }

    const table = document.createElement('table');
    table.className = 'w-full text-sm border-collapse';

    const thead = document.createElement('thead');
    thead.innerHTML = `
        <tr class="h-8 text-left text-neutral-600 dark:text-neutral-400">
            <th class="px-3 py-2">Name</th>
            <th class="px-3 py-2">Member SID</th>
            <th class="px-3 py-2">Distinguished Name</th>
        </tr>
    `;
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    tbody.className = 'divide-y divide-neutral-200 dark:divide-neutral-700';

    members.forEach(member => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800 cursor-pointer';
        row.onclick = () => handleLdapLinkClick(event, member.attributes.MemberDistinguishedName);
        
        const nameCell = document.createElement('td');
        nameCell.className = 'px-3 py-2';
        nameCell.textContent = member.attributes.MemberName || '';

        const sidCell = document.createElement('td');
        sidCell.className = 'px-3 py-2';
        sidCell.textContent = member.attributes.MemberSID || '';

        const dnCell = document.createElement('td');
        dnCell.className = 'px-3 py-2';
        dnCell.textContent = member.attributes.MemberDistinguishedName || '';

        row.appendChild(nameCell);
        row.appendChild(sidCell);
        row.appendChild(dnCell);
        tbody.appendChild(row);
    });

    table.appendChild(tbody);
    membersContent.appendChild(table);
}

async function deleteDomainObject(identity, searchbase) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/remove/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identity: identity,
                searchbase: searchbase
            })
        });

        await handleHttpError(response);
        
        if (response.ok) {
            showSuccessAlert('Successfully deleted object');
            return true;
        }
    } catch (error) {
        console.error('Error deleting domain object:', error);
        showErrorAlert('Failed to delete object');
        return false;
    } finally {
        hideLoadingIndicator();
    }
    return false;
}

async function fetchAndDisplayModalSessions(identity) {
    const sessionsRows = document.getElementById('sessions-rows');
    sessionsRows.innerHTML = '';
    
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/netsession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                identity: identity
            })
        });

        await handleHttpError(response);
        const sessionsData = await response.json();
        updateModalSessionsContent(sessionsData);
    } catch (error) {
        console.error('Error fetching sessions data:', error);
        showErrorAlert('Failed to fetch sessions data');
    } finally {
        hideLoadingIndicator();
    }
}

function updateModalSessionsContent(sessionsData) {
    const sessionsRows = document.getElementById('sessions-rows');
    if (!sessionsRows) return;

    sessionsRows.innerHTML = '';

    if (!sessionsData || !Array.isArray(sessionsData) || sessionsData.length === 0) {
        sessionsRows.innerHTML = `
            <tr>
                <td colspan="4" class="px-3 py-4 text-center text-neutral-500 dark:text-neutral-400">
                    No active sessions found
                </td>
            </tr>
        `;
        return;
    }

    sessionsData.forEach(session => {
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

        const attrs = session.attributes;
        row.innerHTML = `
            <td class="px-3 py-2">${attrs.Username || ''}</td>
            <td class="px-3 py-2">${attrs.IP ? attrs.IP.replace(/\\/g, '') : ''}</td>
            <td class="px-3 py-2">${attrs.Time ? `${attrs.Time} minutes` : ''}</td>
            <td class="px-3 py-2">${attrs['Idle Time'] ? `${attrs['Idle Time']} minutes` : ''}</td>
        `;

        sessionsRows.appendChild(row);
    });
}

async function fetchAndDisplayModalLogonUsers(dnsHostname) {
    showLoadingIndicator();
    try {
        const response = await fetch('/api/get/netloggedon', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                computer_name: dnsHostname  // Changed from 'identity' to 'computer_name'
            })
        });

        await handleHttpError(response);
        const logonData = await response.json();
        updateModalLogonUsersContent(logonData);
    } catch (error) {
        console.error('Error fetching logon users data:', error);
        showErrorAlert('Failed to fetch logon users data');
    } finally {
        hideLoadingIndicator();
    }
}

function updateModalLogonUsersContent(logonData) {
    const logonUsersRows = document.getElementById('logonusers-rows');
    if (!logonUsersRows) return;

    logonUsersRows.innerHTML = '';

    if (!logonData || !Array.isArray(logonData) || logonData.length === 0) {
        logonUsersRows.innerHTML = `
            <tr>
                <td colspan="4" class="px-3 py-4 text-center text-neutral-500 dark:text-neutral-400">
                    No logon users found
                </td>
            </tr>
        `;
        return;
    }

    logonData.forEach(user => {
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

        const attrs = user.attributes;
        row.innerHTML = `
            <td class="px-3 py-2">${attrs.UserName || ''}</td>
            <td class="px-3 py-2">${attrs.LogonDomain || ''}</td>
            <td class="px-3 py-2">${attrs.AuthDomains || ''}</td>
            <td class="px-3 py-2">${attrs.LogonServer || ''}</td>
        `;

        logonUsersRows.appendChild(row);
    });
}

async function handleDisconnect() {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/ldap/close', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        await handleHttpError(response);

        if (response.ok) {
            // Update connection status UI
            const profileMenu = document.getElementById('profile-menu');
            const statusElement = profileMenu.querySelector('#connection-status-display');
            const addressElement = profileMenu.querySelector('#connection-address-display');
            const domainElement = profileMenu.querySelector('#connection-domain-display');
            const usernameElement = profileMenu.querySelector('#username-display');

            // Clear connection info
            usernameElement.textContent = '';
            addressElement.textContent = '';
            domainElement.textContent = '';
            statusElement.textContent = 'Disconnected';
            statusElement.classList.remove('text-green-400');
            statusElement.classList.add('text-red-400');

            showSuccessAlert('Successfully disconnected from LDAP server');
        }
    } catch (error) {
        console.error('Error disconnecting from LDAP server:', error);
        showErrorAlert('Failed to disconnect from LDAP server');
    } finally {
        hideLoadingIndicator();
    }
}

function initializeDisconnectButton() {
    const disconnectButton = document.getElementById('disconnect-button');
    if (disconnectButton) {
        disconnectButton.addEventListener('click', handleDisconnect);
    }
}

function initializeClearCacheButton() {
    const clearCacheButton = document.getElementById('clear-cache-button');
    if (clearCacheButton) {
        clearCacheButton.addEventListener('click', async () => {
            try {
                showLoadingIndicator();
                const response = await fetch('/api/clear-cache', {
                    method: 'GET',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });

                await handleHttpError(response);

                if (response.ok) {
                    showSuccessAlert('Cache cleared successfully');
                }
            } catch (error) {
                console.error('Error clearing cache:', error);
                showErrorAlert('Failed to clear cache');
            } finally {
                hideLoadingIndicator();
            }
        });
    }
}

// Add this function to display the Member Of content
function displayModalMemberOf(memberOf) {
    const tbody = document.getElementById('memberof-rows');
    if (!tbody) return;

    tbody.innerHTML = '';

    if (!memberOf || !Array.isArray(memberOf) || memberOf.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="2" class="px-3 py-2 text-neutral-600 dark:text-neutral-400">
                    No group memberships found
                </td>
            </tr>`;
        return;
    }

    memberOf.forEach(dn => {
        const row = document.createElement('tr');
        row.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800 cursor-pointer';
        row.onclick = () => handleLdapLinkClick(event, dn);

        // Extract CN from DN
        const cnMatch = dn.match(/CN=([^,]+)/);
        const name = cnMatch ? cnMatch[1] : dn;

        row.innerHTML = `
            <td class="px-3 py-2">${name}</td>
            <td class="px-3 py-2">${dn}</td>
        `;
        tbody.appendChild(row);
    });
}