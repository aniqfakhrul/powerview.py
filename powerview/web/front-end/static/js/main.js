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

function showModalContentSpinner() {
    const spinner = document.getElementById('modal-content-spinner');
    if (spinner) {
        spinner.classList.remove('hidden');
    }
}

function hideModalContentSpinner() {
    const spinner = document.getElementById('modal-content-spinner');
    if (spinner) {
        spinner.classList.add('hidden');
    }
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
                const userOnly = (data.username || '').split('\\').pop();
                const domOnly = (data.domain || '').toString();

                // Username and domain on separate lines with subtle styles
                usernameElement.textContent = userOnly || '';
                domainElement.textContent = domOnly || '';

                // Address and nameserver with compact badges
                const proto = data.protocol ? data.protocol.toUpperCase() : '';
                addressElement.innerHTML = proto && data.ldap_address
                    ? `${proto}: // ${data.ldap_address}`
                    : '';
                nameserverElement.innerHTML = data.nameserver ? `NS: ${data.nameserver}` : '';
                if (data.status === 'OK') {
                    statusElement.innerHTML = '<span class="inline-flex items-center gap-1 text-green-500"><span class="inline-block w-2 h-2 rounded-full bg-green-500"></span>Connected</span>';
                } else {
                    statusElement.innerHTML = '<span class="inline-flex items-center gap-1 text-red-500"><span class="inline-block w-2 h-2 rounded-full bg-red-500"></span>Disconnected</span>';
                }
            } else {
                throw new Error('Failed to fetch status');
            }
        } catch (error) {
            const profileMenu = document.getElementById('profile-menu');
            if (profileMenu) {
                const statusElement = profileMenu.querySelector('#connection-status-display');
                if (statusElement) {
                    statusElement.innerHTML = '<span class="inline-flex items-center gap-1 text-red-500"><span class="inline-block w-2 h-2 rounded-full bg-red-500"></span>Disconnected</span>';
                }
            }
            console.error('Error checking connection status:', error);
        } finally {
            clearTimeout(timeoutId);
        }
    }

    const addServiceForm = document.getElementById('add-service-form');
    if (addServiceForm) {
        addServiceForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const form = e.target;
            
            // Get computer name from DNS hostname field
            const dnsHostnameInput = document.querySelector('#dNSHostName-wrapper input');
            if (!dnsHostnameInput) {
                showErrorAlert('Computer hostname not found');
                return;
            }
            
            const computer = dnsHostnameInput.value;
            if (!computer) {
                showErrorAlert('Computer hostname is required');
                return;
            }
            
            try {
                showLoadingIndicator();
                const response = await fetch('/api/add/netservice', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        computer_name: computer,
                        service_name: form.service_name.value,
                        display_name: form.display_name.value,
                        binary_path: form.binary_path.value,
                        service_type: parseInt(form.service_type.value),
                        start_type: parseInt((form.start_type.value || '').toString().replace('-delayed','')),
                        delayed_start: (form.start_type.value || '').toString().includes('-delayed'),
                        service_start_name: form.service_start_name.value || null
                    })
                });
        
                await handleHttpError(response);
                showSuccessAlert('Service created successfully');
                
                // Refresh the services list
                await fetchAndDisplayModalServices(computer);
                
                // Reset the form and hide it
                form.reset();
                const container = document.getElementById('add-service-form-container');
                const content = document.getElementById('add-service-form-content');
                const toggleButton = document.getElementById('toggle-add-service-form');
                
                if (container && content && toggleButton) {
                    content.classList.remove('opacity-100', 'scale-100');
                    content.classList.add('opacity-0', 'scale-95');
                    
                    setTimeout(() => {
                        container.classList.add('hidden');
                    }, 300);
                    
                    toggleButton.innerHTML = '<i class="fas fa-plus"></i>';
                    toggleButton.classList.remove('text-red-600', 'hover:text-red-700', 'dark:text-red-500', 'dark:hover:text-red-400', 'hover:bg-red-50', 'dark:hover:bg-red-950/50');
                    toggleButton.classList.add('text-green-600', 'hover:text-green-700', 'dark:text-green-500', 'dark:hover:text-green-400', 'hover:bg-green-50', 'dark:hover:bg-green-950/50');
                }
            } catch (error) {
                console.error('Error creating service:', error);
                showErrorAlert(error.message || 'Failed to create service');
            } finally {
                hideLoadingIndicator();
            }
        });
    }

    initializeDisconnectButton();
    initializeClearCacheButton();

    // Add this near your other initialization code
    document.getElementById('toggle-add-service-form').addEventListener('click', function() {
        const container = document.getElementById('add-service-form-container');
        const content = document.getElementById('add-service-form-content');
        
        if (container.classList.contains('hidden')) {
            // Show the form
            container.classList.remove('hidden');
            setTimeout(() => {
                content.classList.remove('opacity-0', 'scale-95');
                content.classList.add('opacity-100', 'scale-100');
            }, 10);
            
            // Update button style to show active state
            this.classList.remove('text-green-600', 'hover:text-green-700', 'dark:text-green-500', 'dark:hover:text-green-400', 'hover:bg-green-50', 'dark:hover:bg-green-950/50');
            this.classList.add('text-red-600', 'hover:text-red-700', 'dark:text-red-500', 'dark:hover:text-red-400', 'hover:bg-red-50', 'dark:hover:bg-red-950/50');
            this.innerHTML = '<i class="fas fa-times"></i>';
        } else {
            // Hide the form with animation
            content.classList.remove('opacity-100', 'scale-100');
            content.classList.add('opacity-0', 'scale-95');
            
            setTimeout(() => {
                container.classList.add('hidden');
            }, 300);
            
            // Reset button style
            this.classList.remove('text-red-600', 'hover:text-red-700', 'dark:text-red-500', 'dark:hover:text-red-400', 'hover:bg-red-50', 'dark:hover:bg-red-950/50');
            this.classList.add('text-green-600', 'hover:text-green-700', 'dark:text-green-500', 'dark:hover:text-green-400', 'hover:bg-green-50', 'dark:hover:bg-green-950/50');
            this.innerHTML = '<i class="fas fa-plus"></i>';
        }
    });

    // Reset form state when modal is closed
    document.querySelectorAll('[data-modal-hide="ldap-attributes-modal"]').forEach(button => {
        button.addEventListener('click', function() {
            const container = document.getElementById('add-service-form-container');
            const content = document.getElementById('add-service-form-content');
            const toggleButton = document.getElementById('toggle-add-service-form');
            
            container.classList.add('hidden');
            content.classList.remove('opacity-100', 'scale-100');
            content.classList.add('opacity-0', 'scale-95');
            
            // Reset button style
            toggleButton.classList.remove('text-red-600', 'hover:text-red-700', 'dark:text-red-500', 'dark:hover:text-red-400', 'hover:bg-red-50', 'dark:hover:bg-red-950/50');
            toggleButton.classList.add('text-green-600', 'hover:text-green-700', 'dark:text-green-500', 'dark:hover:text-green-400', 'hover:bg-green-50', 'dark:hover:bg-green-950/50');
            toggleButton.innerHTML = '<i class="fas fa-plus"></i>';
            
            // Reset form if needed
            document.getElementById('add-service-form').reset();
        });
    });
});

function createAttributeEntry(name, value, identity) {
    const wrapper = document.createElement('div');
    wrapper.className = 'flex flex-col gap-1';
    wrapper.id = `${name}-wrapper`;

    const labelDiv = document.createElement('div');
    labelDiv.className = 'flex justify-between items-center';

    const label = document.createElement('label');
    label.className = 'block text-xs font-medium text-neutral-500 dark:text-neutral-400';
    label.textContent = name;

    labelDiv.appendChild(label);

    const inputsContainer = document.createElement('div');
    inputsContainer.className = 'flex items-start justify-between gap-2';

    const isArray = Array.isArray(value);
    const valueContainer = document.createElement('div');
    valueContainer.className = 'attr-value text-sm break-words whitespace-pre-wrap text-neutral-900 dark:text-neutral-100';
    const valueText = isArray ? value.join('\n') : value;
    if (isArray) {
        const chips = document.createElement('div');
        chips.className = 'flex flex-wrap gap-2';
        value.forEach(v => {
            const chip = document.createElement('span');
            chip.className = 'px-2 py-1 rounded-full bg-neutral-100 dark:bg-neutral-800 text-xs text-neutral-700 dark:text-neutral-300';
            chip.textContent = v;
            chips.appendChild(chip);
        });
        valueContainer.appendChild(chips);
    } else {
        valueContainer.textContent = valueText;
    }

    let input;
    if (isArray) {
        input = document.createElement('textarea');
        input.rows = Math.min(10, (value?.length || 1) + 1);
    } else {
        input = document.createElement('input');
        input.type = 'text';
    }
    input.className = 'hidden rounded-md border border-neutral-300 bg-neutral-50 px-2 py-2 text-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-black dark:border-neutral-700 dark:bg-neutral-900/50 dark:focus-visible:outline-yellow-500 w-full whitespace-pre-wrap';
    input.value = valueText;

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

    const buttonsDiv = document.createElement('div');
    buttonsDiv.className = 'flex gap-3 items-center shrink-0 pl-2';
    buttonsDiv.appendChild(editButton);
    buttonsDiv.appendChild(addButton);
    buttonsDiv.appendChild(deleteButton);

    const valueStack = document.createElement('div');
    valueStack.className = 'flex-1';
    valueStack.appendChild(valueContainer);
    valueStack.appendChild(input);

    inputsContainer.appendChild(valueStack);
    inputsContainer.appendChild(buttonsDiv);
    
    wrapper.appendChild(labelDiv);
    wrapper.appendChild(inputsContainer);

    // Edit button click handler with visibility toggle
    editButton.addEventListener('click', async () => {
        const isEditing = input.classList.contains('hidden');
        
        if (isEditing) {
            input.classList.remove('hidden');
            valueContainer.classList.add('hidden');
            editButton.innerHTML = '<i class="fas fa-save fa-xs"></i>';
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
                input.classList.add('hidden');
                valueContainer.textContent = originalValue;
                valueContainer.classList.remove('hidden');
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
                    input.classList.add('hidden');
                    valueContainer.classList.remove('hidden');
                    // Re-render display: create chips if multiple lines
                    valueContainer.innerHTML = '';
                    const parts = (newValue || '').split(/\r?\n/).map(s => s.trim()).filter(Boolean);
                    if (parts.length > 1) {
                        const chips = document.createElement('div');
                        chips.className = 'flex flex-wrap gap-2';
                        parts.forEach(v => {
                            const chip = document.createElement('span');
                            chip.className = 'px-2 py-1 rounded-full bg-neutral-100 dark:bg-neutral-800 text-xs text-neutral-700 dark:text-neutral-300';
                            chip.textContent = v;
                            chips.appendChild(chip);
                        });
                        valueContainer.appendChild(chips);
                    } else {
                        valueContainer.textContent = newValue;
                    }
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
                input.classList.add('hidden');
                valueContainer.classList.remove('hidden');
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
        appendWrapper.className = 'flex gap-2 mt-2';

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
        valueStack.appendChild(appendWrapper);
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
    container.className = 'grid grid-cols-1 md:grid-cols-2 gap-6';

    // Sort attributes alphabetically
    const sortedAttributes = Object.entries(attributes).sort((a, b) => 
        a[0].toLowerCase().localeCompare(b[0].toLowerCase())
    );

    sortedAttributes.forEach(([name, value]) => {
        const attributeEntry = createAttributeEntry(name, value, identity);
        if (typeof value === 'string' && value.length > 120) {
            attributeEntry.classList.add('md:col-span-2');
        }
        container.appendChild(attributeEntry);
    });
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    const overlay = document.getElementById('modal-overlay');
    
    if (modalId === 'ldap-attributes-modal') {
        // Clear SMB tree content
        const smbTree = document.getElementById('smb-tree');
        if (smbTree) {
            smbTree.innerHTML = '';
        }
        
        // Reset connection status
        const connectionStatus = document.getElementById('smb-connection-status');
        if (connectionStatus) {
            connectionStatus.innerHTML = '';
        }

        // Reset computer input
        const computerInput = document.getElementById('modal-smb-computer');
        if (computerInput) {
            computerInput.value = '';
        }

        // Hide the connect as form if it's visible
        const connectAsForm = document.getElementById('connect-as-form');
        if (connectAsForm) {
            connectAsForm.classList.add('hidden');
        }

        // Reset credentials if any
        const usernameInput = document.getElementById('modal-smb-username');
        const passwordInput = document.getElementById('modal-smb-password');
        if (usernameInput) usernameInput.value = '';
        if (passwordInput) passwordInput.value = '';
    }

    if (modal && overlay) {
        modal.classList.add('hidden');
        overlay.classList.add('hidden');
    }
}

// Add this function to handle filtering
function handleModalSearch() {
    const searchInput = document.getElementById('modal-tab-search');
    if (!searchInput) return;
    const clearButton = searchInput.nextElementSibling;

    function filterContent() {
        const searchTerm = searchInput.value.toLowerCase();
        // Find the active tab by checking which tab panel is currently visible
        const activeTabPanel = document.querySelector('#ldap-attributes-modal [role="tabpanel"]:not([style*="display: none"])');
        const activeTabId = activeTabPanel?.id;

        if (!activeTabId) return;

        switch (activeTabId) {
            case 'tabpanelAttributes':
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
            case 'tabpanelTasklist':
                const taskRows = document.querySelectorAll('#tasklist-rows tr');
                taskRows.forEach(row => {
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

            case 'tabpanelServices':
                const statusFilter = document.getElementById('service-status-filter');
                const selectedStatus = statusFilter ? statusFilter.value : 'ALL';
                const serviceRows = document.querySelectorAll('#services-rows tr:not(.details-row)');
                
                serviceRows.forEach(row => {
                    const text = row.textContent.toLowerCase();
                    const statusCell = row.querySelector('td:nth-child(3)');
                    const status = statusCell ? statusCell.textContent.trim() : '';
                    const detailsRow = row.nextElementSibling;
                    
                    const matchesSearch = text.includes(searchTerm);
                    const matchesStatus = selectedStatus === 'ALL' || status === selectedStatus;
                    
                    row.style.display = matchesSearch && matchesStatus ? '' : 'none';
                    if (detailsRow && detailsRow.classList.contains('details-row')) {
                        detailsRow.style.display = matchesSearch && matchesStatus ? '' : 'none';
                    }
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

        // Update modal title and profile header
        const modalTitle = modal.querySelector('h3');
        if (modalTitle) modalTitle.textContent = identity;
        const copyBtn = document.getElementById('modal-copy-dn');
        if (copyBtn) {
            copyBtn.onclick = async () => {
                try {
                    if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
                        await navigator.clipboard.writeText(identity);
                        showSuccessAlert('DN copied');
                    } else {
                        const ta = document.createElement('textarea');
                        ta.value = identity;
                        ta.style.position = 'fixed';
                        ta.style.left = '-1000px';
                        document.body.appendChild(ta);
                        ta.select();
                        document.execCommand('copy');
                        document.body.removeChild(ta);
                        showSuccessAlert('DN copied');
                    }
                } catch (e) {
                    showErrorAlert('Failed to copy DN');
                }
            };
        }

        const name = attributes.displayName || attributes.cn || attributes.name || identity;
        const title = attributes.title || '';
        const department = attributes.department || '';
        const avatar = (attributes.thumbnailPhoto && attributes.thumbnailPhoto.length) ? null : (name ? name.toString().charAt(0).toUpperCase() : '?');

        const avatarEl = document.getElementById('profile-avatar');
        const nameEl = document.getElementById('profile-name');
        const titleEl = document.getElementById('profile-title');
        const deptEl = document.getElementById('profile-dept');
        const sepEl = document.getElementById('profile-sep');
        
        if (avatarEl) avatarEl.textContent = avatar || '';
        if (nameEl) nameEl.textContent = Array.isArray(name) ? name[0] : name;
        if (titleEl) titleEl.textContent = Array.isArray(title) ? title[0] : title;
        if (deptEl) deptEl.textContent = Array.isArray(department) ? department[0] : department;
        if (sepEl) sepEl.classList.toggle('hidden', !(title && department));
        

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
        
        // Show/hide computer-specific tabs
        const sessionsTab = modal.querySelector('[aria-controls="tabpanelSessions"]');
        const tasklistTab = modal.querySelector('[aria-controls="tabpanelTasklist"]');
        const loggedonTab = modal.querySelector('[aria-controls="tabpanelLoggedon"]');
        const servicesTab = modal.querySelector('[aria-controls="tabpanelServices"]');
        
        if (sessionsTab && tasklistTab && loggedonTab && servicesTab) {
            sessionsTab.style.display = isComputer ? '' : 'none';
            tasklistTab.style.display = isComputer ? '' : 'none';
            loggedonTab.style.display = isComputer ? '' : 'none';
            servicesTab.style.display = isComputer ? '' : 'none';
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
            // Populate attributes tab content
            await populateLdapAttributesModal(attributes, identity);

            // Initialize the add new attribute functionality
            handleAddNewAttribute(identity);

            // Initialize tabs to Overview
            selectModalTab('overview');

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
            case 'overview':
                renderOverviewTab();
                break;
            case 'attributes':
                // nothing special; attributes rendered at modal open
                break;
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
            case 'tasklist':
                const dnsHostnameTasklistInput = ldapAttributeModal.querySelector('#dNSHostName-wrapper input');
                const dnsHostnameTasklist = dnsHostnameTasklistInput?.value;
                if (dnsHostnameTasklist) {
                    await fetchAndDisplayModalTasklist(dnsHostnameTasklist);
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

            case 'owner':
                const identity = document.querySelector('#ldap-attributes-modal h3')?.textContent;
                if (identity) {
                    await getObjectOwner(identity);
                }
                break;

            case 'services':
                const dnsHostnameServicesInput = ldapAttributeModal.querySelector('#dNSHostName-wrapper input');
                const dnsHostnameServices = dnsHostnameServicesInput?.value;
                if (dnsHostnameServices) {
                    await fetchAndDisplayModalServices(dnsHostnameServices);
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

async function fetchAndDisplayModalDacl(identity, no_cache = false) {
    showModalContentSpinner();
    try {
        const response = await fetch('/api/get/domainobjectacl', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ identity: identity, searchbase: identity, search_scope: 'BASE', no_cache: no_cache })
        });

        await handleHttpError(response);
        const daclData = await response.json();
        updateModalDaclContent(daclData);
    } catch (error) {
        console.error('Error fetching DACL data:', error);
        showErrorAlert('Failed to fetch DACL data');
    } finally {
        hideModalContentSpinner();
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
                'result-item',
                'border-b',
                'border-neutral-200',
                'dark:border-neutral-700',
                'hover:bg-neutral-50',
                'dark:hover:bg-neutral-800'
            );

            const aceAllowed = attribute.ACEType?.toUpperCase().includes('ALLOWED');
            const aceBadgeClasses = aceAllowed ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
            const aceBadgeLabel = aceAllowed ? 'ALLOW' : 'DENY';
            const aceTypeBadge = '<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ' + aceBadgeClasses + '">' + aceBadgeLabel + '</span>';

            const accessList = (attribute.AccessMask || '')
                .split(',')
                .map(s => s.trim())
                .filter(Boolean)
                .map(mask => '<span class="inline-flex px-2 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-xs mr-1 mb-1">' + mask + '</span>') 
                .join('');

            const sid = (attribute.SecurityIdentifier || '').replace('Pre-Windows 2000', 'Pre2k');

            const inherited = attribute.InheritanceType || '';
            const appliesTo = attribute.ObjectAceType || '';

            const accessListHtml = accessList || '<span class="text-neutral-500 dark:text-neutral-400 text-xs">-</span>';

            row.innerHTML =
                '<td class="px-3 py-2 align-top w-20">' + aceTypeBadge + '</td>' +
                '<td class="px-3 py-2 align-top">' +
                '    <div class="text-sm text-neutral-900 dark:text-neutral-100">' + sid + '</div>' +
                '</td>' +
                '<td class="px-3 py-2">' +
                '    <div class="flex flex-wrap">' + accessListHtml + '</div>' +
                '</td>' +
                '<td class="px-3 py-2 align-top">' +
                '    <span class="text-xs text-neutral-600 dark:text-neutral-300">' + inherited + '</span>' +
                '</td>' +
                '<td class="px-3 py-2 align-top">' +
                '    <span class="text-xs text-neutral-600 dark:text-neutral-300">' + appliesTo + '</span>' +
                '</td>';

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

function renderOverviewTab() {
    const modal = document.getElementById('ldap-attributes-modal');
    if (!modal) return;
    const overview = document.getElementById('overview-content');
    if (!overview) return;
    const attrsSection = document.getElementById('existing-attributes');
    const attributes = {};
    if (attrsSection) {
        const inputs = attrsSection.querySelectorAll('div[id$="-wrapper"] input');
        inputs.forEach(inp => {
            const wrapper = inp.closest('div[id$="-wrapper"]');
            const key = wrapper ? wrapper.id.replace(/-wrapper$/, '') : '';
            if (key && !attributes[key]) attributes[key] = inp.value;
        });
    }
    const objectClass = (attributes['objectClass'] || '').toString().toLowerCase();
    const isComputer = (
        objectClass.includes('computer') ||
        /computer/i.test(attributes['objectCategory'] || '') ||
        /machine/i.test(attributes['sAMAccountType'] || '') ||
        !!attributes['dNSHostName'] ||
        ((attributes['sAMAccountName'] || '').toString().endsWith('$'))
    );

    if (isComputer) {
        const host = attributes['dNSHostName'] || attributes['dnsHostName'] || attributes['cn'] || '-';
        const os = attributes['operatingSystem'] || '-';
        const osVer = attributes['operatingSystemVersion'] || '-';
        const lastLogon = attributes['lastLogonTimestamp'] || attributes['lastLogon'] || '-';
        const desc = attributes['description'] || '-';
        const uac = attributes['userAccountControl'] || '-';
        const encTypes = attributes['msDS-SupportedEncryptionTypes'] || '-';
        const spnRaw = attributes['servicePrincipalName'] || '';
        const spns = spnRaw ? spnRaw.split(/\r?\n/).map(s => s.trim()).filter(Boolean) : [];

        overview.innerHTML = `
            <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="space-y-3">
                    <div class="text-sm text-neutral-500">System</div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <div class="text-xs text-neutral-500">DNS Hostname</div>
                            <div class="text-sm break-all">${host}</div>
                        </div>
                        <div>
                            <div class="text-xs text-neutral-500">Operating System</div>
                            <div class="text-sm">${os}</div>
                        </div>
                        <div>
                            <div class="text-xs text-neutral-500">OS Version</div>
                            <div class="text-sm">${osVer}</div>
                        </div>
                        <div>
                            <div class="text-xs text-neutral-500">Last Logon</div>
                            <div class="text-sm">${lastLogon}</div>
                        </div>
                        <div class="sm:col-span-2">
                            <div class="text-xs text-neutral-500">Description</div>
                            <div class="text-sm break-words">${desc}</div>
                        </div>
                    </div>
                </div>
                <div class="space-y-3">
                    <div class="text-sm text-neutral-500">Security</div>
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <div class="text-xs text-neutral-500">User Account Control</div>
                            <div class="text-sm break-words">${uac}</div>
                        </div>
                        <div>
                            <div class="text-xs text-neutral-500">Encryption Types</div>
                            <div class="text-sm">${encTypes}</div>
                        </div>
                        <div class="sm:col-span-2">
                            <div class="text-xs text-neutral-500">Service Principal Names</div>
                            <div class="flex flex-wrap gap-2">
                                ${spns.length ? spns.map(s => `<span class=\"px-2 py-0.5 rounded bg-neutral-100 dark:bg-neutral-800 text-xs\">${s}</span>`).join('') : '<span class=\"text-neutral-500 dark:text-neutral-400 text-xs\">-</span>'}
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        return;
    }

    const email = attributes['mail'] || '';
    const upn = attributes['userPrincipalName'] || '';
    const phone = attributes['telephoneNumber'] || attributes['homePhone'] || attributes['mobile'] || '';
    const office = attributes['physicalDeliveryOfficeName'] || attributes['streetAddress'] || '';
    const jobTitle = attributes['title'] || '';
    const dept = attributes['department'] || '';
    overview.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div class="space-y-3">
                <div class="text-sm text-neutral-500">Contact information</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <div class="text-xs text-neutral-500">Email</div>
                        <div class="text-sm break-all">${email || upn || '-'}</div>
                    </div>
                    <div>
                        <div class="text-xs text-neutral-500">Work phone</div>
                        <div class="text-sm">${phone || '-'}</div>
                    </div>
                    <div>
                        <div class="text-xs text-neutral-500">Office location</div>
                        <div class="text-sm">${office || '-'}</div>
                    </div>
                    <div>
                        <div class="text-xs text-neutral-500">Job title</div>
                        <div class="text-sm">${jobTitle || '-'}</div>
                    </div>
                </div>
            </div>
            <div class="space-y-3">
                <div class="text-sm text-neutral-500">Organization</div>
                <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                    <div>
                        <div class="text-xs text-neutral-500">Department</div>
                        <div class="text-sm">${dept || '-'}</div>
                    </div>
                    <div>
                        <div class="text-xs text-neutral-500">Manager</div>
                        <div class="text-sm" id="overview-manager">-</div>
                    </div>
                </div>
            </div>
        </div>

        <div id="organization-overview" class="mt-8 space-y-4">
            <div class="text-lg font-semibold text-white">Organization</div>
            <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
                <div class="lg:col-span-1">
                    <div class="text-xs text-neutral-500 mb-2">Manager</div>
                    <div id="org-manager-card" class="border border-neutral-200 dark:border-neutral-700 rounded-md p-4 bg-white dark:bg-neutral-900">
                        <div class="text-sm text-neutral-500">No manager</div>
                    </div>
                </div>
                <div class="lg:col-span-3">
                    <div class="text-xs text-neutral-500 mb-2"><span id="org-subject-name"></span> works with</div>
                    <div id="org-peers-grid" class="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4"></div>
                </div>
            </div>
        </div>
    `;

    loadOrganizationSection(attributes);
}

async function loadOrganizationSection(currentAttributes) {
    try {
        const subjectNameEl = document.getElementById('org-subject-name');
        const profileNameEl = document.getElementById('profile-name');
        if (subjectNameEl) subjectNameEl.textContent = (profileNameEl?.textContent || '').trim();

        const managerDn = Array.isArray(currentAttributes['manager']) ? currentAttributes['manager'][0] : currentAttributes['manager'];
        const identity = document.querySelector('#ldap-attributes-modal h3')?.textContent;
        const managerTarget = document.getElementById('org-manager-card');
        const peersGrid = document.getElementById('org-peers-grid');
        const managerInline = document.getElementById('overview-manager');

        if (!managerDn) {
            if (managerTarget) managerTarget.innerHTML = '<div class="text-sm text-neutral-500">No manager</div>';
            if (managerInline) managerInline.textContent = '-';
        }

        let peers = [];
        if (managerDn) {
            const mgrResp = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ searchbase: managerDn, properties: ['displayName','name','title','thumbnailPhoto','directReports','distinguishedName'], search_scope: 'BASE' })
            });
            await handleHttpError(mgrResp);
            if (!mgrResp.ok) return;
            const mgrData = await mgrResp.json();
            const mgrEntry = Array.isArray(mgrData) ? mgrData[0] : mgrData;
            const mgrAttrs = (mgrEntry && mgrEntry.attributes) ? mgrEntry.attributes : {};
            const mgrDisplayName = Array.isArray(mgrAttrs.displayName) ? mgrAttrs.displayName[0] : mgrAttrs.displayName;
            const mgrSimpleName = Array.isArray(mgrAttrs.name) ? mgrAttrs.name[0] : mgrAttrs.name;
            const mgrName = (mgrDisplayName || mgrSimpleName || '') || 'Manager';
            const mgrTitle = Array.isArray(mgrAttrs.title) ? mgrAttrs.title[0] : (mgrAttrs.title || '');
            if (managerInline) managerInline.textContent = mgrName || '-';
            if (managerTarget) {
                const initial = (mgrName || '?').toString().charAt(0).toUpperCase();
                const mgrNameAttr = (mgrName || '').toString().replace(/"/g, '&quot;');
                const mgrTitleAttr = (mgrTitle || '').toString().replace(/"/g, '&quot;');
                managerTarget.innerHTML = `
                    <div class="flex items-center gap-3 org-card fade-in-up transition transform hover:-translate-y-0.5" style="animation-delay: 0ms">
                        <div class="w-12 h-12 rounded-full bg-neutral-200 dark:bg-neutral-700 flex items-center justify-center text-lg font-semibold text-neutral-700 dark:text-neutral-200">${initial}</div>
                        <div class="min-w-0">
                            <div class="text-sm font-medium text-neutral-900 dark:text-white truncate" title="${mgrNameAttr}">${mgrName}</div>
                            <div class="text-xs text-neutral-600 dark:text-neutral-300 truncate" title="${mgrTitleAttr}">${mgrTitle || ''}</div>
                            <a href="#" class="text-xs text-blue-600 dark:text-yellow-500 hover:underline block mt-1" onclick="handleLdapLinkClick(event, '${managerDn.replace(/'/g,"\\'")}')">View profile</a>
                        </div>
                    </div>
                `;
            }
            const reportsDns = Array.isArray(mgrAttrs.directReports) ? (mgrAttrs.directReports || []).filter(Boolean) : (mgrAttrs.directReports ? [mgrAttrs.directReports] : []);
            peers = reportsDns.filter(dn => dn !== identity).slice(0, 9);
        }

        if (!peersGrid) return;
        peersGrid.innerHTML = '';

        if (peers.length === 0) {
            try {
                const deptRaw = Array.isArray(currentAttributes['department']) ? currentAttributes['department'][0] : currentAttributes['department'];
                if (deptRaw) {
                    const deptResp = await fetch('/api/get/domainuser', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ args: { department: deptRaw }, properties: ['displayName','name','title','distinguishedName'] })
                    });
                    await handleHttpError(deptResp);
                    if (deptResp.ok) {
                        const deptData = await deptResp.json();
                        const deptDns = (deptData || []).map(e => e?.attributes?.distinguishedName).filter(Boolean);
                        peers = deptDns.filter(dn => dn !== identity && dn !== managerDn).slice(0, 9);
                    }
                }
            } catch (e) {
                console.error('Department peers lookup failed:', e);
            }
        }

        if (peers.length === 0) {
            peersGrid.innerHTML = '<div class="text-sm text-neutral-500">No peers found</div>';
            return;
        }

        const cards = await Promise.all(peers.map(async (dn, i) => {
            try {
                const r = await fetch('/api/get/domainobject', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ searchbase: dn, properties: ['displayName','name','title','distinguishedName'], search_scope: 'BASE' })
                });
                await handleHttpError(r);
                if (!r.ok) return null;
                const j = await r.json();
                const entry = Array.isArray(j) ? j[0] : j;
                const a = (entry && entry.attributes) ? entry.attributes : {};
                const displayNameVal = Array.isArray(a.displayName) ? a.displayName[0] : a.displayName;
                const nameVal = Array.isArray(a.name) ? a.name[0] : a.name;
                const n = displayNameVal || nameVal || '';
                const t = Array.isArray(a.title) ? a.title[0] : (a.title || '');
                const initial = (n || '?').toString().charAt(0).toUpperCase();
                const escDn = dn.replace(/'/g, "\\'");
                const delay = Math.min(i * 60, 480);
                const nameAttr = (n || '').toString().replace(/"/g, '&quot;');
                const titleAttr = (t || '').toString().replace(/"/g, '&quot;');
                return `
                    <div class="border border-neutral-200 dark:border-neutral-700 rounded-md p-4 bg-white dark:bg-neutral-900 org-card fade-in-up transition transform hover:-translate-y-0.5" style="animation-delay: ${delay}ms">
                        <div class="flex items-center gap-3">
                            <div class="w-10 h-10 rounded-full bg-neutral-200 dark:bg-neutral-700 flex items-center justify-center text-sm font-semibold text-neutral-700 dark:text-neutral-200">${initial}</div>
                            <div class="min-w-0">
                                <div class="text-sm font-medium text-neutral-900 dark:text-white truncate" title="${nameAttr}">${n || 'User'}</div>
                                <div class="text-xs text-neutral-600 dark:text-neutral-300 truncate" title="${titleAttr}">${t || ''}</div>
                                <a href="#" class="text-xs text-blue-600 dark:text-yellow-500 hover:underline block mt-1" onclick="handleLdapLinkClick(event, '${escDn}')">View profile</a>
                            </div>
                        </div>
                    </div>`;
            } catch { return null; }
        }));

        peersGrid.innerHTML = cards.filter(Boolean).join('') || '<div class="text-sm text-neutral-500">No peers found</div>';
    } catch (e) {
        console.error('Error loading organization section:', e);
    }
}

// Contact and Organization tabs removed

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
async function addDomainObjectAcl(targetIdentity, principalIdentity, rights, aceType, inheritance, refreshCallback = null) {
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
            
            // If a refresh callback is provided, use it
            if (refreshCallback) {
                await refreshCallback();
            } else {
                // Default modal refresh behavior
                const identity = document.querySelector('#ldap-attributes-modal h3')?.textContent;
                if (identity) {
                    await selectModalTab('dacl');
                    await fetchAndDisplayModalDacl(identity, true);
                }
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
    showModalContentSpinner();
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
        hideModalContentSpinner();
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
    
    showModalContentSpinner();
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
        hideModalContentSpinner();
    }
}

async function fetchAndDisplayModalTasklist(dnsHostname) {
    showModalContentSpinner();
    try {
        const response = await fetch('/api/computer/tasklist', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                computer: dnsHostname
            })
        });

        await handleHttpError(response);
        const tasklist = await response.json();
        console.log(tasklist);
        updateModalTasklistContent(tasklist);
    } catch (error) {
        console.error('Error fetching tasklist data:', error);
        showErrorAlert('Failed to fetch tasklist');
    } finally {
        hideModalContentSpinner();
    }
}

function updateModalTasklistContent(tasklist) {
    const tbody = document.getElementById('tasklist-rows');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!tasklist || !Array.isArray(tasklist) || tasklist.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="px-3 py-4 text-center text-neutral-500 dark:text-neutral-400">
                    No processes found or access denied
                </td>
            </tr>
        `;
        return;
    }
    tasklist.forEach(proc => {
        const a = proc.attributes || {};
        const row = document.createElement('tr');
        row.classList.add('h-8','result-item','hover:bg-neutral-50','dark:hover:bg-neutral-800','border-b','border-neutral-200','dark:border-neutral-700','dark:text-neutral-200','text-neutral-600');
        row.innerHTML = `
            <td class="px-3 py-2">${a.PID ?? ''}</td>
            <td class="px-3 py-2">${a.ImageName ?? ''}</td>
            <td class="px-3 py-2">${a.SessionName ?? ''} (${a.SessionID ?? ''})</td>
            <td class="px-3 py-2">${a.SessionUser ?? ''}</td>
            <td class="px-3 py-2">${a.State ?? ''}</td>
            <td class="px-3 py-2">${a.MemUsage ?? ''}</td>
        `;
        tbody.appendChild(row);
    });
}

function updateModalSessionsContent(sessionsData) {
    const sessionsRows = document.getElementById('sessions-rows');
    if (!sessionsRows) return;

    sessionsRows.innerHTML = '';

    if (!sessionsData || !Array.isArray(sessionsData) || sessionsData.length === 0) {
        sessionsRows.innerHTML = `
            <tr>
                <td colspan="5" class="px-3 py-4 text-center text-neutral-500 dark:text-neutral-400">
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
        const clientIP = attrs.IP ? attrs.IP.replace(/\\/g, '') : '';
        const computer = attrs.Computer || '';
        const username = attrs.Username || '';
        
        row.innerHTML = `
            <td class="px-3 py-2">${username}</td>
            <td class="px-3 py-2">${clientIP}</td>
            <td class="px-3 py-2">${attrs['Time Active'] || ''}</td>
            <td class="px-3 py-2">${attrs['Idle Time'] || ''}</td>
            <td class="px-3 py-2 text-right">
                <button onclick="removeNetSession('${computer}', '${username}')" 
                    class="text-red-600 hover:text-red-700 dark:text-red-500 dark:hover:text-red-400 p-1 rounded-md hover:bg-red-50 dark:hover:bg-red-950/50 transition-colors"
                    title="Remove Session for ${username}">
                    <i class="fas fa-times"></i>
                </button>
            </td>
        `;

        sessionsRows.appendChild(row);
    });
}

async function removeNetSession(computer, targetSession) {
    if (!computer || !targetSession) {
        showErrorAlert('Computer and target session (username) are required');
        return;
    }

    try {
        showLoadingIndicator();
        
        const response = await fetch('/api/remove/netsession', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                computer: computer,
                target_session: targetSession
            })
        });

        await handleHttpError(response);
        const result = await response.json();

        if (result === true || (result && result.status === 'success')) {
            showSuccessAlert(`Session for user ${targetSession} removed successfully from ${computer}`);
            
            // Refresh the sessions list
            const modal = document.getElementById('ldap-attributes-modal');
            const dnsHostnameInput = modal.querySelector('#dNSHostName-wrapper input');
            const dnsHostname = dnsHostnameInput?.value;
            if (dnsHostname) {
                await fetchAndDisplayModalSessions(dnsHostname);
            }
        } else {
            showErrorAlert('Failed to remove session');
        }
    } catch (error) {
        console.error('Error removing session:', error);
        showErrorAlert(`Failed to remove session: ${error.message}`);
    } finally {
        hideLoadingIndicator();
    }
}

async function fetchAndDisplayModalLogonUsers(dnsHostname) {
    showModalContentSpinner();
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
        hideModalContentSpinner();
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

async function getObjectOwner(identity) {
    try {
        showModalContentSpinner();
        const response = await fetch('/api/get/domainobjectowner', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                identity: identity,
                searchbase: identity,
                search_scope: 'BASE'
            })
        });

        await handleHttpError(response);
        const data = await response.json();
        
        if (data && data.length > 0) {
            const ownerInfo = data[0].attributes.Owner;
            displayOwnerInfo(ownerInfo);
        } else {
            showErrorAlert(`No owner information found for ${identity}`);
        }
    } catch (error) {
        console.error('Error fetching owner information:', error);
        showErrorAlert('Failed to fetch owner information');
    } finally {
        hideModalContentSpinner();
    }
}

function displayOwnerInfo(ownerInfo) {
    const container = document.getElementById('owner-info');
    if (!container) return;

    container.innerHTML = `
        <div class="flex items-center gap-4">
            <div class="flex-1">
                <div class="text-sm font-medium text-neutral-900 dark:text-white">Current Owner</div>
                <div class="mt-1 text-sm text-neutral-600 dark:text-neutral-400">${ownerInfo}</div>
            </div>
        </div>
    `;

    const changeOwnerButton = document.getElementById('change-owner-button');
    if (changeOwnerButton) {
        changeOwnerButton.addEventListener('click', (event) => {
            event.stopPropagation();
            const identity = document.querySelector('#ldap-attributes-modal h3')?.textContent;
            if (identity) {
                openChangeOwnerModal(identity);
            }
        });
    }
}

function openChangeOwnerModal(identity) {
    const modal = document.getElementById('change-owner-modal');
    const overlay = document.getElementById('modal-overlay');
    modal.classList.remove('hidden');
    overlay.classList.remove('hidden');

    const identityInput = document.getElementById('owner-identity-input');
    identityInput.value = identity;

    const form = document.getElementById('change-owner-form');
    form.onsubmit = async (e) => {
        e.preventDefault();
        const newOwner = document.getElementById('new-owner-input').value;

        const success = await changeOwner(identity, newOwner);
        if (success) {
            hideModal('change-owner-modal');
            await getObjectOwner(identity);
        }
    };
}

async function changeOwner(targetIdentity, principalIdentity) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/set/domainobjectowner', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                targetidentity: targetIdentity,
                principalidentity: principalIdentity
            })
        });

        await handleHttpError(response);
        const result = await response.json();

        if (result === false) {
            showErrorAlert("Failed to change owner. Check logs");
            return false;
        }

        showSuccessAlert("Owner changed successfully");
        return true;
    } catch (error) {
        console.error('Error changing owner:', error);
        showErrorAlert("Failed to change owner. Check logs");
        return false;
    } finally {
        hideLoadingIndicator();
    }
}

async function connectToSMB(data) {
    const response = await fetch('/api/smb/connect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to connect to SMB share');
    }

    return response.json();
}

async function listSMBShares(computer) {
    try {
        const response = await fetch('/api/smb/shares', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list SMB shares');
        }

        return await response.json();
    } catch (error) {
        showErrorAlert(error.message);
        throw error;
    }
}

async function listSMBPath(computer, share, path = '') {
    try {
        const response = await fetch('/api/smb/ls', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list SMB path');
        }

        return await response.json();
    } catch (error) {
        showErrorAlert(error.message);
        throw error;
    }
}

function buildSMBTreeView(shares) {
    let html = '<ul class="space-y-1">';
    shares.forEach(share => {
        const shareName = share.attributes.Name;
        html += `
            <li class="smb-tree-item" data-share="${shareName}">
                <div class="flex items-center gap-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer">
                    <span class="text-yellow-500">${getFileIcon('', true).icon}</span>
                    <span>${shareName}</span>
                    <span class="text-xs text-neutral-500">${share.attributes.Remark}</span>
                </div>
                <ul class="ml-6 space-y-1 hidden"></ul>
            </li>
        `;
    });
    html += '</ul>';
    return html;
}

function attachTreeViewListeners(computer) {
    document.querySelectorAll('.smb-tree-item').forEach(item => {
        const shareDiv = item.querySelector('div');
        const subList = item.querySelector('ul');
        let isLoaded = false;

        shareDiv.onclick = async () => {
            const share = item.dataset.share;
            
            if (!isLoaded) {
                try {
                    showLoadingIndicator();
                    const files = await listSMBPath(computer, share);
                    subList.innerHTML = buildFileList(files, share);
                    isLoaded = true;
                    subList.classList.remove('hidden');
                    attachFileListeners(computer, share);
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    hideLoadingIndicator();
                }
            } else {
                subList.classList.toggle('hidden');
            }
        };
    });
}

function attachFileListeners(computer, share) {
    document.querySelectorAll('.file-item').forEach(item => {
        const fileDiv = item.querySelector('div');
        const subList = item.querySelector('ul');
        const isDirectory = item.getAttribute('data-is-dir') === '16' || item.getAttribute('data-is-dir') === '48';

        if (isDirectory) {
            fileDiv.onclick = async () => {
                if (!subList.classList.contains('hidden') || subList.children.length > 0) {
                    subList.classList.toggle('hidden');
                    return;
                }

                try {
                    showLoadingIndicator();
                    const currentPath = item.dataset.path;
                    const cleanPath = currentPath.replace(/^\//, '').replace(/\//g, '\\');
                    const files = await listSMBPath(computer, share, cleanPath);
                    subList.innerHTML = buildFileList(files, share, currentPath);
                    subList.classList.remove('hidden');

                    attachFileListeners(computer, share);
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    hideLoadingIndicator();
                }
            };
        }
    });
}

async function downloadSMBFile(computer, share, path) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/smb/get', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to download file');
        }

        // Get the filename from the path
        const filename = path.split('\\').pop();

        // Create a blob from the response
        const blob = await response.blob();
        
        // Create a temporary link to trigger the download
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        
        // Cleanup
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

    } catch (error) {
        showErrorAlert(error.message);
        throw error;
    } finally {
        hideLoadingIndicator();
    }
}

// Update buildFileList to use getFileIcon
function buildFileList(files, share, currentPath = '') {
    let html = '';
    files.forEach(file => {
        const isDirectory = file.is_directory;
        const fileIcon = getFileIcon(file.name, isDirectory);
        const computerInput = document.getElementById('smb-computer');
        
        html += `
            <li class="file-item" data-path="${currentPath}/${file.name}" data-is-dir="${file.is_directory ? '16' : '0'}">
                <div class="flex items-center justify-between gap-1 hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer">
                    <div class="flex items-center gap-1">
                        <span class="${isDirectory ? 'text-yellow-500' : 'text-neutral-400'}">${fileIcon.icon}</span>
                        <span>${file.name}</span>
                        <span class="text-xs text-neutral-500">${formatFileSize(file.size)}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        ${isDirectory ? `
                            <button onclick="event.stopPropagation(); uploadSMBFile('${computerInput.value}', '${share}', '${currentPath}/${file.name}')"
                                class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300">
                                <i class="fas fa-upload"></i>
                            </button>
                        ` : `
                            <button onclick="event.stopPropagation(); downloadSMBFile('${computerInput.value}', '${share}', '${currentPath}/${file.name}')" 
                                class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300">
                                <i class="fas fa-download"></i>
                            </button>
                        `}
                    </div>
                </div>
                ${isDirectory ? '<ul class="ml-6 space-y-1 hidden"></ul>' : ''}
            </li>
        `;
    });
    return html;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add file upload functionality
async function uploadSMBFile(computer, share, currentPath) {
    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    fileInput.onchange = async function() {
        if (!this.files || !this.files[0]) return;

        try {
            showLoadingIndicator();
            const formData = new FormData();
            formData.append('file', this.files[0]);
            formData.append('computer', computer);
            formData.append('share', share);
            formData.append('path', currentPath);

            const response = await fetch('/api/smb/put', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to upload file');
            }

            // Refresh the current directory listing
            const files = await listSMBPath(computer, share, currentPath);
            const parentList = document.querySelector(`[data-path="${currentPath}"]`).parentElement;
            parentList.innerHTML = buildFileList(files, share, currentPath);
            attachFileListeners(computer, share);
            
            showSuccessAlert('File uploaded successfully');

        } catch (error) {
            showErrorAlert(error.message);
            console.error('Upload error:', error);
        } finally {
            hideLoadingIndicator();
            document.body.removeChild(fileInput);
        }
    };

    fileInput.click();
}

// Add this to your fetchAndDisplayModalServices function where you populate the services
function updateServicesCount(services) {
    const countElement = document.getElementById('services-count');
    if (countElement) {
        countElement.textContent = services.length;
    }
}

function filterServicesByStatus(tbody, statusFilter) {
    const rows = tbody.querySelectorAll('tr:not(.details-row)');
    rows.forEach(row => {
        const statusCell = row.querySelector('td:nth-child(3)');
        if (!statusCell) return;
        
        const status = statusCell.textContent.trim();
        const detailsRow = row.nextElementSibling;
        
        if (statusFilter === 'ALL' || status === statusFilter) {
            row.style.display = '';
            if (detailsRow && detailsRow.classList.contains('details-row')) {
                detailsRow.style.display = '';
            }
        } else {
            row.style.display = 'none';
            if (detailsRow && detailsRow.classList.contains('details-row')) {
                detailsRow.style.display = 'none';
            }
        }
    });
}

// Update your existing fetchAndDisplayModalServices function
async function fetchAndDisplayModalServices(computer) {
    try {
        showModalContentSpinner();
        const response = await fetch('/api/get/netservice', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                computer_name: computer
            })
        });
        await handleHttpError(response);
        const data = await response.json();

        updateServicesCount(data);
        
        const tbody = document.getElementById('services-rows');
        tbody.innerHTML = '';

        const statusFilter = document.getElementById('service-status-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', (e) => {
                filterServicesByStatus(tbody, e.target.value);
            });
        }

        data.forEach(service => {
            // Create main row
            const row = document.createElement('tr');
            row.className = 'hover:bg-neutral-50 dark:hover:bg-neutral-800 border-b border-neutral-200 dark:border-neutral-700';

            // Handle the status styling
            let status = service.attributes.Status.replace(/\u001b\[\d+m/g, ''); // Remove ANSI codes
            let badgeClass = 'bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300';
            let dotClass = 'bg-neutral-500';
            if (status === 'RUNNING') {
                badgeClass = 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
                dotClass = 'bg-green-600';
            } else if (status === 'STOPPED') {
                badgeClass = 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
                dotClass = 'bg-red-600';
            } else if (status.includes('PENDING')) {
                badgeClass = 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300';
                dotClass = 'bg-yellow-500';
            }
            const statusBadgeHtml = `<span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs ${badgeClass}"><span class="inline-block w-1.5 h-1.5 rounded-full ${dotClass}"></span>${status}</span>`;

            row.innerHTML = `
                <td class="px-3 py-2">
                    <div class="flex items-center gap-2">
                        <div class="w-7 h-7 rounded-md bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center text-neutral-500">
                            <i class="fas fa-cog"></i>
                        </div>
                        <div class="min-w-0">
                            <div class="text-sm font-medium text-neutral-900 dark:text-neutral-100 truncate">${service.attributes.Name}</div>
                            <div class="text-xs text-neutral-500 dark:text-neutral-400 sm:hidden truncate">${service.attributes.DisplayName || ''}</div>
                        </div>
                    </div>
                </td>
                <td class="px-3 py-2 text-neutral-600 dark:text-neutral-300 hidden sm:table-cell">${service.attributes.DisplayName}</td>
                <td class="px-3 py-2">${statusBadgeHtml}</td>
                <td class="px-3 py-2 text-right">
                    <div class="flex justify-end gap-1.5">
                        <button class="start-service-button ${status === 'RUNNING' ? 'hidden' : ''} text-green-600 hover:text-green-700 dark:text-green-400 dark:hover:text-green-300 p-1.5 rounded-md hover:bg-green-50 dark:hover:bg-green-900/20" title="Start Service">
                            <i class="fas fa-play"></i>
                        </button>
                        <button class="stop-service-button ${status !== 'RUNNING' ? 'hidden' : ''} text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 p-1.5 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20" title="Stop Service">
                            <i class="fas fa-stop"></i>
                        </button>
                        <button class="info-button text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 p-1.5 rounded-md hover:bg-blue-50 dark:hover:bg-blue-900/20" title="Details">
                            <i class="fas fa-info-circle"></i>
                        </button>
                        <button class="delete-service-button text-neutral-600 hover:text-red-700 dark:text-neutral-400 dark:hover:text-red-400 p-1.5 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20" title="Delete Service">
                            <i class="fas fa-trash-alt"></i>
                        </button>
                    </div>
                </td>
            `;
            tbody.appendChild(row);

            // Create details row (hidden by default)
            const detailsRow = document.createElement('tr');
            detailsRow.className = 'hidden bg-neutral-50 dark:bg-neutral-800/50';
            detailsRow.innerHTML = `
                <td colspan="4" class="px-3 py-2">
                    <div class="animate-fade-in">
                        <div class="flex items-center gap-2 text-neutral-500 dark:text-neutral-400">
                            <div class="w-4 h-4 animate-spin"><i class="fas fa-circle-notch"></i></div>
                            <span class="text-xs">Loading service details...</span>
                        </div>
                    </div>
                </td>
            `;
            tbody.appendChild(detailsRow);

            const stopButton = row.querySelector('.stop-service-button');
            stopButton.addEventListener('click', async () => {
                try {
                    showModalContentSpinner();
                    const response = await fetch('/api/stop/netservice', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            computer_name: computer,
                            service_name: service.attributes.Name
                        })
                    });

                    await handleHttpError(response);
                    showSuccessAlert('Service stopped successfully');
                    
                    // Refresh the services list
                    await fetchAndDisplayModalServices(computer);
                } catch (error) {
                    console.error('Error stopping service:', error);
                    showErrorAlert(error.message || 'Failed to stop service');
                } finally {
                    hideModalContentSpinner();
                }
            });

            const startButton = row.querySelector('.start-service-button');
            startButton.addEventListener('click', async () => {
                try {
                    showModalContentSpinner();
                    const response = await fetch('/api/start/netservice', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify({
                            computer_name: computer,
                            service_name: service.attributes.Name
                        })
                    });

                    await handleHttpError(response);
                    showSuccessAlert('Service started successfully');
                    
                    // Refresh the services list
                    await fetchAndDisplayModalServices(computer);
                } catch (error) {
                    console.error('Error starting service:', error);
                    showErrorAlert(error.message || 'Failed to start service');
                } finally {
                    hideModalContentSpinner();
                }
            });

            // Add delete button handler
            const deleteButton = row.querySelector('.delete-service-button');
            deleteButton.addEventListener('click', async () => {
                if (confirm(`Are you sure you want to delete the service "${service.attributes.Name}"?`)) {
                    try {
                        showLoadingIndicator();
                        const response = await fetch('/api/remove/netservice', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                computer_name: computer,
                                service_name: service.attributes.Name
                            })
                        });

                        await handleHttpError(response);
                        showSuccessAlert('Service deleted successfully');
                        
                        // Refresh the services list
                        await fetchAndDisplayModalServices(computer);
                    } catch (error) {
                        console.error('Error deleting service:', error);
                        showErrorAlert(error.message || 'Failed to delete service');
                    } finally {
                        hideModalContentSpinner();
                    }
                }
            });

            // Add click handler for info button
            const infoButton = row.querySelector('.info-button');
            infoButton.addEventListener('click', async () => {
                detailsRow.classList.toggle('hidden');
                
                // Only fetch details if we're showing the row and haven't loaded them before
                if (!detailsRow.classList.contains('hidden') && !detailsRow.dataset.loaded) {
                    try {
                        const detailsResponse = await fetch('/api/get/netservice', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ 
                                computer_name: computer,
                                name: service.attributes.Name,
                                raw: true
                            })
                        });

                        await handleHttpError(detailsResponse);
                        const serviceDetails = await detailsResponse.json();
                        
                        if (serviceDetails && serviceDetails[0]) {
                            const details = serviceDetails[0].attributes;
                            detailsRow.innerHTML = `
                                <td colspan="4" class="px-3 py-3">
                                    <form class="service-edit-form">
                                        <div class="animate-fade-in space-y-4">
                                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Service Name</p>
                                                    <input type="text" class="service-name-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white" value="${details.ServiceName}" readonly>
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Display Name</p>
                                                    <input type="text" class="display-name-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white" value="${details.DisplayName}">
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Binary Path</p>
                                                    <input type="text" class="binary-path-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white" value="${details.BinaryPath?.replace('\u0000', '') || ''}">
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Service Type</p>
                                                    <select class="service-type-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white">
                                                        <option value="1" ${details.ServiceType === 1 ? 'selected' : ''}>Kernel Driver</option>
                                                        <option value="2" ${details.ServiceType === 2 ? 'selected' : ''}>File System Driver</option>
                                                        <option value="4" ${details.ServiceType === 4 ? 'selected' : ''}>Adapter</option>
                                                        <option value="8" ${details.ServiceType === 8 ? 'selected' : ''}>Recognizer Driver</option>
                                                        <option value="16" ${details.ServiceType === 16 ? 'selected' : ''}>Win32 Own Process</option>
                                                        <option value="32" ${details.ServiceType === 32 ? 'selected' : ''}>Win32 Share Process</option>
                                                        <option value="256" ${details.ServiceType === 256 ? 'selected' : ''}>Interactive Process</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Start Type</p>
                                                    <select class="start-type-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white">
                                                        <option value="0" ${details.StartType === 0 ? 'selected' : ''}>Boot Start</option>
                                                        <option value="1" ${details.StartType === 1 ? 'selected' : ''}>System Start</option>
                                                        <option value="2" ${details.StartType === 2 ? 'selected' : ''}>Automatic</option>
                                                        <option value="2-delayed">Automatic (Delayed Start)</option>
                                                        <option value="3" ${details.StartType === 3 ? 'selected' : ''}>Manual</option>
                                                        <option value="4" ${details.StartType === 4 ? 'selected' : ''}>Disabled</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Error Control</p>
                                                    <select class="error-control-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white">
                                                        <option value="0" ${details.ErrorControl === 0 ? 'selected' : ''}>Ignore</option>
                                                        <option value="1" ${details.ErrorControl === 1 ? 'selected' : ''}>Normal</option>
                                                        <option value="2" ${details.ErrorControl === 2 ? 'selected' : ''}>Severe</option>
                                                        <option value="3" ${details.ErrorControl === 3 ? 'selected' : ''}>Critical</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Service Start Name</p>
                                                    <input type="text" class="service-start-name-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white" value="${details.ServiceStartName || ''}">
                                                </div>
                                                <div>
                                                    <p class="font-medium text-neutral-700 dark:text-neutral-200">Dependencies</p>
                                                    <input type="text" class="dependencies-input mt-1 w-full px-2 py-1 text-sm bg-white dark:bg-neutral-700 border border-neutral-300 dark:border-neutral-600 rounded text-neutral-900 dark:text-white" value="${details.Dependencies || ''}" readonly>
                                                </div>
                                            </div>
                                            <div class="flex justify-end gap-2 pt-2">
                                                <button type="submit" class="px-3 py-1.5 text-sm font-medium text-white bg-neutral-900 hover:bg-neutral-800 dark:bg-yellow-500 dark:hover:bg-yellow-600 dark:text-black rounded">
                                                    Save Changes
                                                </button>
                                            </div>
                                        </div>
                                    </form>
                                </td>
                            `;
                            detailsRow.dataset.loaded = 'true';

                            // Add form submit handler
                            detailsRow.querySelector('.service-edit-form').onsubmit = async (e) => {
                                e.preventDefault();
                                await updateServiceConfig(computer,
                                    details.ServiceName,
                                    detailsRow.querySelector('.display-name-input').value,
                                    detailsRow.querySelector('.binary-path-input').value,
                                    detailsRow.querySelector('.service-type-input').value,
                                    detailsRow.querySelector('.start-type-input').value,
                                    detailsRow.querySelector('.error-control-input').value,
                                    detailsRow.querySelector('.service-start-name-input').value
                                );
                                await fetchAndDisplayModalServices(computer);
                            };
                        }
                    } catch (error) {
                        console.error('Error fetching service details:', error);
                        detailsRow.innerHTML = `
                            <td colspan="4" class="px-3 py-2 text-red-500 dark:text-red-400">
                                Failed to load service details
                            </td>
                        `;
                    }
                }
            });
        });
    } catch (error) {
    } finally {
        hideModalContentSpinner();
    }
}

async function updateServiceConfig(computer, serviceName, displayName, binaryPath, serviceType, startType, errorControl, serviceStartName) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/set/netservice', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                computer_name: computer,
                service_name: serviceName,
                display_name: displayName,
                binary_path: binaryPath,
                service_type: parseInt(serviceType),
                start_type: parseInt((startType || '').toString().replace('-delayed','')),
                delayed_start: (startType || '').toString().includes('-delayed'),
                error_control: parseInt(errorControl),
                service_start_name: serviceStartName
            })
        });

        await handleHttpError(response);
        showSuccessAlert('Service updated successfully');
    } catch (error) {
        console.error('Error updating service:', error);
        showErrorAlert('Failed to update service');
    } finally {
        hideLoadingIndicator();
    }
}

function getFileIcon(fileName, isDirectory, isExpanded=false) {
    if (isDirectory) {
        return {
            icon: isExpanded ? icons.folderOpenedIcon : icons.folderIcon,
            iconClass: '', // Folders typically don't need specific coloring here
            isCustomSvg: true
        };
    }

    const fileExt = fileName.toLowerCase().substring(fileName.lastIndexOf('.'));
    let details = {
        icon: icons.unknownFileIcon,
        iconClass: 'text-neutral-500 dark:text-neutral-400', // Default color
        isCustomSvg: true
    };

    // Group extensions by type for easier color assignment
    const executableExtensions = ['.exe', '.msi', '.bat', '.cmd', '.com', '.scr'];
    const scriptExtensions = ['.ps1', '.sh', '.py', '.js', '.vbs', '.vba']; // Added
    const excelExtensions = ['.xlsx', '.xls', '.xlsm', '.xlsb', '.xltx', '.xltm', '.xlt', '.csv'];
    const registryExtensions = ['.reg', '.regx'];
    const wordExtensions = ['.docx', '.doc', '.docm', '.dotx', '.dotm', '.dot'];
    const textExtensions = ['.txt', '.log', '.ini', '.cfg', '.conf', '.text', '.md', '.yaml', '.yml', '.json', '.xml']; // Added more
    const dllExtensions = ['.dll', '.sys', '.drv', '.ocx', '.so', '.dylib']; // Added more system libs
    const outlookExtensions = ['.pst', '.ost', '.msg', '.eml', '.nst', '.oft'];
    const powerpointExtensions = ['.ppt', '.pptx', '.pptm', '.potx', '.potm', '.ppsx', '.ppsm'];
    const compressedExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.xz', '.cab'];
    const pdfExtensions = ['.pdf'];
    const certificateExtensions = ['.pfx', '.p12', '.der', '.cer', '.crt', '.p7b', '.p7c', '.pem', '.key'];
    const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg', '.tif', '.tiff', '.ico']; // Added more
    const audioExtensions = ['.mp3', '.wav', '.ogg', '.aac', '.flac', '.m4a']; // Added
    const videoExtensions = ['.mp4', '.mov', '.avi', '.mkv', '.webm', '.wmv']; // Added
    const diskImageExtensions = ['.iso', '.img', '.vhd', '.vhdx']; // Added

    if (executableExtensions.includes(fileExt)) {
        details = { icon: icons.executableIcon, iconClass: 'text-red-500 dark:text-red-400', isCustomSvg: true };
    } else if (scriptExtensions.includes(fileExt)) {
        // Using txtIcon as a stand-in for generic code/script icon, color it differently
        details = { icon: icons.txtIcon, iconClass: 'text-blue-500 dark:text-blue-400', isCustomSvg: true }; 
    } else if (excelExtensions.includes(fileExt)) {
        details = { icon: icons.xlsxIcon, iconClass: 'text-green-600 dark:text-green-500', isCustomSvg: true };
    } else if (registryExtensions.includes(fileExt)) {
        details = { icon: icons.registryIcon, iconClass: 'text-cyan-600 dark:text-cyan-500', isCustomSvg: true };
    } else if (wordExtensions.includes(fileExt)) {
        details = { icon: icons.docxIcon, iconClass: 'text-blue-600 dark:text-blue-500', isCustomSvg: true };
    } else if (textExtensions.includes(fileExt)) {
        details = { icon: icons.txtIcon, iconClass: 'text-gray-600 dark:text-gray-400', isCustomSvg: true };
    } else if (dllExtensions.includes(fileExt)) {
        details = { icon: icons.dllIcon, iconClass: 'text-teal-500 dark:text-teal-400', isCustomSvg: true };
    } else if (outlookExtensions.includes(fileExt)) {
        details = { icon: icons.outlookIcon, iconClass: 'text-sky-600 dark:text-sky-500', isCustomSvg: true };
    } else if (powerpointExtensions.includes(fileExt)) {
        details = { icon: icons.powerpointIcon, iconClass: 'text-orange-600 dark:text-orange-500', isCustomSvg: true };
    } else if (compressedExtensions.includes(fileExt)) {
        details = { icon: icons.zipIcon, iconClass: 'text-amber-600 dark:text-amber-500', isCustomSvg: true };
    } else if (pdfExtensions.includes(fileExt)) {
        details = { icon: icons.pdfIcon, iconClass: 'text-red-700 dark:text-red-600', isCustomSvg: true };
    } else if (certificateExtensions.includes(fileExt)) {
        details = { icon: icons.certIcon, iconClass: 'text-lime-600 dark:text-lime-500', isCustomSvg: true };
    } else if (imageExtensions.includes(fileExt)) {
        // Using jpg/png icons as representative image icons
        details = { icon: (fileExt === '.png' ? icons.pngIcon : icons.jpgIcon), iconClass: 'text-purple-500 dark:text-purple-400', isCustomSvg: true };
    } else if (audioExtensions.includes(fileExt)) {
        // Using a default file icon, colored differently
        details = { icon: icons.unknownFileIcon, iconClass: 'text-pink-500 dark:text-pink-400', isCustomSvg: true }; 
    } else if (videoExtensions.includes(fileExt)) {
        // Using a default file icon, colored differently
        details = { icon: icons.unknownFileIcon, iconClass: 'text-indigo-500 dark:text-indigo-400', isCustomSvg: true }; 
    } else if (diskImageExtensions.includes(fileExt)) {
         // Using zipIcon as a stand-in, colored differently
        details = { icon: icons.zipIcon, iconClass: 'text-blue-400 dark:text-blue-300', isCustomSvg: true }; 
    }
    // Default case is handled by the initial `details` declaration

    return details;
}