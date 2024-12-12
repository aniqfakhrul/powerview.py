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

function handleLdapLinkClick(event) {
    event.preventDefault();
    const targetLink = event.currentTarget; // Use event.currentTarget to get the .ldap-link div itself
    const identity = targetLink.dataset.identity;
    const detailsPanel = document.getElementById('details-panel');
    const commandHistoryPanel = document.getElementById('command-history-panel');

    // Check if the details panel is already showing the clicked identity
    const currentDistinguishedName = detailsPanel.getAttribute('data-identity');

    if (currentDistinguishedName === identity) {
        // Toggle visibility if the same item is clicked again
        detailsPanel.classList.toggle('hidden');
        return;
    }

    // Fetch and populate details if a different item is clicked
    fetchItemData(identity, 'BASE').then(itemData => {
        if (itemData) {
            populateDetailsPanel(itemData);
            detailsPanel.setAttribute('data-identity', identity);
            detailsPanel.classList.remove('hidden');
            commandHistoryPanel.classList.add('hidden');    
        }
    });
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
    console.log(entries);
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
            const domainElement = profileMenu.querySelector('#connection-domain-display');
            const usernameElement = profileMenu.querySelector('#username-display');

            if (response.ok) {
                const data = await response.json();
                usernameElement.textContent = data.username;
                addressElement.textContent = `${data.protocol}://${data.ldap_address}`;
                domainElement.textContent = `${data.domain}`;
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
            const statusElement = document.getElementById('connection-status-display');
            const iconElement = document.querySelector('.fa-wifi');

            statusElement.textContent = 'Disconnected';
            statusElement.classList.remove('text-green-400');
            statusElement.classList.add('text-red-400');

            iconElement.classList.remove('text-green-400');
            iconElement.classList.add('text-red-400');

            console.error('Error checking connection status:', error);
        } finally {
            clearTimeout(timeoutId);
        }
    }

    checkConnectionStatus();
    setInterval(checkConnectionStatus, 300000);
});
