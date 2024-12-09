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
    showLoadingIndicator();
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
        hideLoadingIndicator();
    }
}


function showLoadingIndicator() {
    const spinner = document.getElementById("loading-spinner");
    if (spinner) {
        spinner.removeAttribute('hidden');
    }
}

function hideLoadingIndicator() {
    const spinner = document.getElementById("loading-spinner");
    if (spinner) {
        spinner.setAttribute('hidden', true);
    }
}

function isValidDistinguishedName(value) {
    const dnPattern = /^(CN|OU|DC)=/i; // Simple pattern to identify a DN
    return dnPattern.test(value);
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
            const usernameElement = profileMenu.querySelector('#username-display');
            const iconElement = profileMenu.querySelector('.fa-wifi');

            if (response.ok) {
                const data = await response.json();
                usernameElement.textContent = data.username.split('\\')[1];
                if (data.status === 'OK') {
                    statusElement.textContent = 'Connected';
                    statusElement.classList.remove('text-red-400');
                    statusElement.classList.add('text-green-400');

                    iconElement.classList.remove('text-red-400');
                    iconElement.classList.add('text-green-400');
                } else {
                    statusElement.textContent = 'Disconnected';
                    statusElement.classList.remove('text-green-400');
                    statusElement.classList.add('text-red-400');

                    iconElement.classList.remove('text-green-400');
                    iconElement.classList.add('text-red-400');
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