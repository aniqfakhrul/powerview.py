document.addEventListener('DOMContentLoaded', () => {
    let identityToDelete = null;
    let rowToDelete = null;

    async function fetchAndPopulateUsers() {
        try {
            const response = await fetch('/api/get/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    properties: ["cn", "sAMAccountname", "mail", "adminCount"]
                })
            });
            await handleHttpError(response);

            const users = await response.json();
            populateUsersTable(users);
        } catch (error) {
            console.error('Error fetching users:', error);
        }
    }

    function filterUsers() {
        const searchInput = document.getElementById('user-search').value.toLowerCase();
        const rows = document.querySelectorAll('tbody tr');

        rows.forEach(row => {
            const name = row.querySelector('td:nth-child(1)').textContent.toLowerCase();
            const email = row.querySelector('td:nth-child(2)').textContent.toLowerCase();

            if (name.includes(searchInput) || email.includes(searchInput)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    document.getElementById('user-search').addEventListener('input', filterUsers);

    function populateUsersTable(users) {
        const table = document.getElementById('users-result-table');
        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';

        if (users.length > 0) {
            // Get attribute keys from the first user to create table headers
            const attributeKeys = Object.keys(users[0].attributes);

            // Create table headers
            thead.innerHTML = ''; // Clear existing headers
            const headerRow = document.createElement('tr');
            attributeKeys.forEach(key => {
                const th = document.createElement('th');
                th.scope = 'col';
                th.className = 'p-1';
                th.textContent = key;
                headerRow.appendChild(th);
            });

            // Add an extra header for actions
            const actionTh = document.createElement('th');
            actionTh.scope = 'col';
            actionTh.className = 'p-1';
            actionTh.textContent = 'Action';
            headerRow.appendChild(actionTh);

            thead.appendChild(headerRow);

            // Populate table rows
            users.forEach(user => {
                const tr = document.createElement('tr');
                tr.classList.add('ldap-link', 'dark:hover:bg-white/5', 'dark:hover:text-white');
                tr.dataset.identity = user.dn;
                tr.onclick = (event) => handleLdapLinkClick(event);

                attributeKeys.forEach(key => {
                    const td = document.createElement('td');
                    td.className = 'p-1 whitespace-nowrap';
                    const value = user.attributes[key];
                    if (key === 'adminCount') {
                        const statusSpan = document.createElement('span');
                        if (value === 1) {
                            statusSpan.className = 'px-1 inline-flex text-xs leading-4 font-semibold rounded-md bg-green-100 text-green-800';
                            statusSpan.textContent = 'True';
                        } else {
                            statusSpan.textContent = '';
                        }
                        td.appendChild(statusSpan);
                    } else {
                        if (Array.isArray(value)) {
                            td.innerHTML = value.join('<br>');
                        } else {
                            td.textContent = value;
                        }
                    }
                    tr.appendChild(td);
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
                    showDeleteModal(user.attributes.cn, tr);
                });
                actionTd.appendChild(deleteButton);

                tr.appendChild(actionTd);

                tbody.appendChild(tr);
            });
        }
    }

    async function addUser(username, password) {
        try {
            const response = await fetch('/api/add/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ username, userpass: password })
            });

            await handleHttpError(response);

            const result = await response.json();
            console.log('User added:', result);

            // Refresh the user list
            fetchAndPopulateUsers();
        } catch (error) {
            console.error('Error adding user:', error);
        }
    }

    function showDeleteModal(username, rowElement) {
        identityToDelete = username;
        rowToDelete = rowElement;
        const modal = document.getElementById('popup-modal');
        const overlay = document.getElementById('modal-overlay');
        document.getElementById('identity-to-delete').textContent = username;
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
    }

    function showAddUserModal() {
        const modal = document.getElementById('add-user-modal');
        const overlay = document.getElementById('modal-overlay');
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
    }

    document.getElementById('confirm-delete').addEventListener('click', async () => {
        if (identityToDelete && rowToDelete) {
            await deleteUser(identityToDelete, rowToDelete);
            identityToDelete = null;
            rowToDelete = null;
            document.getElementById('popup-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
        }
    });

    // Add event listener for the close button
    document.querySelectorAll('[data-modal-hide]').forEach(button => {
        button.addEventListener('click', () => {
            const modalId = button.getAttribute('data-modal-hide');
            document.getElementById(modalId).classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
        });
    });

    // Add event listener for the Add User button
    document.querySelector('[data-modal-toggle="add-user-modal"]').addEventListener('click', showAddUserModal);

    document.getElementById('add-user-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const username = document.getElementById('new-username').value;
        const password = document.getElementById('new-password').value;
        addUser(username, password);
        document.getElementById('add-user-modal').classList.add('hidden');
        document.getElementById('modal-overlay').classList.add('hidden');
    });

    async function deleteUser(distinguishedName, rowElement) {
        try {
            const response = await fetch('/api/remove/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ identity: distinguishedName })
            });

            await handleHttpError(response);

            const result = await response.json();
            console.log('User deleted:', result);

            // Remove the row from the table
            rowElement.remove();
        } catch (error) {
            console.error('Error deleting user:', error);
        }
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

    function collectQueryParams() {
        // Default values for all parameters
        const defaultArgs = {
            identity: document.getElementById('identity-input').value || '',
            spn: false,
            admincount: false,
            lockout: false,
            password_expired: false,
            passnotrequired: false,
            rbcd: false,
            shadowcred: false,
            preauthnotrequired: false,
            trustedtoauth: false,
            allowdelegation: false,
            disallowdelegation: false,
            unconstrained: false,
            enabled: false,
            disabled: false,
            properties: [], // Initialize as empty, will be set by collectProperties
            ldapfilter: document.getElementById('ldap-filter-input').value || '',
            searchbase: document.getElementById('searchbase-input').value || ''
        };

        // Collect current values based on data-active attribute
        const currentArgs = {
            identity: document.getElementById('identity-input').value || '',
            spn: document.getElementById('spn-toggle').getAttribute('data-active') === 'true',
            trustedtoauth: document.getElementById('trusted-to-auth-toggle').getAttribute('data-active') === 'true',
            enabled: document.getElementById('enabled-users-toggle').getAttribute('data-active') === 'true',
            preauthnotrequired: document.getElementById('preauth-not-required-toggle').getAttribute('data-active') === 'true',
            passnotrequired: document.getElementById('pass-not-required-toggle').getAttribute('data-active') === 'true',
            admincount: document.getElementById('admin-count-toggle').getAttribute('data-active') === 'true',
            lockout: document.getElementById('lockout-toggle').getAttribute('data-active') === 'true',
            rbcd: document.getElementById('rbcd-toggle').getAttribute('data-active') === 'true',
            shadowcred: document.getElementById('shadow-cred-toggle').getAttribute('data-active') === 'true',
            unconstrained: document.getElementById('unconstrained-delegation-toggle').getAttribute('data-active') === 'true',
            disabled: document.getElementById('disabled-users-toggle').getAttribute('data-active') === 'true',
            password_expired: document.getElementById('password-expired-toggle').getAttribute('data-active') === 'true',
            ldapfilter: document.getElementById('ldap-filter-input').value || '',
            searchbase: document.getElementById('searchbase-input').value || '',
            properties: collectProperties() // Use collectProperties to set the properties
        };

        // Merge defaultArgs with currentArgs
        const args = { ...defaultArgs, ...currentArgs };

        return { args };
    }

    function collectProperties() {
        const properties = [];
        const propertyButtons = document.querySelectorAll('.custom-toggle-switch[data-active="true"]');
    
        propertyButtons.forEach(button => {
            const ldapAttribute = button.getAttribute('data-ldap-attribute');
            if (ldapAttribute) {
                properties.push(ldapAttribute);
            }
        });
    
        return properties;
    }

    async function searchUsers() {
        const searchSpinner = document.getElementById('search-spinner');
        const boxOverlaySpinner = document.getElementById('box-overlay-spinner');
        searchSpinner.classList.remove('hidden'); // Show the spinner
        boxOverlaySpinner.classList.remove('hidden'); // Show the spinner

        const queryParams = collectQueryParams();
        try {
            const response = await fetch('/api/get/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(queryParams)
            });

            await handleHttpError(response);

            const result = await response.json();
            populateUsersTable(result);
        } catch (error) {
            console.error('Error searching users:', error);
        } finally {
            searchSpinner.classList.add('hidden'); // Hide the spinner
            boxOverlaySpinner.classList.add('hidden'); // Hide the spinner
        }
    }

    // Attach event listener to the search button
    document.getElementById('search-users-button').addEventListener('click', searchUsers);

    // enable if you want to fetch users on page load
    // fetchAndPopulateUsers();
});
