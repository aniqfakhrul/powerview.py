document.addEventListener('DOMContentLoaded', () => {
    const activeFilters = new Set();
    const defaultProperties = ['name', 'sAMAccountName', 'mail'];
    let identityToDelete = null;
    let rowToDelete = null;
    let allOUs = [];
    let searchBaseDropdownVisible = false;

    initializePropertyFilter(defaultProperties);
    initializeQueryTemplates();
    initializeDeleteHandlers();
    initializeSearchBase();

    function initializeQueryTemplates() {
        const dropdownButton = document.getElementById('user-filter-dropdown-button');
        const dropdownMenu = document.getElementById('user-filter-dropdown-menu');
        const selectedFilters = document.getElementById('selected-user-filters');
        const searchButton = document.getElementById('user-search-button');

        dropdownButton.addEventListener('click', () => {
            dropdownMenu.classList.toggle('hidden');
        });

        document.addEventListener('click', (event) => {
            if (!dropdownButton.contains(event.target) && !dropdownMenu.contains(event.target)) {
                dropdownMenu.classList.add('hidden');
            }
        });

        dropdownMenu.querySelectorAll('button').forEach(button => {
            button.addEventListener('click', () => {
                const filter = button.dataset.filter;
                if (!activeFilters.has(filter)) {
                    activeFilters.add(filter);
                    renderActiveFilters();
                }
                dropdownMenu.classList.add('hidden');
            });
        });

        searchButton.addEventListener('click', searchUsers);
    }

    function renderActiveFilters() {
        const container = document.getElementById('selected-user-filters');
        container.innerHTML = Array.from(activeFilters).map(filter => `
            <span class="px-2 py-1 bg-neutral-100 dark:bg-neutral-800 rounded-md text-sm flex items-center gap-1">
                ${filter}
                <button class="hover:text-red-500" onclick="removeFilter('${filter}')">
                    <i class="fas fa-times fa-xs"></i>
                </button>
            </span>
        `).join('');
    }

    window.removeFilter = (filter) => {
        activeFilters.delete(filter);
        renderActiveFilters();
    };

    function initializePropertyFilter(initialProperties) {
        const selectedProperties = [...initialProperties];
        const container = document.getElementById('user-properties');
        const newPropertyInput = document.getElementById('new-user-property');
        
        if (!container || !newPropertyInput) {
            console.error('Required elements not found');
            return;
        }

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
            if (selectedProperties.length <= 1) {
                showErrorAlert('At least one property must be selected');
                return;
            }
            const index = selectedProperties.indexOf(prop);
            if (index > -1) {
                selectedProperties.splice(index, 1);
                renderProperties();
            }
        };

        newPropertyInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const newProp = e.target.value.trim();
                if (!newProp) return;
                
                if (selectedProperties.includes(newProp)) {
                    showErrorAlert('Property already exists');
                    return;
                }

                selectedProperties.push(newProp);
                renderProperties();
                e.target.value = '';
            }
        });

        renderProperties();
    }

    function getActiveFilters() {
        const filters = {};
        activeFilters.forEach(filter => {
            filters[filter] = true;
        });
        return filters;
    }

    function getSelectedProperties() {
        const container = document.getElementById('user-properties');
        if (!container) return [];
        
        return Array.from(container.children).map(span => 
            span.textContent.trim().replace(/\s*×\s*$/, '')  // Remove the "×" from the text
        );
    }

    function collectQueryParams() {
        const identityFilter = document.getElementById('user-identity')?.value.trim() || '';
        const customLdapFilter = document.getElementById('custom-ldap-filter')?.value.trim();
        const searchBase = document.getElementById('user-search-base').value;
        
        return {
            args: {
                properties: getSelectedProperties(),
                identity: identityFilter,
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
                ldapfilter: customLdapFilter || '',
                searchbase: searchBase,
                ...getActiveFilters()
            }
        };
    }

    async function searchUsers(no_cache=false) {
        const searchSpinner = document.getElementById('search-spinner');
        const boxOverlaySpinner = document.getElementById('box-overlay-spinner');
        
        try {
            if (searchSpinner) searchSpinner.classList.remove('hidden');
            if (boxOverlaySpinner) boxOverlaySpinner.classList.remove('hidden');
            
            const response = await fetch('/api/get/domainuser', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({...collectQueryParams(), no_cache: no_cache})
            });

            await handleHttpError(response);
            const result = await response.json();

            if (!Array.isArray(result)) {
                throw new Error('Invalid response format');
            }

            populateUsersTable(result);
        } catch (error) {
            console.error('Error searching users:', error);
            showErrorAlert('Failed to search users. Please try again.');
        } finally {
            if (searchSpinner) searchSpinner.classList.add('hidden');
            if (boxOverlaySpinner) boxOverlaySpinner.classList.add('hidden');
        }
    }

    function filterUsers() {
        const searchInput = document.getElementById('user-search').value.toLowerCase();
        const tbody = document.querySelector('#users-result-table tbody');
        const rows = tbody.querySelectorAll('tr:not(#initial-state):not(#loading-placeholder):not(#empty-placeholder)');

        rows.forEach(row => {
            let found = false;
            const cells = row.querySelectorAll('td');
            
            cells.forEach(cell => {
                const cellText = cell.textContent.toLowerCase();
                if (cellText.includes(searchInput)) {
                    found = true;
                }
            });

            if (found) {
                row.classList.remove('hidden');
            } else {
                row.classList.add('hidden');
            }
        });

        // Update counter to show filtered results
        const visibleRows = tbody.querySelectorAll('tr:not(.hidden):not(#initial-state):not(#loading-placeholder):not(#empty-placeholder)').length;
        const counter = document.getElementById('users-counter');
        const totalRows = tbody.querySelectorAll('tr:not(#initial-state):not(#loading-placeholder):not(#empty-placeholder)').length;
        counter.textContent = `Showing ${visibleRows} of ${totalRows} Users`;
    }

    // Add debounce to search filter
    const searchInput = document.getElementById('user-search');
    if (searchInput) {
        let debounceTimeout;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimeout);
            debounceTimeout = setTimeout(filterUsers, 300);
        });
    }

    function initializeDeleteHandlers() {
        document.getElementById('confirm-delete').addEventListener('click', async () => {
            if (identityToDelete && rowToDelete) {
                await deleteUser(identityToDelete, rowToDelete);
                
                document.getElementById('popup-modal').classList.add('hidden');
                document.getElementById('modal-overlay').classList.add('hidden');

                identityToDelete = null;
                rowToDelete = null;
            }
        });
    }

    function populateUsersTable(users) {
        const table = document.getElementById('users-result-table');
        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';

        // Update counter
        const counter = document.getElementById('users-counter');
        counter.textContent = `Total Users Found: ${users.length}`;

        if (users.length > 0) {
            const attributeKeys = Object.keys(users[0].attributes);

            thead.innerHTML = '';
            const headerRow = document.createElement('tr');
            attributeKeys.forEach(key => {
                const th = document.createElement('th');
                th.scope = 'col';
                th.className = 'p-1';
                th.textContent = key;
                headerRow.appendChild(th);
            });

            const actionTh = document.createElement('th');
            actionTh.scope = 'col';
            actionTh.className = 'p-1';
            actionTh.textContent = 'Action';
            headerRow.appendChild(actionTh);

            thead.appendChild(headerRow);

            users.forEach(user => {
                const tr = document.createElement('tr');
                tr.classList.add('dark:hover:bg-white/5', 'dark:hover:text-white', 'cursor-pointer');
                tr.dataset.identity = user.dn;

                tr.addEventListener('click', (event) => {
                    if (event.target.closest('button')) return;
                    handleLdapLinkClick(event, user.dn);
                });

                attributeKeys.forEach(key => {
                    const td = document.createElement('td');
                    td.className = 'p-1 whitespace-nowrap relative group';
                    const value = user.attributes[key];
                    
                    // Create wrapper div for content and copy button
                    const wrapper = document.createElement('div');
                    wrapper.className = 'flex items-center gap-2';
                    
                    // Create text content span
                    const textSpan = document.createElement('span');
                    if (Array.isArray(value)) {
                        textSpan.innerHTML = value.join('<br>');
                    } else {
                        textSpan.textContent = value;
                    }
                    
                    // Create copy button
                    const copyButton = document.createElement('button');
                    copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
                    copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                    copyButton.title = 'Copy to clipboard';
                    
                    // Add click handler for copy button
                    copyButton.addEventListener('click', async (event) => {
                        event.stopPropagation(); // Prevent row click event
                        const textToCopy = Array.isArray(value) ? value.join('\n') : value;
                        
                        try {
                            // Modern clipboard API
                            if (navigator.clipboard && window.isSecureContext) {
                                await navigator.clipboard.writeText(textToCopy);
                            } else {
                                // Fallback for older browsers or non-HTTPS
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
                            
                            // Show success feedback
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
                    tr.appendChild(td);
                });

                const actionTd = document.createElement('td');
                actionTd.className = 'p-1 whitespace-nowrap';

                const deleteButton = document.createElement('button');
                deleteButton.className = 'text-red-600 hover:text-red-700 dark:text-red-500 dark:hover:text-red-400 p-1 rounded-md hover:bg-red-50 dark:hover:bg-red-950/50 transition-colors';
                deleteButton.innerHTML = '<i class="fas fa-trash-alt"></i>';
                deleteButton.title = 'Delete User';
                deleteButton.addEventListener('click', (event) => {
                    event.stopPropagation();
                    showDeleteModal(user.dn, tr);
                });
                actionTd.appendChild(deleteButton);

                tr.appendChild(actionTd);
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `
                <tr id="empty-placeholder">
                    <td colspan="100%" class="text-center py-4">No users found</td>
                </tr>
            `;
        }
    }

    function showDeleteModal(identity, rowElement) {
        identityToDelete = identity;
        rowToDelete = rowElement;
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

    async function showAddUserModal() {
        const modal = document.getElementById('add-user-modal');
        const overlay = document.getElementById('modal-overlay');
        
        try {
            // Show the modal
            modal.removeAttribute('aria-hidden');
            modal.classList.remove('hidden');
            overlay.classList.remove('hidden');

            // Focus on the username input instead of the first input
            const usernameInput = document.getElementById('new-username');
            if (usernameInput) {
                usernameInput.focus();
            }
        } catch (error) {
            console.error('Error initializing Add User Modal:', error);
            showErrorAlert('Failed to initialize Add User Modal');
        }
    }

    // Modal event listeners
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

    document.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
            const visibleModals = document.querySelectorAll('.fixed:not(.hidden)[aria-hidden]');
            visibleModals.forEach(modal => {
                modal.setAttribute('aria-hidden', 'true');
                modal.classList.add('hidden');
                document.getElementById('modal-overlay').classList.add('hidden');
            });
        }
    });

    document.querySelector('[data-modal-toggle="add-user-modal"]')?.addEventListener('click', showAddUserModal);

    document.getElementById('add-user-form')?.addEventListener('submit', (event) => {
        event.preventDefault();
        const username = document.getElementById('new-username')?.value;
        const password = document.getElementById('new-password')?.value;
        const basedn = document.getElementById('user-base-dn')?.value;
        if (!username || !password) {
            showErrorAlert('Please fill in all fields');
            return;
        }

        console.log(username, password, basedn);

        addUser(username, password, basedn);
        document.getElementById('add-user-modal')?.classList.add('hidden');
        document.getElementById('modal-overlay')?.classList.add('hidden');
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

            if (result === false) {
                showErrorAlert("Failed to delete user. Check logs");
                return false;
            }

            showSuccessAlert("User deleted successfully");
            rowElement.remove();
            return true;
        } catch (error) {
            console.error('Error deleting user:', error);
            showErrorAlert("Failed to delete user. Check logs");
            return false;
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

            const result = await response.json();
            showSuccessAlert(`Added user ${username} to ${basedn}`);

            searchUsers(no_cache=true); // Refresh the user list
        } catch (error) {
            console.error('Error adding user:', error);
            showErrorAlert('Failed to add user. Please try again.');
        }
    }

    // Show initial state
    const tbody = document.querySelector('#users-result-table tbody');
    tbody.innerHTML = `
        <tr id="initial-state">
            <td colspan="100%" class="text-center py-8 text-neutral-500">
                <i class="fa-solid fa-magnifying-glass mb-2 text-lg"></i>
                <p>Use the search button or filters above to find users</p>
            </td>
        </tr>
    `;

    // Initialize counter
    const counter = document.getElementById('users-counter');
    counter.textContent = 'Total Users Found: 0';

    async function initializeSearchBase() {
        const searchBaseSelect = document.getElementById('user-search-base');
        const searchBaseDropdown = document.getElementById('search-base-dropdown');
        const searchInput = document.getElementById('search-base-input');
        const optionsContainer = document.getElementById('search-base-options');
        const baseDnModal = document.getElementById('user-base-dn');

        try {
            // Get domain info for root DN
            const domainInfo = await getDomainInfo();
            const rootDN = domainInfo.root_dn;

            // Fill in the base DN modal for search base input
            baseDnModal.value = `CN=Users,${rootDN}`;
            
            // Get all OUs
            const ous = await getDomainOU();
            if (Array.isArray(ous)) {
                allOUs = [
                    { dn: rootDN, name: 'Root DN' },
                    ...ous.map(ou => ({ 
                        dn: ou.dn, 
                        name: ou.dn.split(',').find(part => part.startsWith('OU='))?.substring(3) || ou.dn 
                    }))
                ];
            }

            // Initial render of select
            searchBaseSelect.innerHTML = `<option value="${rootDN}">${rootDN}</option>`;
            
            // Handle click on select to show custom dropdown
            searchBaseSelect.addEventListener('click', (e) => {
                e.preventDefault();
                searchBaseDropdown.classList.remove('hidden');
                searchInput.focus();
                searchBaseDropdownVisible = true;
                renderFilteredOptions();
            });

            // Handle search input
            searchInput.addEventListener('input', debounce(() => {
                renderFilteredOptions();
            }, 300));

            // Handle clicking outside
            document.addEventListener('click', (e) => {
                if (!searchBaseDropdown.contains(e.target) && !searchBaseSelect.contains(e.target)) {
                    searchBaseDropdown.classList.add('hidden');
                    searchBaseDropdownVisible = false;
                }
            });

            // Handle option selection
            optionsContainer.addEventListener('click', (e) => {
                const option = e.target.closest('.search-base-option');
                if (option) {
                    const value = option.dataset.value;
                    searchBaseSelect.innerHTML = `<option value="${value}" selected>${value}</option>`;
                    searchBaseDropdown.classList.add('hidden');
                    searchBaseDropdownVisible = false;
                    searchInput.value = '';
                }
            });

        } catch (error) {
            console.error('Error initializing search base:', error);
            showErrorAlert('Failed to load organizational units');
        }
    }

    function renderFilteredOptions() {
        const searchInput = document.getElementById('search-base-input');
        const optionsContainer = document.getElementById('search-base-options');
        const searchTerm = searchInput.value.toLowerCase();

        const filteredOUs = allOUs.filter(ou => 
            ou.dn.toLowerCase().includes(searchTerm) || 
            ou.name.toLowerCase().includes(searchTerm)
        );

        optionsContainer.innerHTML = filteredOUs.map(ou => `
            <div class="search-base-option px-4 py-2 hover:bg-neutral-100 dark:hover:bg-neutral-700 cursor-pointer text-sm" data-value="${ou.dn}">
                <div class="font-medium">${ou.name}</div>
                <div class="text-xs text-neutral-500 dark:text-neutral-400">${ou.dn}</div>
            </div>
        `).join('');
    }

    // Utility function for debouncing
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    // Add this function to fetch domain OUs
    async function getDomainOU() {
        try {
            const response = await fetch('/api/get/domainou', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ properties: ['name'] })
            });

            await handleHttpError(response);
            return await response.json();
        } catch (error) {
            console.error('Error fetching domain OUs:', error);
            return [];
        }
    }
});
