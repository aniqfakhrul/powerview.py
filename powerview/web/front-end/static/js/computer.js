document.addEventListener('DOMContentLoaded', () => {
    const activeFilters = new Set();
    const defaultProperties = ['dnsHostName', 'operatingSystem', 'description'];
    let identityToDelete = null;
    let rowToDelete = null;
    let allOUs = [];
    let searchBaseDropdownVisible = false;

    initializePropertyFilter(defaultProperties);
    initializeQueryTemplates();
    initializeDeleteHandlers();
    initializeSearchBase();

    function initializeQueryTemplates() {
        const dropdownButton = document.getElementById('filter-dropdown-button');
        const dropdownMenu = document.getElementById('filter-dropdown-menu');
        const selectedFilters = document.getElementById('selected-filters');
        const searchButton = document.getElementById('computer-search-button');

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

        searchButton.addEventListener('click', searchComputers);
    }

    function renderActiveFilters() {
        const container = document.getElementById('selected-filters');
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

    function getActiveFilters() {
        const filters = {};
        activeFilters.forEach(filter => {
            filters[filter] = true;
        });
        return filters;
    }

    function getSelectedProperties() {
        const propertyElements = document.querySelectorAll('#computer-properties span');
        return Array.from(propertyElements).map(span => 
            span.textContent.trim().replace(/\s*×\s*$/, '')
        );
    }

    function initializePropertyFilter(initialProperties) {
        const selectedProperties = [...initialProperties];
        const container = document.getElementById('computer-properties');
        const newPropertyInput = document.getElementById('new-computer-property');
        
        if (!container || !newPropertyInput) {
            console.error('Required elements not found');
            return;
        }

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

        renderProperties();
    }

    function filterComputers() {
        const searchInput = document.getElementById('computer-search').value.toLowerCase();
        const rows = document.querySelectorAll('tbody tr');

        rows.forEach(row => {
            const name = row.querySelector('td:nth-child(1)').textContent.toLowerCase();
            const samAccountName = row.querySelector('td:nth-child(2)').textContent.toLowerCase();
            const operatingSystem = row.querySelector('td:nth-child(3)').textContent.toLowerCase();

            if (name.includes(searchInput) || 
                samAccountName.includes(searchInput) || 
                operatingSystem.includes(searchInput)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    const searchInput = document.getElementById('computer-search');
    if (searchInput) {
        let debounceTimeout;
        searchInput.addEventListener('input', () => {
            clearTimeout(debounceTimeout);
            debounceTimeout = setTimeout(filterComputers, 300);
        });
    }

    function populateComputersTable(computers) {
        const table = document.getElementById('computers-result-table');
        const thead = table.querySelector('thead');
        const tbody = table.querySelector('tbody');
        tbody.innerHTML = '';

        const counter = document.getElementById('computers-counter');
        counter.textContent = `Total Computers: ${computers.length}`;

        if (computers.length > 0) {
            // Get all unique attribute keys from all computers and normalize them
            const attributeKeys = [...new Set(
                computers.flatMap(computer => 
                    Object.keys(computer.attributes || {}).map(key => key.toLowerCase())
                )
            )];

            // Create table headers
            thead.innerHTML = '';
            const headerRow = document.createElement('tr');
            attributeKeys.forEach(key => {
                const th = document.createElement('th');
                th.scope = 'col';
                th.className = 'p-1';
                // Capitalize first letter of each word for display
                th.textContent = key.split(/(?=[A-Z])/).join(' ').replace(/^\w/, c => c.toUpperCase());
                headerRow.appendChild(th);
            });

            // Add Action column header
            const actionTh = document.createElement('th');
            actionTh.scope = 'col';
            actionTh.className = 'p-1';
            actionTh.textContent = 'Action';
            headerRow.appendChild(actionTh);
            thead.appendChild(headerRow);

            // Populate table rows
            computers.forEach(computer => {
                const tr = document.createElement('tr');
                tr.classList.add('dark:hover:bg-white/5', 'dark:hover:text-white', 'cursor-pointer');
                tr.dataset.identity = computer.dn;

                tr.addEventListener('click', (event) => {
                    if (event.target.closest('button')) return;
                    handleLdapLinkClick(event, computer.dn);
                });

                // Create cells for each attribute
                attributeKeys.forEach(key => {
                    const td = document.createElement('td');
                    td.className = 'p-1 whitespace-nowrap relative group';
                    
                    const wrapper = document.createElement('div');
                    wrapper.className = 'flex items-center gap-2';
                    
                    const textSpan = document.createElement('span');
                    // Find the actual key in the attributes object (case-insensitive)
                    const actualKey = Object.keys(computer.attributes || {})
                        .find(k => k.toLowerCase() === key);
                    const value = actualKey ? computer.attributes[actualKey] : null;
                    
                    // Handle different value types
                    if (Array.isArray(value)) {
                        if (value.length === 0) {
                            textSpan.textContent = '';
                        } else {
                            textSpan.innerHTML = value.join('<br>');
                        }
                    } else if (value === undefined || value === null) {
                        textSpan.textContent = '';
                    } else {
                        textSpan.textContent = value;
                    }

                    const copyButton = document.createElement('button');
                    copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
                    copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                    copyButton.title = 'Copy to clipboard';
                    
                    copyButton.addEventListener('click', async (event) => {
                        event.stopPropagation();
                        const textToCopy = Array.isArray(value) ? value.join('\n') : (value || '');
                        
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
                    tr.appendChild(td);
                });

                // Add action column
                const actionTd = document.createElement('td');
                actionTd.className = 'p-1 whitespace-nowrap';

                const deleteButton = document.createElement('button');
                deleteButton.className = 'text-red-600 hover:text-red-700 dark:text-red-500 dark:hover:text-red-400 p-1 rounded-md hover:bg-red-50 dark:hover:bg-red-950/50 transition-colors';
                deleteButton.innerHTML = '<i class="fas fa-trash-alt"></i>';
                deleteButton.title = 'Delete Computer';
                deleteButton.addEventListener('click', (event) => {
                    event.stopPropagation();
                    showDeleteModal(computer.dn, tr);
                });
                actionTd.appendChild(deleteButton);

                tr.appendChild(actionTd);
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `
                <tr id="empty-placeholder">
                    <td colspan="100%" class="text-center py-4">No computers found</td>
                </tr>
            `;
        }
    }

    async function addComputer(computer_name, computer_pass, basedn) {
        try {
            const response = await fetch('/api/add/domaincomputer', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ computer_name: computer_name, computer_pass: computer_pass, basedn: basedn })
            });

            await handleHttpError(response);

            const result = await response.json();
            console.log('Computer added:', result);

            searchComputers();
        } catch (error) {
            console.error('Error adding user:', error);
        }
    }
    
    function showDeleteModal(hostname, rowElement) {
        identityToDelete = hostname;
        rowToDelete = rowElement;
        const modal = document.getElementById('popup-modal');
        const overlay = document.getElementById('modal-overlay');
        document.getElementById('identity-to-delete').textContent = hostname;
        
        modal.removeAttribute('aria-hidden');
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');

        const firstButton = modal.querySelector('button');
        if (firstButton) {
            firstButton.focus();
        }
    }

    function showAddComputerModal() {
        const modal = document.getElementById('add-computer-modal');
        const overlay = document.getElementById('modal-overlay');
        
        modal.removeAttribute('aria-hidden');
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');

        // Focus on the computer name input instead of the first input
        const computerNameInput = document.getElementById('new-computername');
        if (computerNameInput) {
            computerNameInput.focus();
        }
    }

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

    document.querySelector('[data-modal-toggle="add-computer-modal"]').addEventListener('click', showAddComputerModal);

    document.getElementById('add-computer-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const computer_name = document.getElementById('new-computername').value;
        const computer_pass = document.getElementById('new-computerpass').value;
        const basedn = document.getElementById('computer-base-dn').value;
        addComputer(computer_name, computer_pass, basedn);
        document.getElementById('add-computer-modal').classList.add('hidden');
        document.getElementById('modal-overlay').classList.add('hidden');
    });

    async function deleteComputer(distinguishedName, rowElement) {
        try {
            const response = await fetch('/api/remove/domaincomputer', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ computer_name: distinguishedName })
            });

            await handleHttpError(response);

            const result = await response.json();
            console.log('Computer deleted:', result);

            if (result === false) {
                showErrorAlert("Failed to delete computer. Check logs");
                return false;
            }

            showSuccessAlert("Computer deleted successfully");
            rowElement.remove();
            return true;
        } catch (error) {
            console.error('Error deleting computer:', error);
            showErrorAlert("Failed to delete computer. Check logs");
            return false;
        }
    }

    function collectQueryParams() {
        const identityFilter = document.getElementById('computer-identity')?.value.trim() || '';
        const ldapFilter = document.getElementById('custom-ldap-filter')?.value.trim() || '';
        const searchBase = document.getElementById('computer-search-base').value;
        
        return {
            args: {
                properties: getSelectedProperties(),
                identity: identityFilter,
                ldapfilter: ldapFilter,
                unconstrained: false,
                enabled: false,
                disabled: false,
                trustedtoauth: false,
                laps: false,
                rbcd: false,
                shadowcred: false,
                printers: false,
                spn: false,
                excludedcs: false,
                bitlocker: false,
                gmsapassword: false,
                pre2k: false,
                searchbase: searchBase,
                ...getActiveFilters()
            }
        };
    }

    async function searchComputers() {
        const searchSpinner = document.getElementById('search-spinner');
        const boxOverlaySpinner = document.getElementById('box-overlay-spinner');
        try {
            if (searchSpinner) searchSpinner.classList.remove('hidden');
            if (boxOverlaySpinner) boxOverlaySpinner.classList.remove('hidden');

            const response = await fetch('/api/get/domaincomputer', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(collectQueryParams())
            });

            await handleHttpError(response);
            const result = await response.json();
            if (!Array.isArray(result)) {
                throw new Error('Invalid response format');
            }

            populateComputersTable(result);
        } catch (error) {
            console.error('Error searching computers:', error);
            showErrorAlert('Failed to search computers. Please try again.');
        } finally {
            if (searchSpinner) searchSpinner.classList.add('hidden');
            if (boxOverlaySpinner) boxOverlaySpinner.classList.add('hidden');
        }
    }

    document.getElementById('computer-search-button').addEventListener('click', searchComputers);

    // Show initial state
    const tbody = document.querySelector('#computers-result-table tbody');
    tbody.innerHTML = `
        <tr id="initial-state">
            <td colspan="100%" class="text-center py-8 text-neutral-500">
                <i class="fa-solid fa-magnifying-glass mb-2 text-lg"></i>
                <p>Use the search button or filters above to find computers</p>
            </td>
        </tr>
    `;

    // Initialize counter
    const counter = document.getElementById('computers-counter');
    counter.textContent = 'Total Computers Found: 0';

    function initializeDeleteHandlers() {
        const confirmDeleteButton = document.getElementById('confirm-delete');
        
        confirmDeleteButton.replaceWith(confirmDeleteButton.cloneNode(true));
        
        document.getElementById('confirm-delete').addEventListener('click', async () => {
            if (identityToDelete && rowToDelete) {
                await deleteComputer(identityToDelete, rowToDelete);
                
                document.getElementById('popup-modal').classList.add('hidden');
                document.getElementById('modal-overlay').classList.add('hidden');

                identityToDelete = null;
                rowToDelete = null;
            }
        });
    }

    async function initializeSearchBase() {
        const searchBaseSelect = document.getElementById('computer-search-base');
        const searchBaseDropdown = document.getElementById('search-base-dropdown');
        const searchInput = document.getElementById('search-base-input');
        const optionsContainer = document.getElementById('search-base-options');
        const baseDnModal = document.getElementById('computer-base-dn');
        
        try {
            // Get domain info for root DN
            const domainInfo = await getDomainInfo();
            const rootDN = domainInfo.root_dn;
            
            // Fill in the base DN modal for search base input
            baseDnModal.value = rootDN;

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
