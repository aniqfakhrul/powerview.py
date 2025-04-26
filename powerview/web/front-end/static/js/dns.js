document.addEventListener('DOMContentLoaded', () => {
    function convertZoneToId(zoneName) {
        return zoneName.replace(/\./g, '-');
    }

    async function fetchAndDisplayDnsZones() {
        // Select the spinner element
        showInitLoadingIndicator();

        try {
            const response = await fetch('/api/get/domaindnszone', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            await handleHttpError(response);

            const data = await response.json();
            const zoneNames = data.map(obj => obj.attributes.name);

            // Populate the zone names in the modal dropdown
            const zoneDropdown = document.getElementById('dns-zone');
            if (zoneDropdown) {
                zoneDropdown.innerHTML = ''; // Clear existing options
                
                // Get currently selected zone
                const selectedZone = document.querySelector('.zone-item.bg-neutral-200, .zone-item.dark\\:bg-neutral-800');
                const currentZoneName = selectedZone ? selectedZone.querySelector('span').textContent : null;

                zoneNames.forEach((zoneName, index) => {
                    const option = document.createElement('option');
                    option.value = zoneName;
                    option.textContent = zoneName;
                    
                    // Set as selected if it matches the current zone or if it's the first item and no zone is selected
                    if ((currentZoneName && zoneName === currentZoneName) || (!currentZoneName && index === 0)) {
                        option.selected = true;
                    }
                    
                    zoneDropdown.appendChild(option);
                });
            }

            const zoneNameContainer = document.querySelector('.zone-name-container');
            if (!zoneNameContainer) {
                console.error('Zone name container not found');
                return;
            }

            // Clear existing content
            zoneNameContainer.innerHTML = '';

            // Create and append new zone names as dropdowns
            zoneNames.forEach(name => {
                const zoneDiv = document.createElement('div');
                zoneDiv.classList.add(
                    'cursor-pointer',
                    'zone-item', 
                    'flex', 
                    'items-center',
                    'p-2',
                    'rounded', 
                    'hover:bg-neutral-100', 
                    'dark:hover:bg-neutral-700'
                );
                
                zoneDiv.addEventListener('click', () => {
                    // Remove selected classes from all zone items
                    document.querySelectorAll('.zone-item').forEach(item => {
                        item.classList.remove('bg-neutral-200', 'dark:bg-neutral-800');
                    });
                    // Add selected classes to clicked zone
                    zoneDiv.classList.add('bg-neutral-200', 'dark:bg-neutral-800');
                    toggleZoneRecords(name, zoneDiv);
                });

                const zoneSpan = document.createElement('span');
                zoneSpan.textContent = name;
                zoneSpan.classList.add('text-neutral-900', 'dark:text-white', 'mr-2','text-left');

                const spinnerSVG = getSpinnerSVG(`button-${convertZoneToId(name)}`);

                const recordsContainer = document.createElement('div');
                recordsContainer.classList.add('records-container', 'ml-4', 'mt-2', 'hidden');

                zoneDiv.appendChild(zoneSpan);
                zoneDiv.insertAdjacentHTML('beforeend', spinnerSVG);
                zoneDiv.appendChild(recordsContainer);
                zoneNameContainer.appendChild(zoneDiv);
            });
        } catch (error) {
            console.error('Error fetching DNS zones:', error);
        } finally {
            hideInitLoadingIndicator();
        }
    }

    async function toggleZoneRecords(zoneName, parentElement) {
        const recordsContainer = parentElement.querySelector('.records-container');

        if (!recordsContainer.classList.contains('hidden')) {
            recordsContainer.classList.add('hidden');
            recordsContainer.innerHTML = '';
            return;
        }

        const zoneSpinner = document.getElementById(`spinner-button-${convertZoneToId(zoneName)}`);
        if (zoneSpinner) {
            zoneSpinner.classList.remove('hidden');
        }

        try {
            const response = await fetch('/api/get/domaindnsrecord', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ zonename: zoneName})
            });

            await handleHttpError(response);
            const data = await response.json();

            // Clear record search when switching zones
            const recordSearchInput = document.getElementById('record-search');
            if (recordSearchInput) {
                recordSearchInput.value = '';
            }

            // Deduplicate records, prioritizing those with addresses
            const uniqueRecords = new Map();
            data.forEach(record => {
                const name = record.attributes.name;
                const currentRecord = uniqueRecords.get(name);
                
                if (!currentRecord || (!currentRecord.attributes.Address && record.attributes.Address)) {
                    uniqueRecords.set(name, record);
                }
            });

            const recordNameSection = document.querySelector('.record-name-section');
            if (!recordNameSection) {
                console.error('Record Name section not found');
                return;
            }

            recordNameSection.innerHTML = '';

            // Create table with a specific class for filtering
            const table = document.createElement('table');
            table.classList.add('w-full', 'text-left', 'border-collapse', 'dns-records-table');

            // Create table header
            const thead = document.createElement('thead');
            const headerRow = document.createElement('tr');
            ['Name', 'Address'].forEach(headerText => {
                const th = document.createElement('th');
                th.textContent = headerText;
                th.classList.add(
                    'text-neutral-600',
                    'dark:text-neutral-400',
                    'px-3',
                    'py-2',
                    'font-medium'
                );
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            // Create tbody
            const tbody = document.createElement('tbody');
            tbody.classList.add('divide-y', 'divide-neutral-200', 'dark:divide-neutral-700');

            // Populate table rows
            Array.from(uniqueRecords.values()).forEach(record => {
                const row = document.createElement('tr');
                row.classList.add(
                    'cursor-pointer',
                    'hover:bg-neutral-100',
                    'dark:hover:bg-neutral-700',
                    'dns-record-row'  // Add specific class for filtering
                );

                row.addEventListener('click', () => {
                    tbody.querySelectorAll('tr').forEach(r => {
                        r.classList.remove('bg-neutral-200', 'dark:bg-neutral-800');
                    });
                    row.classList.add('bg-neutral-200', 'dark:bg-neutral-800');
                    fetchAndDisplayDnsRecordDetails(record.attributes.name, zoneName);
                });

                const nameCell = document.createElement('td');
                nameCell.textContent = record.attributes.name;
                nameCell.classList.add('text-neutral-900', 'dark:text-white', 'px-3', 'py-2');

                const addressCell = document.createElement('td');
                addressCell.textContent = record.attributes.Address || '';
                addressCell.classList.add('text-neutral-900', 'dark:text-white', 'px-3', 'py-2');

                row.appendChild(nameCell);
                row.appendChild(addressCell);
                tbody.appendChild(row);
            });

            table.appendChild(tbody);
            recordNameSection.appendChild(table);

        } catch (error) {
            console.error('Error loading DNS records:', error);
            showErrorAlert('Failed to load DNS records');
        } finally {
            if (zoneSpinner) {
                zoneSpinner.classList.add('hidden');
            }
        }
    }

    function showAddDnsRecordModal() {
        const modal = document.getElementById('add-dns-record-modal');
        const overlay = document.getElementById('modal-overlay');
        
        // Get currently selected zone
        const selectedZone = document.querySelector('.zone-item.bg-neutral-200, .zone-item.dark\\:bg-neutral-800');
        const currentZoneName = selectedZone ? selectedZone.querySelector('span').textContent : null;
        
        // Set the dropdown's selected value
        const zoneDropdown = document.getElementById('dns-zone');
        if (zoneDropdown) {
            if (currentZoneName) {
                zoneDropdown.value = currentZoneName;
            } else {
                // If no zone is selected, select the first option
                if (zoneDropdown.options.length > 0) {
                    zoneDropdown.selectedIndex = 0;
                }
            }
        }

        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
    }

    document.getElementById('confirm-delete').addEventListener('click', async () => {
        if (recordnameToDelete) {
            await deleteDnsRecord(recordnameToDelete);
            recordnameToDelete = null;
            document.getElementById('popup-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');
        }
    });

    // Add an event listener for the close button
    document.querySelectorAll('[data-modal-hide]').forEach(button => {
        button.addEventListener('click', () => {
            const modalId = button.getAttribute('data-modal-hide');
            const modal = document.getElementById(modalId);
            const overlay = document.getElementById('modal-overlay');
            
            if (modal) {
                modal.classList.add('hidden');
            }
            if (overlay) {
                overlay.classList.add('hidden');
            }
        });
    });

    // Add event listener for the Add DNS Record button
    document.querySelector('[data-modal-toggle="add-dns-record-modal"]').addEventListener('click', showAddDnsRecordModal);

    document.getElementById('add-dns-record-form').addEventListener('submit', (event) => {
        event.preventDefault();
        const dns_name = document.getElementById('new-dns-name').value;
        const dns_address = document.getElementById('new-dns-address').value;
        const selected_zone = document.getElementById('dns-zone').value;
        
        if (!selected_zone) {
            showErrorAlert('Please select a DNS zone');
            return;
        }
        
        addDnsRecord(dns_name, dns_address, selected_zone);
        document.getElementById('add-dns-record-modal').classList.add('hidden');
        document.getElementById('modal-overlay').classList.add('hidden');
    });

    async function fetchAndDisplayDnsRecordDetails(identity, zoneName) {
        showLoadingIndicator();
        try {
            const response = await fetch('/api/get/domaindnsrecord', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ zonename: zoneName, identity: identity })
            });

            await handleHttpError(response);

            const data = await response.json();
            populateDNSDetailsPanel(data);
        } catch (error) {
            console.error('Error fetching DNS record details:', error);
        } finally {
            hideLoadingIndicator();
        }
    }

    function showDeleteModal(recordname) {
        recordnameToDelete = recordname;
        const modal = document.getElementById('popup-modal');
        const overlay = document.getElementById('modal-overlay');
        document.getElementById('identity-to-delete').textContent = recordname;
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
    }

    function populateDNSDetailsPanel(data) {

        const deleteButton = document.querySelector('[data-modal-target="delete-record-modal"]');
        deleteButton.classList.remove('hidden');
        deleteButton.addEventListener('click', () => {
            const records = Array.isArray(data) ? data : [data];
            if (records.length > 0) {
                showDeleteModal(records[0].attributes.name);
            } else {
                console.error('No records available to delete');
            }
        });

        const detailsContainer = document.querySelector('.dns-record-details-container');
        if (!detailsContainer) {
            console.error('DNS record details container not found');
            return;
        }

        // Clear existing content
        detailsContainer.innerHTML = '';

        // Convert single object to array if necessary
        const records = Array.isArray(data) ? data : [data];

        records.forEach((record, index) => {
            // Add a separator before each record except the first one
            if (index > 0) {
                const separator = document.createElement('div');
                separator.classList.add('my-4', 'border-t', 'border-neutral-200', 'dark:border-neutral-700');
                
                // Add record counter
                const recordCounter = document.createElement('div');
                recordCounter.classList.add(
                    'mt-4', 
                    'mb-2', 
                    'font-semibold', 
                    'text-neutral-700', 
                    'dark:text-neutral-300'
                );
                
                detailsContainer.appendChild(separator);
                detailsContainer.appendChild(recordCounter);
            }

            const attributes = record.attributes;
            Object.entries(attributes).forEach(([key, value]) => {
                const isDistinguishedName = Array.isArray(value) 
                    ? value.some(isValidDistinguishedName) 
                    : isValidDistinguishedName(value);

                let detailHTML = `<strong>${key}:</strong> `;
                if (key === 'dnsRecord') {
                    detailHTML += Array.isArray(value) 
                        ? value.map(v => convertToBase64(v)).join('<br>')
                        : convertToBase64(value);
                } else if (isDistinguishedName) {
                    detailHTML += Array.isArray(value) 
                        ? value.map(v => `<a href="#" class="text-blue-400 hover:text-blue-600" data-identity="${v}" onclick="handleLdapLinkClick(event, '${v}')">${v}</a>`).join('<br>')
                        : `<a href="#" class="text-blue-400 hover:text-blue-600" data-identity="${value}" onclick="handleLdapLinkClick(event, '${value}')">${value}</a>`;
                } else {
                    detailHTML += Array.isArray(value) ? value.join('<br>') : value;
                }

                const detailElement = document.createElement('p');
                detailElement.innerHTML = detailHTML;
                detailElement.classList.add(
                    'text-sm', 
                    'text-neutral-700', 
                    'dark:text-neutral-300', 
                    'py-1'
                );
                detailsContainer.appendChild(detailElement);
            });
        });
    }

    function createDNLink(dn) {
        const link = document.createElement('a');
        link.href = '#';
        link.textContent = dn;
        link.classList.add('text-blue-500', 'hover:text-blue-600', 'dark:text-blue-400', 'dark:hover:text-blue-300');
        link.dataset.identity = dn;
        link.addEventListener('click', (e) => handleLdapLinkClick(e, dn));
        return link;
    }

    async function addDnsRecord(recordName, recordAddress, zoneName) {
        try {
            showLoadingIndicator();

            const response = await fetch('/api/add/domaindnsrecord', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    recordname: recordName,
                    recordaddress: recordAddress,
                    zonename: zoneName
                })
            });

            await handleHttpError(response);

            const data = await response.json();
            console.log(data);
            showSuccessAlert('DNS record added successfully');

            // Check if the currently selected zone matches the zone we added the record to
            const selectedZone = document.querySelector('.zone-item.bg-neutral-200, .zone-item.dark\\:bg-neutral-800');
            const currentZoneName = selectedZone ? selectedZone.querySelector('span').textContent : null;

            // If we're viewing the same zone, refresh the records list
            if (currentZoneName === zoneName) {
                // Fetch and display updated records for the current zone
                const recordsResponse = await fetch('/api/get/domaindnsrecord', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ zonename: zoneName })
                });

                await handleHttpError(recordsResponse);
                const recordsData = await recordsResponse.json();
                
                // Clear and repopulate the records table
                const recordSection = document.querySelector('.record-name-section');
                if (recordSection) {
                    recordSection.innerHTML = '';
                    
                    const table = document.createElement('table');
                    table.classList.add('w-full', 'text-left');
                    
                    // Add table headers
                    const headerRow = document.createElement('tr');
                    ['Name', 'Address'].forEach(headerText => {
                        const th = document.createElement('th');
                        th.textContent = headerText;
                        th.classList.add(
                            'text-neutral-600',
                            'dark:text-neutral-400',
                            'font-medium',
                            'text-sm'
                        );
                        headerRow.appendChild(th);
                    });
                    table.appendChild(headerRow);

                    // Add records
                    recordsData.forEach(record => {
                        const row = document.createElement('tr');
                        row.classList.add(
                            'cursor-pointer',
                            'hover:bg-neutral-100',
                            'dark:hover:bg-neutral-700'
                        );

                        row.addEventListener('click', () => {
                            table.querySelectorAll('tr').forEach(r => {
                                r.classList.remove('bg-neutral-200', 'dark:bg-neutral-800');
                            });
                            row.classList.add('bg-neutral-200', 'dark:bg-neutral-800');
                            fetchAndDisplayDnsRecordDetails(record.attributes.name, zoneName);
                        });

                        const nameCell = document.createElement('td');
                        nameCell.textContent = record.attributes.name;
                        nameCell.classList.add('text-neutral-900', 'dark:text-white', 'py-2');
                        
                        const addressCell = document.createElement('td');
                        addressCell.textContent = record.attributes.Address || '';
                        addressCell.classList.add('text-neutral-900', 'dark:text-white', 'py-2');

                        row.appendChild(nameCell);
                        row.appendChild(addressCell);
                        table.appendChild(row);
                    });

                    recordSection.appendChild(table);
                }
            }

            // Close the modal
            document.getElementById('add-dns-record-modal').classList.add('hidden');
            document.getElementById('modal-overlay').classList.add('hidden');

        } catch (error) {
            console.error('Error adding DNS record:', error);
            showErrorAlert('Failed to add DNS record');
        } finally {
            hideLoadingIndicator();
        }
    }

    async function deleteDnsRecord(recordName) {
        try {
            showLoadingIndicator();

            // Updated selector to match new theme colors
            const selectedZone = document.querySelector('.zone-item.bg-neutral-200, .zone-item.dark\\:bg-neutral-800');
            const zoneName = selectedZone ? selectedZone.querySelector('span').textContent : null;

            if (!zoneName) {
                showErrorAlert('Could not determine the zone name');
                return;
            }

            const response = await fetch('/api/remove/domaindnsrecord', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    recordname: recordName,
                    zonename: zoneName
                })
            });

            await handleHttpError(response);

            const data = await response.json();
            console.log('DNS record deleted:', data);
            showSuccessAlert('DNS record deleted successfully');
            
            // Clear the details panel
            const detailsContainer = document.querySelector('.dns-record-details-container');
            if (detailsContainer) {
                detailsContainer.innerHTML = '';
            }

            // Hide the delete button
            const deleteButton = document.querySelector('[data-modal-target="delete-record-modal"]');
            if (deleteButton) {
                deleteButton.classList.add('hidden');
            }

            // Remove the selected row from the table
            const selectedRow = document.querySelector('.record-name-section tr.bg-neutral-200, .record-name-section tr.dark\\:bg-neutral-800');
            if (selectedRow) {
                selectedRow.remove();
            }

        } catch (error) {
            console.error('Error deleting DNS record:', error);
            showErrorAlert('Failed to delete DNS record');
        } finally {
            hideLoadingIndicator();
        }
    }

    // Add event listeners for search inputs with debounce
    const zoneSearchInput = document.getElementById('zone-search');
    const recordSearchInput = document.getElementById('record-search');

    if (zoneSearchInput) {
        let zoneDebounceTimeout;
        zoneSearchInput.addEventListener('input', () => {
            clearTimeout(zoneDebounceTimeout);
            zoneDebounceTimeout = setTimeout(filterZones, 100);
        });
    }

    if (recordSearchInput) {
        let recordDebounceTimeout;
        recordSearchInput.addEventListener('input', () => {
            clearTimeout(recordDebounceTimeout);
            recordDebounceTimeout = setTimeout(filterRecords, 100);
        });
    }

    function filterZones() {
        const searchTerm = zoneSearchInput.value.toLowerCase();
        const zoneItems = document.querySelectorAll('.zone-item');

        zoneItems.forEach(item => {
            const zoneName = item.querySelector('span').textContent.toLowerCase();
            if (zoneName.includes(searchTerm)) {
                item.classList.remove('hidden');
            } else {
                item.classList.add('hidden');
            }
        });
    }

    function filterRecords() {
        const searchTerm = document.getElementById('record-search').value.toLowerCase();
        const rows = document.querySelectorAll('.dns-record-row');
        
        rows.forEach(row => {
            const cells = Array.from(row.getElementsByTagName('td'));
            const textContent = cells.map(cell => cell.textContent.toLowerCase()).join(' ');
            
            if (textContent.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    // Add clear button functionality
    document.querySelectorAll('.clear-input').forEach(button => {
        button.addEventListener('click', (e) => {
            const input = e.target.closest('.relative').querySelector('input');
            input.value = '';
            input.dispatchEvent(new Event('input')); // Trigger the search filter
        });
    });

    fetchAndDisplayDnsZones();
});
