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
                zoneDiv.classList.add('zone-item', 'flex', 'items-center');

                const zoneSpan = document.createElement('span');
                zoneSpan.textContent = name;
                zoneSpan.classList.add('cursor-pointer', 'text-neutral-900', 'dark:text-white', 'mr-2','text-left', 'hover:bg-gray-200', 'dark:hover:bg-gray-700');
                zoneSpan.addEventListener('click', () => toggleZoneRecords(name, zoneDiv));

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
            recordsContainer.innerHTML = ''; // Clear existing records
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
                body: JSON.stringify({ zonename: zoneName, properties: ['name', 'Address'] })
            });

            await handleHttpError(response);

            const data = await response.json();

            // Select the Record Name section
            const recordNameSection = document.querySelector('.record-name-section');
            if (!recordNameSection) {
                console.error('Record Name section not found');
                return;
            }

            // Clear existing content
            recordNameSection.innerHTML = '';

            // Create a table
            const table = document.createElement('table');
            table.classList.add('w-full', 'text-left', 'border-collapse');

            // Create table header
            const headerRow = document.createElement('tr');
            const nameHeader = document.createElement('th');
            nameHeader.textContent = 'Name';
            const addressHeader = document.createElement('th');
            addressHeader.textContent = 'Address';
            headerRow.appendChild(nameHeader);
            headerRow.appendChild(addressHeader);
            table.appendChild(headerRow);

            // Populate table rows
            data.forEach(record => {
                const row = document.createElement('tr');
                row.classList.add('cursor-pointer', 'hover:bg-gray-100', 'dark:hover:bg-gray-700');

                const nameCell = document.createElement('td');
                nameCell.textContent = record.attributes.name;
                const addressCell = document.createElement('td');
                addressCell.textContent = record.attributes.Address;

                row.appendChild(nameCell);
                row.appendChild(addressCell);

                // Add click event listener to the row
                row.addEventListener('click', () => {
                    fetchAndDisplayDnsRecordDetails(record.attributes.name, zoneName);
                });

                table.appendChild(row);
            });

            // Append table to the Record Name section
            recordNameSection.appendChild(table);

        } catch (error) {
            console.error('Error fetching DNS records:', error);
        } finally {
            if (zoneSpinner) {
                zoneSpinner.classList.add('hidden'); // Hide the spinner after processing
            }
        }
    }

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

    // Example function to handle the click event
    function handleLdapLinkClick(event, identity) {
        event.preventDefault();
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

    function populateDNSDetailsPanel(data) {
        const detailsContainer = document.querySelector('.dns-record-details-container');
        if (!detailsContainer) {
            console.error('DNS record details container not found');
            return;
        }

        // Clear existing content
        detailsContainer.innerHTML = '';

        // Convert single object to array if necessary
        const records = Array.isArray(data) ? data : [data];

        records.forEach(record => {
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
                detailElement.classList.add('text-sm', 'text-gray-700', 'dark:text-gray-300', 'py-1');
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

    fetchAndDisplayDnsZones();
});
