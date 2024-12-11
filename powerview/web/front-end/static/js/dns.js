document.addEventListener('DOMContentLoaded', () => {
    async function fetchAndDisplayDnsZones() {
        // Select the spinner element
        const spinner = document.getElementById('box-overlay-spinner');
        if (!spinner) {
            console.error('Spinner element not found');
            return;
        }

        // Show the spinner
        spinner.classList.remove('hidden');

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
                zoneDiv.classList.add('zone-item', 'mb-4');

                const zoneButton = document.createElement('button');
                zoneButton.textContent = name;
                zoneButton.classList.add('zone-button', 'w-full', 'text-left', 'bg-gray-100', 'dark:bg-gray-800', 'p-2', 'rounded', 'font-semibold', 'hover:bg-gray-200', 'dark:hover:bg-gray-700');
                zoneButton.addEventListener('click', () => toggleZoneRecords(name, zoneDiv));

                const recordsContainer = document.createElement('div');
                recordsContainer.classList.add('records-container', 'ml-4', 'mt-2', 'hidden');

                zoneDiv.appendChild(zoneButton);
                zoneDiv.appendChild(recordsContainer);
                zoneNameContainer.appendChild(zoneDiv);
            });
        } catch (error) {
            console.error('Error fetching DNS zones:', error);
        } finally {
            // Hide the spinner after fetching data
            spinner.classList.add('hidden');
        }
    }

    async function toggleZoneRecords(zoneName, parentElement) {
        const recordsContainer = parentElement.querySelector('.records-container');

        if (!recordsContainer.classList.contains('hidden')) {
            recordsContainer.classList.add('hidden');
            recordsContainer.innerHTML = ''; // Clear existing records
            return;
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
        }
    }

    async function fetchAndDisplayDnsRecordDetails(identity, zoneName) {
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
            const detailsContainer = document.querySelector('.dns-record-details-container');
            if (!detailsContainer) {
                console.error('DNS record details container not found');
                return;
            }

            // Clear existing content
            detailsContainer.innerHTML = '';

            // Check if data is an array and iterate over it
            if (Array.isArray(data)) {
                data.forEach(record => {
                    const attributes = record.attributes;
                    Object.entries(attributes).forEach(([key, value]) => {
                        const detailElement = document.createElement('p');
                        detailElement.innerHTML = `<strong>${key}:</strong> ${value}`;
                        detailElement.classList.add('text-sm', 'text-gray-700', 'dark:text-gray-300', 'py-1');
                        detailsContainer.appendChild(detailElement);
                    });
                });
            } else {
                console.error('Unexpected data format:', data);
            }
        } catch (error) {
            console.error('Error fetching DNS record details:', error);
        }
    }

    fetchAndDisplayDnsZones();
});
