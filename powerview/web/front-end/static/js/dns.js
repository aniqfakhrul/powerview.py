document.addEventListener('DOMContentLoaded', () => {
    let recordnameToDelete = null;
    function convertZoneToId(zoneName) {
        return zoneName.replace(/\./g, '-');
    }

    // Soft badge helpers moved to static.js and loaded globally

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
            const rawZones = Array.isArray(data) ? data : [];
            const zoneMap = new Map();
            rawZones.forEach(item => {
                if (typeof item === 'string') {
                    const name = item;
                    if (name && !zoneMap.has(name)) zoneMap.set(name, { name, type: '' });
                } else {
                    const attrs = (item && item.attributes) || {};
                    const name = attrs.name || attrs.dc || '';
                    const type = attrs.type || '';
                    if (name && !zoneMap.has(name)) zoneMap.set(name, { name, type });
                }
            });
            const zonesList = Array.from(zoneMap.values());

            // Populate the zone names in the modal dropdown
            const zoneDropdown = document.getElementById('dns-zone');
            if (zoneDropdown) {
                zoneDropdown.innerHTML = '';
                const selectedZoneRow = document.querySelector('.zone-row.bg-neutral-200, .zone-row.dark\\:bg-neutral-800');
                const currentZoneName = selectedZoneRow ? (selectedZoneRow.querySelector('td')?.textContent || '').split(' (')[0] : null;
                zonesList.forEach((z, index) => {
                    const option = document.createElement('option');
                    option.value = z.name;
                    option.textContent = z.name;
                    if ((currentZoneName && z.name === currentZoneName) || (!currentZoneName && index === 0)) option.selected = true;
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

            const table = document.createElement('table');
            table.classList.add('w-full', 'text-sm', 'border-collapse');

            const tbody = document.createElement('tbody');
            tbody.className = '';
            zonesList.forEach(z => {
                const tr = document.createElement('tr');
                tr.className = 'zone-row cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-700';
                tr.addEventListener('click', () => {
                    tbody.querySelectorAll('tr').forEach(r => r.classList.remove('bg-neutral-200', 'dark:bg-neutral-800'));
                    tr.classList.add('bg-neutral-200', 'dark:bg-neutral-800');
                    toggleZoneRecords(z.name);
                });
                const td = document.createElement('td');
                td.className = 'px-3 py-2 text-neutral-900 dark:text-white';
                if (z.type) {
                    const badge = `<span class="${getSoftBadgeClasses(zoneTypeColor(z.type))}">${z.type}</span>`;
                    td.innerHTML = `${z.name} ${badge}`;
                } else {
                    td.textContent = z.name;
                }
                tr.appendChild(td);
                tbody.appendChild(tr);
            });
            table.appendChild(tbody);
            zoneNameContainer.appendChild(table);
        } catch (error) {
            console.error('Error fetching DNS zones:', error);
        } finally {
            hideInitLoadingIndicator();
        }
    }

    async function toggleZoneRecords(zoneName) {
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

            const table = document.createElement('table');
            table.classList.add('w-full', 'text-sm', 'border-collapse', 'dns-records-table');
            const thead = document.createElement('thead');
            const hr = document.createElement('tr');
            ['Name', 'Type', 'TTL', 'Value', 'Actions'].forEach(h => {
                const th = document.createElement('th');
                th.className = 'text-left px-3 py-2 text-neutral-600 dark:text-neutral-400 font-medium';
                th.textContent = h;
                hr.appendChild(th);
            });
            thead.appendChild(hr);
            table.appendChild(thead);

            const tbody = document.createElement('tbody');
            tbody.className = 'divide-y divide-neutral-200 dark:divide-neutral-800';

            const recordsArray = Array.from(uniqueRecords.values());
            const typeSelect = document.getElementById('record-type-filter');
            if (typeSelect) {
                const types = Array.from(new Set(recordsArray.map(r => (r.attributes || {}).RecordType).filter(Boolean)));
                typeSelect.innerHTML = '<option value="ALL">ALL</option>' + types.map(t => `<option value="${t}">${t}</option>`).join('');
                typeSelect.addEventListener('change', filterRecords);
            }

            const exportBtn = document.getElementById('export-records-csv');
            if (exportBtn) {
                exportBtn.onclick = () => exportRecordsToCSV(recordsArray);
            }

            recordsArray.forEach(rec => {
                const a = rec.attributes || {};
                const tr = document.createElement('tr');
                tr.className = 'dns-record-row cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-700';
                tr.addEventListener('click', () => {
                    tbody.querySelectorAll('tr').forEach(r => r.classList.remove('bg-neutral-200', 'dark:bg-neutral-800'));
                    tr.classList.add('bg-neutral-200', 'dark:bg-neutral-800');
                    fetchAndDisplayDnsRecordDetails(a.name, zoneName);
                });

                const nameTd = document.createElement('td');
                nameTd.className = 'px-3 py-2 text-neutral-900 dark:text-white';
                nameTd.textContent = a.name || '';

                const typeTd = document.createElement('td');
                typeTd.className = 'px-3 py-2 text-neutral-900 dark:text-white';
                typeTd.textContent = a.RecordType || '';

                const ttlTd = document.createElement('td');
                ttlTd.className = 'px-3 py-2 text-neutral-900 dark:text-white';
                ttlTd.textContent = a.TTL != null ? a.TTL : '';

                const valueTd = document.createElement('td');
                valueTd.className = 'px-3 py-2 text-neutral-900 dark:text-white';
                let val = a.Address || '';
                if (!val && a.RecordType === 'SRV') val = (a.Name || '') + (a.Port ? ':' + a.Port : '');
                if (!val && a.RecordType === 'SOA') val = a['Primary Server'] || a.Name || '';
                if (!val && Array.isArray(a.dnsRecord) && a.dnsRecord.length) {
                    try { val = convertToBase64(a.dnsRecord[0]); } catch (e) { val = '[raw]'; }
                }
                valueTd.textContent = val || '';
                
                const actionsTd = document.createElement('td');
                actionsTd.className = 'px-3 py-2 text-center';
                const delBtn = document.createElement('button');
                delBtn.className = 'text-red-600 hover:text-red-700 dark:text-red-500 dark:hover:text-red-400 p-1.5 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20';
                delBtn.title = `Delete ${a.name || ''}`;
                delBtn.innerHTML = '<i class="fas fa-trash"></i>';
                delBtn.addEventListener('click', async (ev) => {
                    ev.stopPropagation();
                    if (!a.name) return;
                    const ok = confirm(`Delete DNS record \"${a.name}\"?`);
                    if (!ok) return;
                    await deleteDnsRecord(a.name);
                    tr.remove();
                });
                actionsTd.appendChild(delBtn);

                tr.appendChild(nameTd);
                tr.appendChild(typeTd);
                tr.appendChild(ttlTd);
                tr.appendChild(valueTd);
                tr.appendChild(actionsTd);
                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            recordNameSection.appendChild(table);

        } catch (error) {
            console.error('Error loading DNS records:', error);
            showErrorAlert('Failed to load DNS records');
        } finally {
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
            const overlay = document.getElementById('modal-overlay') || document.getElementById('dns-details-overlay');
            
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
        if (deleteButton) {
            deleteButton.classList.remove('hidden');
            deleteButton.onclick = () => {
                const records = Array.isArray(data) ? data : [data];
                if (records.length > 0) showDeleteModal(records[0].attributes.name);
            };
        }

        const modal = document.getElementById('dns-record-details-modal');
        const overlay = document.getElementById('dns-details-overlay');
        const detailsContainer = document.getElementById('dns-record-details-content');
        if (!modal || !overlay || !detailsContainer) return;
        detailsContainer.innerHTML = '';

        const records = Array.isArray(data) ? data : [data];
        records.forEach((record, index) => {
            if (index > 0) {
                const separator = document.createElement('div');
                separator.classList.add('my-4', 'border-t', 'border-neutral-200', 'dark:border-neutral-700');
                detailsContainer.appendChild(separator);
            }

            const table = document.createElement('table');
            table.className = 'w-full text-sm border-collapse';
            const thead = document.createElement('thead');
            const hr = document.createElement('tr');
            const th1 = document.createElement('th');
            th1.className = 'text-left px-3 py-2 text-neutral-600 dark:text-neutral-400 font-medium';
            th1.textContent = 'Attribute';
            const th2 = document.createElement('th');
            th2.className = 'text-left px-3 py-2 text-neutral-600 dark:text-neutral-400 font-medium';
            th2.textContent = 'Value';
            hr.appendChild(th1); hr.appendChild(th2);
            thead.appendChild(hr);
            table.appendChild(thead);

            const tbody = document.createElement('tbody');
            tbody.className = '';

            const attributes = record.attributes || {};
            Object.entries(attributes).forEach(([key, value]) => {
                const isDn = Array.isArray(value) ? value.some(isValidDistinguishedName) : isValidDistinguishedName(value);
                const tr = document.createElement('tr');
                tr.className = 'align-top';

                const ktd = document.createElement('td');
                ktd.className = 'px-3 py-2 text-neutral-600 dark:text-neutral-400 w-1/3';
                ktd.textContent = key;

                const vtd = document.createElement('td');
                vtd.className = 'px-3 py-2 text-neutral-900 dark:text-white';

                if (key === 'dnsRecord') {
                    const val = Array.isArray(value) ? value.map(v => convertToBase64(v)).join('\n') : convertToBase64(value);
                    vtd.innerHTML = val.toString().split('\n').map(s => `<span class="block">${s}</span>`).join('');
                } else if (isDn) {
                    const arr = Array.isArray(value) ? value : [value];
                    vtd.innerHTML = arr.map(v => `<a href="#" class="text-blue-600 dark:text-yellow-500 hover:underline" onclick="handleLdapLinkClick(event, '${(v || '').replace(/'/g, "\\'")}')">${v}</a>`).join('<br>');
                } else if (Array.isArray(value)) {
                    vtd.innerHTML = value.map(v => `<span class="block">${v}</span>`).join('');
                } else {
                    vtd.textContent = value != null ? value : '';
                }

                tr.appendChild(ktd);
                tr.appendChild(vtd);
                tbody.appendChild(tr);
            });

            table.appendChild(tbody);
            detailsContainer.appendChild(table);
        });
        modal.classList.remove('hidden');
        overlay.classList.remove('hidden');
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
            const selectedZone = document.querySelector('.zone-row.bg-neutral-200, .zone-row.dark\\:bg-neutral-800');
            const zoneName = selectedZone ? selectedZone.querySelector('td')?.textContent : null;

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
        const zoneRows = document.querySelectorAll('.zone-row');
        zoneRows.forEach(row => {
            const cell = row.querySelector('td');
            const zoneName = (cell ? cell.textContent : '').toLowerCase();
            row.style.display = zoneName.includes(searchTerm) ? '' : 'none';
        });
    }

    function filterRecords() {
        const searchTerm = (document.getElementById('record-search')?.value || '').toLowerCase();
        const typeFilter = document.getElementById('record-type-filter')?.value || 'ALL';
        const rows = document.querySelectorAll('.dns-record-row');
        rows.forEach(row => {
            const cells = Array.from(row.getElementsByTagName('td'));
            const rowType = (cells[1]?.textContent || '').trim();
            const textContent = cells.map(cell => (cell.textContent || '').toLowerCase()).join(' ');
            const matchesSearch = textContent.includes(searchTerm);
            const matchesType = typeFilter === 'ALL' || rowType === typeFilter;
            row.style.display = matchesSearch && matchesType ? '' : 'none';
        });
    }

    // Modal overlay click to close
    const dnsDetailsOverlay = document.getElementById('dns-details-overlay');
    if (dnsDetailsOverlay) {
        dnsDetailsOverlay.addEventListener('click', () => {
            const modal = document.getElementById('dns-record-details-modal');
            modal.classList.add('hidden');
            dnsDetailsOverlay.classList.add('hidden');
        });
    }

    function exportRecordsToCSV(records) {
        try {
            const headers = ['Name','RecordType','TTL','Value'];
            const rows = records.map(r => {
                const a = r.attributes || {};
                let value = a.Address || '';
                if (!value && a.RecordType === 'SRV') value = (a.Name || '') + (a.Port ? ':' + a.Port : '');
                if (!value && a.RecordType === 'SOA') value = a['Primary Server'] || a.Name || '';
                if (!value && Array.isArray(a.dnsRecord) && a.dnsRecord.length) {
                    try { value = convertToBase64(a.dnsRecord[0]); } catch (e) { value = '[raw]'; }
                }
                return [a.name || '', a.RecordType || '', a.TTL != null ? a.TTL : '', (value || '').toString().replace(/\n/g,' ')]
                    .map(v => '"' + String(v).replace(/"/g,'""') + '"').join(',');
            });
            const csv = headers.join(',') + '\n' + rows.join('\n');
            const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = url;
            link.download = 'dns_records.csv';
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            URL.revokeObjectURL(url);
        } catch (e) { console.error('CSV export failed', e); }
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
