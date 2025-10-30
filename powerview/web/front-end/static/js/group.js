document.addEventListener('DOMContentLoaded', () => {
    let expandedGroup = null;
    let allGroups = [];

    const groupSearchInput = document.getElementById('group-search');
    groupSearchInput.addEventListener('input', (e) => {
        filterGroups((e.target.value || '').toLowerCase());
    });

    function filterGroups(searchTerm) {
        const tbody = document.querySelector('.groups-container table tbody');
        if (!tbody) return;
        Array.from(tbody.querySelectorAll('tr.group-row')).forEach(row => {
            const name = (row.querySelector('td')?.textContent || '').toLowerCase();
            row.style.display = name.includes(searchTerm) ? '' : 'none';
            const details = row.nextElementSibling;
            if (details && details.classList.contains('group-details-row')) {
                details.style.display = row.style.display;
            }
        });
    }

    async function fetchAndDisplayGroups() {
        showLoadingIndicator();
        try {
            const response = await fetch('/api/get/domaingroup', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            await handleHttpError(response);
            const data = await response.json();
            allGroups = data; // Store all groups
            
            const container = document.querySelector('.groups-container');
            if (!container) return;
            container.innerHTML = '';

            const table = document.createElement('table');
            table.className = 'min-w-full text-sm text-neutral-600 dark:text-neutral-300';
            const thead = document.createElement('thead');
            thead.className = 'sticky text-left top-0 border-b border-neutral-300 bg-neutral-50 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white';
            const hr = document.createElement('tr');
            ['Name','Member Count'].forEach((h,i)=>{
                const th=document.createElement('th');
                th.textContent=h; th.className=`px-4 py-3 font-medium ${i===1?'text-center':''}`; hr.appendChild(th);
            });
            thead.appendChild(hr); table.appendChild(thead);

            const tbody = document.createElement('tbody');
            tbody.className = '';

            const sortedData = data.sort((a,b)=>{
                const countA = getMemberCount(a.attributes.member);
                const countB = getMemberCount(b.attributes.member);
                return countB - countA;
            });

            sortedData.forEach(group => {
                const groupName = group.attributes.name;
                const memberCount = getMemberCount(group.attributes.member);

                const row = document.createElement('tr');
                row.className = 'group-row cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800';
                row.addEventListener('click', async () => {
                    const detailsRow = row.nextElementSibling;
                    const isOpen = detailsRow && detailsRow.classList.contains('group-details-row');
                    if (isOpen) {
                        detailsRow.remove();
                        row.classList.remove('active-group-row','border-b-2','border-yellow-500','dark:border-yellow-500');
                        expandedGroup = null;
                        return;
                    }
                    if (expandedGroup) {
                        const openRows = tbody.querySelectorAll('tr.group-details-row');
                        openRows.forEach(r => r.remove());
                        const prevActive = tbody.querySelector('tr.active-group-row');
                        if (prevActive) prevActive.classList.remove('active-group-row','border-b-2','border-yellow-500','dark:border-yellow-500');
                    }
                    const members = await fetchGroupMembers(groupName);
                    const dr = document.createElement('tr');
                    dr.className = 'group-details-row bg-neutral-50 dark:bg-neutral-900';
                    const td = document.createElement('td');
                    td.colSpan = 2;
                    td.className = 'px-4 py-3';
                    td.innerHTML = buildMembersTable(groupName, members);
                    dr.appendChild(td);
                    row.insertAdjacentElement('afterend', dr);
                    row.classList.add('active-group-row','border-b-2','border-yellow-500','dark:border-yellow-500');
                    expandedGroup = groupName;
                });

                const nameCell = document.createElement('td');
                nameCell.className = 'px-4 py-3';
                nameCell.textContent = groupName;
                const countCell = document.createElement('td');
                countCell.className = 'px-4 py-3 text-center';
                countCell.textContent = memberCount;
                row.appendChild(nameCell); row.appendChild(countCell); tbody.appendChild(row);
            });

            table.appendChild(tbody); container.appendChild(table);

        } catch (error) {
            console.error('Error fetching groups:', error);
            showErrorAlert('Failed to fetch domain groups');
        } finally {
            hideLoadingIndicator();
        }
    }

    async function fetchGroupMembers(groupName) {
        try {
            const response = await fetch('/api/get/domaingroupmember', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    identity: groupName
                })
            });
            await handleHttpError(response);
            return await response.json();
        } catch (error) {
            console.error('Error fetching group members:', error);
            showErrorAlert('Failed to fetch group members');
            return [];
        }
    }

    // Initialize the page
    fetchAndDisplayGroups();

    // Add helper function to calculate member count
    function getMemberCount(member) {
        if (!member) return 0;
        if (Array.isArray(member)) return member.length;
        if (typeof member === 'string') return 1;
        return 0;
    }

    function buildMembersTable(groupName, data) {
        if (!Array.isArray(data) || data.length === 0) {
            return '<div class="text-sm text-neutral-500 dark:text-neutral-400">No members found</div>';
        }
        const rows = data.map(m => {
            const a = m.attributes || {};
            const name = a.MemberName || '';
            const domain = a.MemberDomain || '';
            const dn = a.MemberDistinguishedName || '';
            const escDn = (dn||'').replace(/'/g, "\\'");
            const escGroup = (groupName||'').replace(/'/g, "\\'");
            return `<tr class="hover:bg-neutral-100 dark:hover:bg-neutral-800 cursor-pointer border-b border-neutral-200 dark:border-neutral-800" onclick="handleLdapLinkClick(event, '${escDn}')">
                        <td class="px-3 py-2">${name}</td>
                        <td class="px-3 py-2">${domain}</td>
                        <td class="px-3 py-2">${dn}</td>
                        <td class="px-3 py-2 text-right">
                            <button class="text-red-600 hover:text-red-700 dark:text-red-500 dark:hover:text-red-400 p-1 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20"
                                    title="Remove from group"
                                    onclick="removeGroupMember(event, '${escGroup}', '${escDn}')">
                                <i class="fas fa-trash"></i>
                            </button>
                        </td>
                    </tr>`;
        }).join('');
        return `<div class="rounded-md overflow-hidden">
                    <table class="min-w-full text-sm">
                        <thead class="bg-neutral-50 dark:bg-neutral-900 text-neutral-700 dark:text-neutral-300">
                            <tr><th class="px-3 py-2 text-left">Member Name</th><th class="px-3 py-2 text-left">Member Domain</th><th class="px-3 py-2 text-left">Distinguished Name</th><th class="px-3 py-2 text-right">Action</th></tr>
                        </thead>
                        <tbody>${rows}</tbody>
                    </table>
                </div>`;
    }

    // expose global handler for inline button
    window.removeGroupMember = async function(event, groupName, memberDn) {
        try {
            event.stopPropagation();
            showLoadingIndicator();
            const response = await fetch('/api/remove/domaingroupmember', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ identity: groupName, members: memberDn })
            });
            await handleHttpError(response);
            const result = await response.json();
            if (result === false) {
                showErrorAlert('Failed to remove group member');
                return;
            }
            const tr = event.target.closest('tr');
            if (tr) tr.remove();
            const detailsTd = event.target.closest('table')?.parentElement;
            const groupRow = detailsTd?.parentElement?.previousElementSibling;
            const countCell = groupRow?.cells?.[1];
            if (countCell) {
                const cur = parseInt(countCell.textContent || '0', 10);
                if (!isNaN(cur) && cur > 0) countCell.textContent = String(cur - 1);
            }
            showSuccessAlert('Member removed from group');
        } catch (e) {
            console.error('Remove member failed', e);
            showErrorAlert('Failed to remove group member');
        } finally {
            hideLoadingIndicator();
        }
    }
});
