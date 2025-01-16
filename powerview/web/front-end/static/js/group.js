document.addEventListener('DOMContentLoaded', () => {
    let currentSelectedGroup = null;
    let allGroups = []; // Store all groups for filtering
    let allMembers = []; // Store all members for filtering

    // Add event listeners for search inputs
    const groupSearchInput = document.getElementById('group-search');
    const memberSearchInput = document.getElementById('member-search');

    groupSearchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        filterGroups(searchTerm);
    });

    memberSearchInput.addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        filterMembers(searchTerm);
    });

    function filterGroups(searchTerm) {
        const tbody = document.querySelector('.groups-container table tbody');
        if (!tbody) return;

        Array.from(tbody.getElementsByTagName('tr')).forEach(row => {
            const name = row.cells[0].textContent.toLowerCase();
            
            if (name.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    function filterMembers(searchTerm) {
        const tbody = document.querySelector('.members-container table tbody');
        if (!tbody) return;

        Array.from(tbody.getElementsByTagName('tr')).forEach(row => {
            const name = row.cells[0].textContent.toLowerCase();
            const domain = row.cells[1].textContent.toLowerCase();
            const dn = row.cells[2].textContent.toLowerCase();
            
            if (name.includes(searchTerm) || 
                domain.includes(searchTerm) || 
                dn.includes(searchTerm)) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
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
            
            const groupsContainer = document.querySelector('.groups-container');
            if (!groupsContainer) return;

            groupsContainer.innerHTML = ''; // Clear existing content

            // Create and populate the groups table
            const table = document.createElement('table');
            table.className = 'min-w-full text-sm text-neutral-600 dark:text-neutral-300';

            // Create table header
            const thead = document.createElement('thead');
            thead.className = 'sticky text-left top-0 border-b border-neutral-300 bg-neutral-50 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white';
            
            const headerRow = document.createElement('tr');
            ['Name', 'Member Count'].forEach((headerText, index) => {
                const th = document.createElement('th');
                th.textContent = headerText;
                th.className = `px-4 py-3 font-medium ${index === 1 ? 'text-center' : ''}`;
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            // Create table body
            const tbody = document.createElement('tbody');
            tbody.className = 'divide-y divide-neutral-200 dark:divide-neutral-700';

            // Sort data by member count in descending order
            const sortedData = data.sort((a, b) => {
                const countA = getMemberCount(a.attributes.member);
                const countB = getMemberCount(b.attributes.member);
                return countB - countA; // Descending order
            });

            sortedData.forEach(group => {
                const row = document.createElement('tr');
                row.className = 'cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800';
                
                row.addEventListener('click', () => {
                    tbody.querySelectorAll('tr').forEach(r => {
                        r.classList.remove('bg-neutral-200', 'dark:bg-neutral-700');
                    });
                    row.classList.add('bg-neutral-200', 'dark:bg-neutral-700');
                    
                    currentSelectedGroup = group.attributes.name;
                    fetchGroupMembers(group.attributes.name);
                });

                // Add cells
                const nameCell = document.createElement('td');
                nameCell.textContent = group.attributes.name;
                nameCell.className = 'px-4 py-3';

                const countCell = document.createElement('td');
                const memberCount = getMemberCount(group.attributes.member);
                countCell.textContent = memberCount;
                countCell.className = 'px-4 py-3 text-center';

                row.appendChild(nameCell);
                row.appendChild(countCell);
                tbody.appendChild(row);
            });

            table.appendChild(tbody);
            groupsContainer.appendChild(table);

        } catch (error) {
            console.error('Error fetching groups:', error);
            showErrorAlert('Failed to fetch domain groups');
        } finally {
            hideLoadingIndicator();
        }
    }

    async function fetchGroupMembers(groupName) {
        showLoadingIndicator();
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
            const data = await response.json();
            allMembers = data;

            const memberSearchInput = document.getElementById('member-search');
            if (memberSearchInput) {
                memberSearchInput.value = '';
            }

            const membersContainer = document.querySelector('.members-container');
            if (!membersContainer) return;

            const memberHeader = document.querySelector('.member-header');
            if (memberHeader) {
                memberHeader.textContent = `Members of ${groupName}`;
            }

            const table = document.createElement('table');
            table.className = 'min-w-full text-sm text-neutral-600 dark:text-neutral-300';

            const thead = document.createElement('thead');
            thead.className = 'top-0 border-b border-neutral-300 bg-neutral-50 text-sm text-neutral-900 dark:border-neutral-700 dark:bg-neutral-900 dark:text-white';
            
            const headerRow = document.createElement('tr');
            ['Member Name', 'Member Domain', 'Distinguished Name'].forEach(headerText => {
                const th = document.createElement('th');
                th.textContent = headerText;
                th.className = 'px-4 py-3 font-medium text-left';
                headerRow.appendChild(th);
            });
            thead.appendChild(headerRow);
            table.appendChild(thead);

            const tbody = document.createElement('tbody');
            tbody.className = 'divide-y divide-neutral-200 dark:divide-neutral-700';

            data.forEach(member => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-100 dark:hover:bg-neutral-800 cursor-pointer group';
                
                row.addEventListener('click', (event) => {
                    if (!event.target.closest('button')) {  // Only handle click if not clicking copy button
                        handleLdapLinkClick(event, member.attributes.MemberDistinguishedName);
                    }
                });

                // Create cells with copy buttons
                const cells = [
                    { value: member.attributes.MemberName },
                    { value: member.attributes.MemberDomain },
                    { value: member.attributes.MemberDistinguishedName }
                ];

                cells.forEach(({ value }) => {
                    const td = document.createElement('td');
                    td.className = 'px-4 py-3 text-left relative';

                    const wrapper = document.createElement('div');
                    wrapper.className = 'flex items-center gap-2';

                    const textSpan = document.createElement('span');
                    textSpan.textContent = value;

                    const copyButton = document.createElement('button');
                    copyButton.className = 'opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800';
                    copyButton.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
                    copyButton.title = 'Copy to clipboard';
                    
                    copyButton.addEventListener('click', async (event) => {
                        event.stopPropagation();
                        
                        try {
                            if (navigator.clipboard && window.isSecureContext) {
                                await navigator.clipboard.writeText(value);
                            } else {
                                const textArea = document.createElement('textarea');
                                textArea.value = value;
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
                    row.appendChild(td);
                });

                tbody.appendChild(row);
            });

            table.appendChild(tbody);
            membersContainer.innerHTML = '';
            membersContainer.appendChild(table);

        } catch (error) {
            console.error('Error fetching group members:', error);
            showErrorAlert('Failed to fetch group members');
        } finally {
            hideLoadingIndicator();
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
});
