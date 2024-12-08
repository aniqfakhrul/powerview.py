document.addEventListener('DOMContentLoaded', () => {
    const footerYear = document.querySelector('#footer-year');
    if (footerYear) {
        footerYear.textContent = currentYear();
    }

    async function executePowerViewCommand() {
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

            if (!response.ok) {
                const errorMessage = result.error || 'An unknown error occurred.';
                alert(`Error: ${errorMessage}`);
                return;
            }

            console.log('Command execution result:', result);
        } catch (error) {
            console.error('Error executing command:', error);
            alert('Failed to execute command. Please check the console for more details.');
        }
    }

    async function initialize() {
        checkConnectionStatus();
        try {
            const domainInfoResponse = await fetch('/api/get/domaininfo', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            if (!domainInfoResponse.ok) {
                throw new Error(`HTTP error! status: ${domainInfoResponse.status}`);
            }

            const domainInfo = await domainInfoResponse.json();
            const rootDn = domainInfo.root_dn;
            const domainName = domainInfo.domain;
            const flatName = domainInfo.flatName;

            const domainSpan = document.querySelector('span#domain-name');
            if (domainSpan) {
                domainSpan.textContent = flatName;
            }

            const distinguishedNames = [
                rootDn,
                `CN=Configuration,${rootDn}`,
                `CN=Schema,CN=Configuration,${rootDn}`,
                `DC=DomainDnsZones,${rootDn}`,
                `DC=ForestDnsZones,${rootDn}`
            ];

            for (const dn of distinguishedNames) {
                const exists = await checkDistinguishedNameExists(dn);
                if (exists) {
                    createTreeNode(dn);
                }
            }
        } catch (error) {
            console.error('Error during initialization:', error);
        }
    }

    async function checkDistinguishedNameExists(identity) {
        try {
            const response = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchbase: identity, search_scope: 'BASE' })
            });

            if (!response.ok) {
                return false;
            }

            const data = await response.json();
            return data && data.length > 0;
        } catch (error) {
            console.error('Error checking distinguished name:', error);
            return false;
        }
    }

function createTreeNode(dn) {
    const treeView = document.getElementById('tree-view');
    if (!treeView) return;

    const div = document.createElement('div');
    div.classList.add('flex', 'items-center', 'gap-1', 'hover:bg-gray-100', 'rounded', 'cursor-pointer');

    const buildingIcon = document.createElement('i');
    buildingIcon.classList.add('far', 'fa-folder', 'w-4', 'h-4', 'text-yellow-500');

    div.appendChild(buildingIcon);
    div.innerHTML += `<span>${dn}</span>`;

    div.addEventListener('click', async (event) => {
        event.stopPropagation();

        let subtreeContainer = div.nextElementSibling;
        if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
            subtreeContainer.remove();
            return;
        }

        const itemData = await fetchItemData(dn, 'BASE');
        if (itemData) {
            populateResultsPanel(itemData);
            toggleSubtree(dn, div);
        }
    });

    treeView.appendChild(div);
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

    async function fetchItemData(identity, search_scope = 'LEVEL') {
        console.log(identity);
        //showLoadingIndicator();
        try {
            const response = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchbase: identity, search_scope: search_scope })
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
            //hideLoadingIndicator();
        }
    }

    async function toggleSubtree(searchbase, parentElement) {
        let subtreeContainer = parentElement.nextElementSibling;
        if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
            subtreeContainer.remove();
            return; // Exit the function to prevent fetching data again
        }

        try {
            const response = await fetch('/api/get/domainobject', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ searchbase: searchbase, search_scope: 'LEVEL' })
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            const data = await response.json();
            console.log('Fetched data:', data); // Log the data to inspect its structure

            if (Array.isArray(data)) {
                displaySubtree(data, parentElement);
            } else if (data && typeof data === 'object') {
                displaySubtree([data], parentElement);
            } else {
                console.error('Unexpected data format:', data);
            }
        } catch (error) {
            console.error('Error fetching subtree:', error);
        }
    }

    function displaySubtree(dataArray, parentElement) {
        const subtreeContainer = document.createElement('div');
        subtreeContainer.classList.add('ml-6', 'subtree');

        dataArray.forEach(obj => {
            const objDiv = document.createElement('div');
            objDiv.classList.add('flex', 'items-center', 'gap-1', 'hover:bg-gray-100', 'rounded', 'cursor-pointer');

            let iconClasses = ['far', 'fa-folder']; // Default outlined icon
            let iconColorClass = 'text-blue-500'; // Default color for most objects

            if (obj.attributes.objectClass.includes('group')) {
                iconClasses = ['fas', 'fa-users']; // Use fa-users for groups
            } else if (obj.attributes.objectClass.includes('container')) {
                iconClasses = ['fas', 'fa-folder']; // Use fa-box-open for containers
                iconColorClass = 'text-yellow-500'; // Yellow for containers
            } else if (obj.attributes.objectClass.includes('computer')) {
                iconClasses = ['fas', 'fa-desktop']; // Use fa-desktop for computers
            } else if (obj.attributes.objectClass.includes('user')) {
                iconClasses = ['far', 'fa-user']; // Use fa-user-circle for users
            } else if (obj.attributes.objectClass.includes('organizationalUnit')) {
                iconClasses = ['far', 'fa-building']; // Use fa-building for organizational units
                iconColorClass = 'text-yellow-500'; // Yellow for organizational units
            }

            const icon = document.createElement('i');
            icon.classList.add(...iconClasses, 'w-4', 'h-4', 'mr-1', iconColorClass);

            objDiv.appendChild(icon);
            objDiv.innerHTML += `<span>${obj.attributes.name || obj.dn}</span>`;

            objDiv.addEventListener('click', async (event) => {
                event.stopPropagation();

                let childSubtreeContainer = objDiv.nextElementSibling;
                if (childSubtreeContainer && childSubtreeContainer.classList.contains('subtree')) {
                    childSubtreeContainer.remove();
                    return; // Exit the function to prevent fetching data again
                }

                const itemData = await fetchItemData(obj.dn, 'BASE', no_loading = true);
                if (itemData) {
                    populateResultsPanel(itemData);
                    toggleSubtree(obj.dn, objDiv);
                }
            });

            subtreeContainer.appendChild(objDiv);
        });

        parentElement.insertAdjacentElement('afterend', subtreeContainer);
    }

    function populateResultsPanel(item) {
        const resultsPanel = document.getElementById("results-panel");
        const attributes = item.attributes;

        let detailsHTML = `
            <div class="bg-gray-50 px-4 py-2 border-b">
                <h3 class="font-medium">${attributes.name || 'Details'}</h3>
            </div>
            <div class="p-4">
                <dl class="grid grid-cols-2 gap-4">
        `;

        for (const [key, value] of Object.entries(attributes)) {
            if (key === 'member' || key === 'memberOf' || key === 'objectCategory' || key === 'distinguishedName') {
                detailsHTML += `
                    <div>
                    <dt class="text-sm font-medium text-gray-500">${key}</dt>
                    <dd class="mt-1 text-sm text-gray-900">
                        ${Array.isArray(value) ? value.map(v => `<a href="#" class="text-blue-400 hover:text-blue-600 ldap-link" data-identity="${v}">${v}</a>`).join('<br>') : `<a href="#" class="text-blue-400 hover:text-blue-600 ldap-link" data-identity="${value}">${value}</a>`}
                        </dd>
                    </div>
                `;
            } else {
                detailsHTML += `
                    <div>
                        <dt class="text-sm font-medium text-gray-500">${key}</dt>
                        <dd class="mt-1 text-sm text-gray-900">${Array.isArray(value) ? value.join('<br>') : value}</dd>
                    </div>
                `;
            }
        }

        detailsHTML += `
                </dl>
            </div>
        `;

        resultsPanel.innerHTML = detailsHTML;

        attachLdapLinkListeners();
    }

    function attachLdapLinkListeners() {
        document.querySelectorAll('.ldap-link').forEach(link => {
            link.addEventListener('click', async (event) => {
                event.preventDefault();
                const identity = event.target.dataset.identity;
                const detailsPanel = document.getElementById('details-panel');
                const commandHistoryPanel = document.getElementById('command-history-panel');

                // Check if the details panel is already showing the clicked identity
                const currentDistinguishedName = detailsPanel.getAttribute('data-distinguished-name');

                if (currentDistinguishedName === identity) {
                    // Toggle visibility if the same item is clicked again
                    detailsPanel.classList.toggle('hidden');
                    return;
                }

                // Fetch and populate details if a different item is clicked
                const itemData = await fetchItemData(identity, 'BASE');
                if (itemData) {
                    populateDetailsPanel(itemData);
                    detailsPanel.setAttribute('data-distinguished-name', identity); // Store the current identity
                    detailsPanel.classList.remove('hidden');
                    commandHistoryPanel.classList.add('hidden');    
                }
            });
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
        console.log(item)
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

    function showLoadingIndicator() {
        const resultsPanel = document.getElementById("results-panel");
        resultsPanel.innerHTML = '<div class="loading">Loading...</div>';
    }

    function hideLoadingIndicator() {
        // Optionally clear the loading indicator if needed
    }

    function currentYear() {
        return new Date().getFullYear();
    }

    async function checkConnectionStatus() {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 5000); // Set timeout to 5 seconds

        try {
            const response = await fetch('/api/status', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                },
                signal: controller.signal
            });

            const statusElement = document.getElementById('connection-status');
            const iconElement = document.querySelector('.fa-wifi');

            if (response.ok) {
                const data = await response.json();
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
            const statusElement = document.getElementById('connection-status');
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

    setInterval(checkConnectionStatus, 300000);

    // function openModal(userDetails) {
    //     const modal = document.getElementById('user-modal');
    //     const modalContent = document.getElementById('modal-content');
    //     const modalTitle = document.getElementById('modal-title');

    //     // Set the modal title and content
    //     modalTitle.textContent = `Details for ${userDetails.name}`;
    //     modalContent.innerHTML = `
    //         <p><strong>Distinguished Name:</strong> ${userDetails.dn}</p>
    //         <p><strong>Email:</strong> ${userDetails.email}</p>
    //         <p><strong>Phone:</strong> ${userDetails.phone}</p>
    //         <!-- Add more user details as needed -->
    //     `;

    //     // Show the modal
    //     modal.classList.remove('hidden');
    // }

    // function closeModal() {
    //     const modal = document.getElementById('user-modal');
    //     modal.classList.add('hidden');
    // }

    // // Example usage: Attach this function to user elements in your results section
    // document.querySelectorAll('#details-title').forEach(element => {
    //     element.addEventListener('click', function() {
    //         const userDetails = {
    //             name: 'test',
    //             dn: 'test',
    //             email: 'test',
    //             phone: 'test'
    //         };
    //         openModal(userDetails);
    //     });
    // });
    const convertFromSidButton = document.querySelector('#convertfromsid-button');
    if (convertFromSidButton) {
        convertFromSidButton.addEventListener('click', async () => {
            const sidInput = document.querySelector('input[placeholder="S-1-5-21-..."]').value.trim();
            if (!sidInput) {
                alert('Please enter a SID.');
                return;
            }

            try {
                const response = await fetch('/api/convert/sid', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ objectsid: sidInput })
                });

                const data = await response.json();
                // console.log('ConvertFrom_SID result:', data);

                // Display the result
                const resultElement = document.getElementById('convertfromsid-result');
                resultElement.querySelector('p').textContent = JSON.stringify(data, null, 2);
                resultElement.classList.remove('hidden');
            } catch (error) {
                console.error('Error converting SID:', error);
            }
        });
    }

    // Check if the ConvertFrom_UAC button exists before adding an event listener
    const convertFromUacButton = document.querySelector('#convertfromuac-button');
    if (convertFromUacButton) {
        convertFromUacButton.addEventListener('click', async () => {
            const uacInput = document.querySelector('input[placeholder="Enter UAC value..."]').value.trim();
            if (!uacInput) {
                alert('Please enter a UAC value.');
                return;
            }

            try {
                const response = await fetch('/api/convert/uacvalue', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ value: uacInput })
                });

                const data = await response.json();
                // console.log('ConvertFrom_UAC result:', data);

                // Display the result in a prettier format
                const resultElement = document.getElementById('convertfromuac-result');
                const formattedData = data.map(item => `<li>${item.attributes.Name}: ${item.attributes.Value}</li>`).join('');
                resultElement.querySelector('p').innerHTML = `<ul>${formattedData}</ul>`;
                resultElement.classList.remove('hidden');
            } catch (error) {
                console.error('Error converting UAC:', error);
            }
        });
    }

    initialize();
    const executeButton = document.querySelector('button#execute-button');
    if (executeButton) {
        executeButton.addEventListener('click', executePowerViewCommand);
    }
});