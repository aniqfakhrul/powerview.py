document.addEventListener('DOMContentLoaded', () => {
    async function initialize() {
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
        const div = document.createElement('div');
        div.classList.add('flex', 'items-center', 'gap-1', 'p-1', 'hover:bg-gray-100', 'rounded', 'cursor-pointer');

        const folderIcon = document.createElement('svg');
        folderIcon.classList.add('w-4', 'h-4', 'text-yellow-500');
        folderIcon.setAttribute('fill', 'none');
        folderIcon.setAttribute('stroke', 'currentColor');
        folderIcon.setAttribute('viewBox', '0 0 24 24');
        folderIcon.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        folderIcon.innerHTML = '<path d="M3 7v4a1 1 0 001 1h3m10 0h3a1 1 0 001-1V7m-4 0V5a2 2 0 00-2-2H8a2 2 0 00-2 2v2m0 0h12"></path>';

        div.appendChild(folderIcon);
        div.innerHTML += `<span>${dn}</span>`;

        div.addEventListener('click', async (event) => {
            event.stopPropagation();

            let subtreeContainer = div.nextElementSibling;
            if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
                subtreeContainer.remove();
                return;
            }

            showLoadingIndicator();
            const itemData = await fetchItemData(dn, 'BASE');
            if (itemData) {
                populateDetailsPanel(itemData);
                toggleSubtree(dn, div);
            }
            hideLoadingIndicator();
        });

        treeView.appendChild(div);
    }

    async function fetchItemData(identity, search_scope = 'LEVEL') {
        console.log(identity);
        showLoadingIndicator();
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
        }
    }

    async function toggleSubtree(searchbase, parentElement) {
        let subtreeContainer = parentElement.nextElementSibling;
        if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
            subtreeContainer.remove();
            return;
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

            subtreeContainer = document.createElement('div');
            subtreeContainer.classList.add('ml-6', 'subtree');

            data.forEach(obj => {
                const objDiv = document.createElement('div');
                objDiv.classList.add('flex', 'items-center', 'gap-1', 'p-1', 'hover:bg-gray-100', 'rounded', 'cursor-pointer');

                const svg = document.createElement('svg');
                svg.classList.add('w-4', 'h-4', 'text-blue-500');
                svg.setAttribute('fill', 'none');
                svg.setAttribute('stroke', 'currentColor');
                svg.setAttribute('viewBox', '0 0 24 24');
                svg.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
                svg.innerHTML = '<path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 7v4a1 1 0 001 1h3m10 0h3a1 1 0 001-1V7m-4 0V5a2 2 0 00-2-2H8a2 2 0 00-2 2v2m0 0h12"></path>';

                objDiv.appendChild(svg);
                objDiv.innerHTML += `<span>${obj.attributes.name || obj.dn}</span>`;

                objDiv.addEventListener('click', async (event) => {
                    event.stopPropagation();
                    const itemData = await fetchItemData(obj.dn, search_scope='BASE');
                    if (itemData) {
                        populateDetailsPanel(itemData);
                        toggleSubtree(obj.dn, objDiv);
                    }
                    hideLoadingIndicator();
                });

                subtreeContainer.appendChild(objDiv);
            });

            parentElement.insertAdjacentElement('afterend', subtreeContainer);

        } catch (error) {
            console.error('Error fetching subtree:', error);
        }
    }

    function populateDetailsPanel(item) {
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
            detailsHTML += `
                <div>
                    <dt class="text-sm font-medium text-gray-500">${key}</dt>
                    <dd class="mt-1 text-sm text-gray-900">${Array.isArray(value) ? value.join('<br>') : value}</dd>
                </div>
            `;
        }

        detailsHTML += `
                </dl>
            </div>
        `;

        resultsPanel.innerHTML = detailsHTML;
    }

    function showLoadingIndicator() {
        const resultsPanel = document.getElementById("results-panel");
        resultsPanel.innerHTML = '<div class="loading">Loading...</div>';
    }

    function hideLoadingIndicator() {
        // Optionally clear the loading indicator if needed
    }

    initialize();
});