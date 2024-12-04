async function initialize() {
    try {
        const response = await fetch('/api/get/domainou', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Domain OU Data:', data);

        const treeView = document.getElementById('tree-view');
        treeView.innerHTML = '';

        data.forEach(item => {
            const name = item.attributes.name;
            const searchbase = item.dn;
            const div = document.createElement('div');
            div.classList.add('flex', 'items-center', 'gap-1', 'p-1', 'hover:bg-gray-100', 'rounded', 'cursor-pointer', 'dropdown-toggle');

            const folderIcon = document.createElement('svg');
            folderIcon.classList.add('w-4', 'h-4', 'text-yellow-500');
            folderIcon.setAttribute('fill', 'none');
            folderIcon.setAttribute('stroke', 'currentColor');
            folderIcon.setAttribute('viewBox', '0 0 24 24');
            folderIcon.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            folderIcon.innerHTML = '<path d="M3 7v4a1 1 0 001 1h3m10 0h3a1 1 0 001-1V7m-4 0V5a2 2 0 00-2-2H8a2 2 0 00-2 2v2m0 0h12"></path>';

            div.appendChild(folderIcon);
            div.innerHTML += `<span>${name}</span>`;

            div.addEventListener('click', () => toggleSubtree(searchbase, div));
            treeView.appendChild(div);
        });
    } catch (error) {
        console.error('Error fetching domain OU:', error);
    }
}

async function toggleSubtree(searchbase, parentElement) {
    // Check if the subtree is already visible
    let subtreeContainer = parentElement.nextElementSibling;
    if (subtreeContainer && subtreeContainer.classList.contains('subtree')) {
        // If visible, remove it to close the dropdown
        subtreeContainer.remove();
        return;
    }

    // If not visible, fetch and display the subtree
    try {
        const response = await fetch('/api/get/domainobject', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ searchbase: searchbase })
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Subtree Data:', data);

        // Create a new subtree container
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

            // Add click event listener to populate details panel
            objDiv.addEventListener('click', (event) => {
                event.stopPropagation(); // Prevent event bubbling
                populateDetailsPanel(obj);
                toggleSubtree(obj.dn, objDiv);
            });

            subtreeContainer.appendChild(objDiv);
        });

        // Insert the subtree after the parent element
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
                <dd class="mt-1 text-sm text-gray-900">${Array.isArray(value) ? value.join(', ') : value}</dd>
            </div>
        `;
    }

    detailsHTML += `
            </dl>
        </div>
    `;

    resultsPanel.innerHTML = detailsHTML;
}

initialize();
