async function fetchAndDisplayDomainOU() {
    try {
        const response = await fetch('/api/get/domainobject', {
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

            const svg1 = document.createElement('svg');
            svg1.classList.add('w-4', 'h-4', 'text-gray-500');
            svg1.setAttribute('fill', 'none');
            svg1.setAttribute('stroke', 'currentColor');
            svg1.setAttribute('viewBox', '0 0 24 24');
            svg1.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            svg1.innerHTML = '<path d="m6 9 6 6 6-6"></path>';

            const svg2 = document.createElement('svg');
            svg2.classList.add('w-4', 'h-4', 'text-yellow-500');
            svg2.setAttribute('fill', 'none');
            svg2.setAttribute('stroke', 'currentColor');
            svg2.setAttribute('viewBox', '0 0 24 24');
            svg2.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
            svg2.innerHTML = '<path d="M20 20a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-7.9a2 2 0 0 1-1.69-.9L9.6 3.9A2 2 0 0 0 7.93 3H4a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"></path>';

            div.appendChild(svg1);
            div.appendChild(svg2);
            div.innerHTML += `<span>${name}</span>`;

            div.addEventListener('click', () => fetchAndDisplaySubtree(searchbase, div));
            treeView.appendChild(div);
        });
    } catch (error) {
        console.error('Error fetching domain OU:', error);
    }
}

async function fetchAndDisplaySubtree(searchbase, parentElement) {
    try {
        const response = await fetch(`/api/get/domainobject?searchbase=${encodeURIComponent(searchbase)}`, {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json',
            }
        });

        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('Subtree Data:', data);

        let subtreeContainer = parentElement.querySelector('.subtree');
        if (subtreeContainer) {
            subtreeContainer.remove();
        }

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
            subtreeContainer.appendChild(objDiv);
        });

        parentElement.appendChild(subtreeContainer);

    } catch (error) {
        console.error('Error fetching subtree:', error);
    }
}

fetchAndDisplayDomainOU();
