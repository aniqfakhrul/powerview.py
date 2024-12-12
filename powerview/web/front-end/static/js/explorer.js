function executePowerViewCommand() {
    const searchInput = document.querySelector('input[name="object-search"]').value;
    console.log(searchInput);
    fetch('/api/get/domainobject', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ identity: searchInput })
    })
    .then(response => response.json())
    .then(data => {
        if (data && data.length > 0) {
            const dn = data[0].dn;
            const name = data[0].attributes.name;
            expandTreeView(dn, name);
        }
    })
    .catch(error => console.error('Error:', error));
}

function expandTreeView(dn, name) {
    const parts = dn.split(',');
    const treePath = parts.reverse().map(part => part.split('=')[1]);
    // Assuming you have a function to expand the tree based on the path
    expandTreePath(treePath);
}

function expandTreePath(treePath) {
    // Example logic to expand the tree
    let currentNode = document.getElementById('tree-view');
    treePath.forEach(part => {
        const node = currentNode.querySelector(`[data-name="${part}"]`);
        if (node) {
            node.classList.add('expanded'); // Assuming 'expanded' is a class that shows the node
            currentNode = node;
        }
    });
}

function selectTab(tabName) {
    const tabs = ['general', 'group', 'dacl'];
    tabs.forEach(tab => {
        const button = document.querySelector(`button[aria-controls="tabpanel${tab.charAt(0).toUpperCase() + tab.slice(1)}"]`);
        const panel = document.getElementById(`tabpanel${tab.charAt(0).toUpperCase() + tab.slice(1)}`);
        if (tab === tabName) {
            button.setAttribute('aria-selected', 'true');
            button.setAttribute('tabindex', '0');
            button.classList.add('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
            panel.style.display = 'block';
        } else {
            button.setAttribute('aria-selected', 'false');
            button.setAttribute('tabindex', '-1');
            button.classList.remove('font-bold', 'text-black', 'border-b-2', 'border-black', 'dark:border-yellow-500', 'dark:text-yellow-500');
            button.classList.add('text-neutral-600', 'font-medium', 'dark:text-neutral-300', 'dark:hover:border-b-neutral-300', 'dark:hover:text-white', 'hover:border-b-2', 'hover:border-b-neutral-800', 'hover:text-neutral-900');
            panel.style.display = 'none';
        }
    });
}

document.addEventListener('DOMContentLoaded', () => {
    const searchInput = document.getElementById('tab-search');
    const clearButton = document.querySelector('.clear-input');
    const tabPanels = document.querySelectorAll('[role="tabpanel"]');

    // Store the current filter state
    let currentFilter = '';

    if (searchInput) {
        searchInput.addEventListener('input', () => {
            currentFilter = searchInput.value.toLowerCase();
            filterTabResults(currentFilter);
        });

        clearButton.addEventListener('click', () => {
            searchInput.value = '';
            currentFilter = '';
            filterTabResults('');
        });
    }

    function filterTabResults(query) {
        const activeTabButton = document.querySelector('[role="tab"][aria-selected="true"]');
        if (!activeTabButton) return;

        const activePanelId = activeTabButton.getAttribute('aria-controls');
        const activePanel = document.getElementById(activePanelId);

        if (activePanel) {
            const items = activePanel.querySelectorAll('.result-item');
            items.forEach(item => {
                const text = item.textContent.toLowerCase();
                if (text.includes(query)) {
                    item.classList.remove('hidden');
                } else {
                    item.classList.add('hidden');
                }
            });
        }
    }
});