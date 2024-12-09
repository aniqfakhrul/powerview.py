document.addEventListener('DOMContentLoaded', () => {

    async function initialize() {
        try {
            const domainInfoResponse = await fetch('/api/get/domaininfo', {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                }
            });

            await handleHttpError(domainInfoResponse);

            const domainInfo = await domainInfoResponse.json();
            const rootDn = domainInfo.root_dn;

            const searchBase = document.getElementById('searchbase-input');
            if (searchBase) {
                searchBase.value = rootDn;
            }
        } catch (error) {
            console.error('Error during initialization:', error);
        }

        initializeButtonStyles();
    }
    
    const toggleButtons = document.querySelectorAll('.custom-toggle-switch');
    toggleButtons.forEach(toggleButton => {
        toggleButton.addEventListener('click', () => {
            const isAllButton = toggleButton.id === 'all-toggle';

            if (toggleButton.dataset.active === 'false') {
                toggleButton.dataset.active = 'true';
                toggleButton.classList.remove('dark:bg-neutral-900', 'dark:text-white');
                toggleButton.classList.add('bg-green-600', 'text-white', 'hover:bg-green-700');

                if (isAllButton) {
                    // Set only buttons under the properties card to inactive
                    const propertiesContainer = document.getElementById('properties-container');
                    const propertyButtons = propertiesContainer.querySelectorAll('.custom-toggle-switch');
                    propertyButtons.forEach(otherButton => {
                        if (otherButton !== toggleButton) {
                            otherButton.dataset.active = 'false';
                            otherButton.classList.remove('bg-green-600', 'text-white', 'hover:bg-green-700');
                            otherButton.classList.add('dark:bg-neutral-900', 'dark:text-white', 'dark:focus-visible:outline-neutral-900');
                        }
                    });
                }
            } else {
                toggleButton.dataset.active = 'false';
                toggleButton.classList.remove('bg-green-600', 'text-white', 'hover:bg-green-700');
                toggleButton.classList.add('dark:bg-neutral-900', 'dark:text-white', 'dark:focus-visible:outline-neutral-900');
            }
        });
    });

    function initializeButtonStyles() {
        const toggleButtons = document.querySelectorAll('.custom-toggle-switch');
        toggleButtons.forEach(toggleButton => {
            if (toggleButton.dataset.active === 'true') {
                toggleButton.classList.add('bg-green-600', 'text-white', 'hover:bg-green-700');
                toggleButton.classList.remove('dark:bg-neutral-900', 'dark:text-white', 'dark:focus-visible:outline-neutral-900');
            } else {
                toggleButton.classList.add('dark:bg-neutral-900', 'dark:text-white', 'dark:focus-visible:outline-neutral-900');
                toggleButton.classList.remove('bg-green-600', 'text-white', 'hover:bg-green-700');
            }
        });
    }

    
    // Add event listeners for all clear buttons
    document.querySelectorAll('.clear-input').forEach(button => {
        button.addEventListener('click', (event) => {
            const input = event.target.closest('.relative').querySelector('input');
            if (input) {
                input.value = '';
            }
        });
    });

    initialize();
});