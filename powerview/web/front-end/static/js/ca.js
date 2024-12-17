document.addEventListener('DOMContentLoaded', function() {
    fetchCAServers();

    // Initialize filter buttons
    const filterButtons = {
        all: document.getElementById('filter-all'),
        enabled: document.getElementById('filter-enabled'),
        disabled: document.getElementById('filter-disabled'),
        vulnerable: document.getElementById('filter-vulnerable')
    };

    let currentFilter = 'all';
    let currentSearchText = '';

    // Set "All" filter as active by default
    filterButtons.all.classList.remove('bg-neutral-200', 'dark:bg-neutral-700');
    filterButtons.all.classList.add('bg-blue-500', 'dark:bg-blue-700', 'text-white');

    // Add click handlers for filter buttons
    Object.entries(filterButtons).forEach(([type, button]) => {
        button.addEventListener('click', () => {
            // Update active state of buttons
            Object.values(filterButtons).forEach(btn => {
                btn.classList.remove('bg-blue-500', 'dark:bg-blue-700', 'text-white');
                btn.classList.add('bg-neutral-200', 'dark:bg-neutral-700');
            });
            button.classList.remove('bg-neutral-200', 'dark:bg-neutral-700');
            button.classList.add('bg-blue-500', 'dark:bg-blue-700', 'text-white');

            currentFilter = type;
            applyFilters();
        });
    });

    // Add search filter functionality
    const filterInput = document.getElementById('template-filter');
    filterInput.addEventListener('input', function() {
        currentSearchText = this.value.toLowerCase();
        applyFilters();
    });

    function applyFilters() {
        const templates = document.querySelectorAll('.cert-templates-container > div');
        
        templates.forEach(template => {
            const templateName = template.querySelector('span').textContent.toLowerCase();
            const isEnabled = template.querySelector('.bg-green-100') !== null;
            const isVulnerable = template.querySelector('.bg-red-100') !== null;

            let shouldShow = true;

            // Apply type filter
            switch(currentFilter) {
                case 'enabled':
                    shouldShow = isEnabled;
                    break;
                case 'disabled':
                    shouldShow = !isEnabled;
                    break;
                case 'vulnerable':
                    shouldShow = isVulnerable;
                    break;
                case 'all':
                default:
                    shouldShow = true;
            }

            // Apply text filter
            if (shouldShow && currentSearchText) {
                shouldShow = templateName.includes(currentSearchText);
            }

            template.classList.toggle('hidden', !shouldShow);
        });
    }

    function fetchCAServers() {
        fetch('/api/get/domainca')
            .then(response => response.json())
            .then(data => {
                const container = document.querySelector('.ca-servers-container');
                container.innerHTML = '';
                
                if (!data || data.length === 0) {
                    container.innerHTML = `
                        <div class="flex items-center justify-center h-full text-neutral-500">
                            <div class="text-center">
                                <i class="fa-solid fa-certificate mb-2 text-2xl"></i>
                                <p>No CA servers found</p>
                            </div>
                        </div>`;
                    return;
                }
                
                data.forEach(ca => {
                    const caElement = document.createElement('div');
                    caElement.className = 'p-3 hover:bg-neutral-100 dark:hover:bg-neutral-700 rounded-lg cursor-pointer mb-2';
                    caElement.innerHTML = `
                        <div class="flex items-center gap-2">
                            <i class="fa-solid fa-certificate text-neutral-600 dark:text-neutral-400"></i>
                            <span class="text-neutral-700 dark:text-neutral-300">${ca.attributes.cn}</span>
                        </div>
                    `;
                    caElement.addEventListener('click', () => {
                        document.querySelectorAll('.ca-servers-container > div').forEach(el => {
                            el.classList.remove('bg-neutral-100', 'dark:bg-neutral-700');
                        });
                        caElement.classList.add('bg-neutral-100', 'dark:bg-neutral-700');
                        
                        // Show CA details first
                        showCADetails(ca);
                        
                        // Then fetch and show templates
                        fetchCertificateTemplates(ca.attributes.cn);
                    });
                    container.appendChild(caElement);
                });
            })
            .catch(error => {
                console.error('Error fetching CA servers:', error);
                const container = document.querySelector('.ca-servers-container');
                container.innerHTML = `
                    <div class="flex items-center justify-center h-full text-neutral-500">
                        <div class="text-center">
                            <i class="fa-solid fa-circle-exclamation mb-2 text-2xl"></i>
                            <p>Failed to fetch CA servers</p>
                        </div>
                    </div>`;
            });
    }

    function fetchCertificateTemplates(caName) {
        showLoadingIndicator();
        fetch('/api/get/domaincatemplate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                resolve_sids: true
            })
        })
        .then(response => response.json())
        .then(data => {
            const container = document.querySelector('.cert-templates-container');
            container.innerHTML = '';

            data.forEach(template => {
                if (template.attributes['Certificate Authorities'] === caName) {
                    const templateElement = document.createElement('div');
                    templateElement.className = 'p-3 hover:bg-neutral-100 dark:hover:bg-neutral-700 rounded-lg cursor-pointer mb-2';
                    
                    // Get vulnerability type if exists
                    let vulnType = '';
                    if (template.attributes.Vulnerable && template.attributes.Vulnerable.length > 0) {
                        vulnType = template.attributes.Vulnerable[0].split(' - ')[0];
                    }

                    templateElement.innerHTML = `
                        <div class="flex items-center justify-between">
                            <div class="flex items-center gap-2">
                                <i class="fa-solid fa-file-certificate text-neutral-600 dark:text-neutral-400"></i>
                                <span class="text-neutral-700 dark:text-neutral-300">${template.attributes.displayName}</span>
                            </div>
                            <div class="flex items-center gap-2">
                                ${vulnType ? `
                                    <span class="px-2 py-0.5 text-xs rounded-full bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300">
                                        ${vulnType}
                                    </span>
                                ` : ''}
                                <span class="px-2 py-0.5 text-xs rounded-full ${
                                    template.attributes.Enabled ? 
                                    'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' : 
                                    'bg-neutral-100 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-300'
                                }">${template.attributes.Enabled ? 'Enabled' : 'Disabled'}</span>
                            </div>
                        </div>
                    `;
                    
                    templateElement.addEventListener('click', () => {
                        document.querySelectorAll('.cert-templates-container > div').forEach(el => {
                            el.classList.remove('bg-neutral-100', 'dark:bg-neutral-700');
                        });
                        templateElement.classList.add('bg-neutral-100', 'dark:bg-neutral-700');
                        showTemplateDetails(template);
                    });
                    container.appendChild(templateElement);
                }
            });
        })
        .catch(error => console.error('Error fetching certificate templates:', error))
        .finally(() => hideLoadingIndicator());
    }

    function showTemplateDetails(template) {
        const container = document.querySelector('.template-details-container');
        container.innerHTML = `
            <div class="p-4">
                <h3 class="text-lg font-semibold text-neutral-700 dark:text-neutral-300 mb-4">${template.attributes.displayName}</h3>
                
                <!-- Basic Info -->
                <div class="grid grid-cols-2 gap-4 mb-6">
                    <div class="text-sm group">
                        <p class="text-neutral-600 dark:text-neutral-400 mb-1">Status</p>
                        <div class="flex items-center gap-2">
                            <span class="px-2 py-1 rounded-full text-sm ${
                                template.attributes.Enabled ? 
                                'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' : 
                                'bg-neutral-100 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-300'
                            }">${template.attributes.Enabled ? 'Enabled' : 'Disabled'}</span>
                            <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800" onclick="copyToClipboard(event, '${template.attributes.Enabled ? 'Enabled' : 'Disabled'}')" title="Copy to clipboard">
                                <i class="fas fa-copy fa-xs"></i>
                            </button>
                        </div>
                    </div>
                    <div class="text-sm group">
                        <p class="text-neutral-600 dark:text-neutral-400 mb-1">CA Server</p>
                        <div class="flex items-center gap-2">
                            <span class="text-neutral-700 dark:text-neutral-300">${template.attributes['Certificate Authorities']}</span>
                            <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800" onclick="copyToClipboard(event, '${template.attributes['Certificate Authorities']}')" title="Copy to clipboard">
                                <i class="fas fa-copy fa-xs"></i>
                            </button>
                        </div>
                    </div>
                </div>

                <div class="space-y-6">
                    <!-- Vulnerability Section - Only show if vulnerabilities exist and array is not empty -->
                    ${template.attributes.Vulnerable && template.attributes.Vulnerable.length > 0 ? `
                        <div class="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg mb-4">
                            <h4 class="text-sm font-medium text-red-800 dark:text-red-300 mb-2">Vulnerabilities</h4>
                            <ul class="space-y-1">
                                ${template.attributes.Vulnerable.map(vuln => 
                                    `<li class="text-sm text-red-700 dark:text-red-400">${vuln}</li>`
                                ).join('')}
                            </ul>
                        </div>
                    ` : ''}

                    <!-- Authentication Settings -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Authentication Settings</h4>
                        <ul class="space-y-2">
                            <li class="flex items-center gap-2 text-neutral-700 dark:text-neutral-300">
                                <i class="fa-solid fa-${template.attributes['Client Authentication'] ? 'check text-green-500' : 'times text-red-500'}"></i>
                                Client Authentication
                            </li>
                            <li class="flex items-center gap-2 text-neutral-700 dark:text-neutral-300">
                                <i class="fa-solid fa-${template.attributes['Enrollment Agent'] ? 'check text-green-500' : 'times text-red-500'}"></i>
                                Enrollment Agent
                            </li>
                            <li class="flex items-center gap-2 text-neutral-700 dark:text-neutral-300">
                                <i class="fa-solid fa-${template.attributes['Any Purpose'] ? 'check text-green-500' : 'times text-red-500'}"></i>
                                Any Purpose
                            </li>
                        </ul>
                    </div>

                    <!-- Extended Key Usage -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Extended Key Usage</h4>
                        <ul class="space-y-1">
                            ${template.attributes.pKIExtendedKeyUsage ? 
                                template.attributes.pKIExtendedKeyUsage.map(usage => 
                                    `<li class="text-sm text-neutral-700 dark:text-neutral-300">${usage}</li>`
                                ).join('') : 
                                '<li class="text-sm text-neutral-500 dark:text-neutral-400">None specified</li>'
                            }
                        </ul>
                    </div>

                    <!-- Administrative Rights -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Administrative Rights</h4>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">Write DACL</p>
                                <ul class="space-y-1">
                                    ${template.attributes['Write Dacl'].map(right => 
                                        `<li class="text-sm">
                                            <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                                onclick="handleObjectClick(event, '${right}')">${right}</a>
                                        </li>`
                                    ).join('')}
                                </ul>
                            </div>
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">Write Owner</p>
                                <ul class="space-y-1">
                                    ${template.attributes['Write Owner'].map(right => 
                                        `<li class="text-sm">
                                            <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                                onclick="handleObjectClick(event, '${right}')">${right}</a>
                                        </li>`
                                    ).join('')}
                                </ul>
                            </div>
                        </div>
                    </div>

                    <!-- Enrollment Rights -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Enrollment Rights</h4>
                        <ul class="space-y-1">
                            ${template.attributes['Enrollment Rights'].map(right => 
                                `<li class="text-sm">
                                    <a href="#" class="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300" 
                                        onclick="handleObjectClick(event, '${right}')">${right}</a>
                                </li>`
                            ).join('')}
                        </ul>
                    </div>

                    <!-- Technical Details -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Technical Details</h4>
                        <div class="grid grid-cols-2 gap-4">
                            ${Object.entries({
                                'Expiration Period': template.attributes.pKIExpirationPeriod,
                                'Overlap Period': template.attributes.pKIOverlapPeriod,
                                'Template OID': template.attributes['msPKI-Cert-Template-OID'],
                                'Distinguished Name': template.attributes.distinguishedName
                            }).map(([label, value]) => `
                                <div class="group">
                                    <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">${label}</p>
                                    <div class="flex items-center gap-2">
                                        <p class="text-sm text-neutral-700 dark:text-neutral-300 break-all">${value}</p>
                                        <button class="opacity-0 group-hover:opacity-100 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 transition-opacity p-1 rounded-md hover:bg-neutral-100 dark:hover:bg-neutral-800" onclick="copyToClipboard(event, '${value}')" title="Copy to clipboard">
                                            <i class="fas fa-copy fa-xs"></i>
                                        </button>
                                    </div>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    function showCADetails(ca) {
        const container = document.querySelector('.template-details-container');
        container.innerHTML = `
            <div class="p-4">
                <h3 class="text-lg font-semibold text-neutral-700 dark:text-neutral-300 mb-4">
                    <div class="flex items-center gap-2">
                        <i class="fa-solid fa-certificate"></i>
                        ${ca.attributes.displayName}
                    </div>
                </h3>

                <div class="space-y-6">
                    <!-- Basic Info -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Basic Information</h4>
                        <div class="grid grid-cols-2 gap-4">
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">DNS Hostname</p>
                                <p class="text-sm text-neutral-700 dark:text-neutral-300">${ca.attributes.dNSHostName}</p>
                            </div>
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">Distinguished Name</p>
                                <p class="text-sm text-neutral-700 dark:text-neutral-300 break-all">${ca.attributes.distinguishedName}</p>
                            </div>
                        </div>
                    </div>

                    <!-- Certificate Templates -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Available Certificate Templates</h4>
                        <div class="grid grid-cols-2 gap-2">
                            ${ca.attributes.certificateTemplates.map(template => `
                                <div class="text-sm text-neutral-700 dark:text-neutral-300 bg-neutral-50 dark:bg-neutral-800 p-2 rounded">
                                    <i class="fa-solid fa-file-certificate mr-2 text-neutral-500"></i>
                                    ${template}
                                </div>
                            `).join('')}
                        </div>
                    </div>

                    <!-- CA Certificate Info -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">CA Certificate</h4>
                        <div class="space-y-2">
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">Certificate DN</p>
                                <p class="text-sm text-neutral-700 dark:text-neutral-300">${ca.attributes.cACertificateDN}</p>
                            </div>
                        </div>
                    </div>

                    <!-- Technical Details -->
                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Technical Details</h4>
                        <div class="space-y-2">
                            <div>
                                <p class="text-xs text-neutral-500 dark:text-neutral-400 mb-1">Object GUID</p>
                                <p class="text-sm text-neutral-700 dark:text-neutral-300">${ca.attributes.objectGUID}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    // Add copyToClipboard function
    window.copyToClipboard = async (event, text) => {
        event.stopPropagation();
        const button = event.currentTarget;
        
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text);
            } else {
                const textArea = document.createElement('textarea');
                textArea.value = text;
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
            
            // Show success feedback
            button.innerHTML = '<i class="fas fa-check fa-xs"></i>';
            setTimeout(() => {
                button.innerHTML = '<i class="fas fa-copy fa-xs"></i>';
            }, 1000);
        } catch (err) {
            console.error('Failed to copy text: ', err);
            showErrorAlert('Failed to copy to clipboard');
        }
    };
});
