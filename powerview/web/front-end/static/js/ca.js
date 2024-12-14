document.addEventListener('DOMContentLoaded', function() {
    fetchCAServers();

    // Add filter functionality
    const filterInput = document.getElementById('template-filter');
    filterInput.addEventListener('input', function() {
        const filterText = this.value.toLowerCase();
        const templates = document.querySelectorAll('.cert-templates-container > div');
        
        templates.forEach(template => {
            const templateName = template.querySelector('span').textContent.toLowerCase();
            if (templateName.includes(filterText)) {
                template.classList.remove('hidden');
            } else {
                template.classList.add('hidden');
            }
        });
    });

    function fetchCAServers() {
        fetch('/api/get/domainca')
            .then(response => response.json())
            .then(data => {
                const container = document.querySelector('.ca-servers-container');
                container.innerHTML = '';
                
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
                        fetchCertificateTemplates(ca.attributes.cn, null);
                    });
                    container.appendChild(caElement);
                });
            })
            .catch(error => console.error('Error fetching CA servers:', error));
    }

    function fetchCertificateTemplates(caName) {
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
        .catch(error => console.error('Error fetching certificate templates:', error));
    }

    function showTemplateDetails(template) {
        const container = document.querySelector('.template-details-container');
        container.innerHTML = `
            <div class="p-4">
                <h3 class="text-lg font-semibold text-neutral-700 dark:text-neutral-300 mb-4">${template.attributes.displayName}</h3>
                
                <div class="grid grid-cols-2 gap-4 mb-6">
                    <div class="text-sm">
                        <p class="text-neutral-600 dark:text-neutral-400 mb-1">Status</p>
                        <span class="px-2 py-1 rounded-full text-sm ${
                            template.attributes.Enabled ? 
                            'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300' : 
                            'bg-neutral-100 text-neutral-800 dark:bg-neutral-700 dark:text-neutral-300'
                        }">${template.attributes.Enabled ? 'Enabled' : 'Disabled'}</span>
                    </div>
                </div>

                <div class="space-y-6">
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
                        </ul>
                    </div>

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

                    <div>
                        <h4 class="text-sm font-medium text-neutral-600 dark:text-neutral-400 mb-2">Approval Settings</h4>
                        <ul class="space-y-2">
                            <li class="flex items-center gap-2 text-neutral-700 dark:text-neutral-300">
                                <i class="fa-solid fa-${template.attributes.ManagerApproval ? 'check text-green-500' : 'times text-red-500'}"></i>
                                Manager Approval Required
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
        `;
    }
});
