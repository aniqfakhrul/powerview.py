import { graphData } from './state.js';
import { addToGraph } from './viz.js';
import { fetchFullDACL, loadGraphData } from './network.js';

// DOM Elements
const loadingOverlay = document.getElementById('loading-overlay');
const loadingStatus = document.getElementById('loading-status');
const detailsPanel = document.getElementById('details-panel');
const panelContent = document.getElementById('panel-content');
const searchResults = document.getElementById('search-results');
const searchInput = document.getElementById('graph-search');
const opsecModal = document.getElementById('opsec-modal');

export function showLoading(isLoading) {
    if (isLoading) {
        loadingOverlay.classList.remove('hidden');
    } else {
        loadingOverlay.classList.add('hidden');
    }
}

export function updateStatus(text, isError = false) {
    if (loadingStatus) {
        loadingStatus.textContent = text;
        if (isError) loadingStatus.classList.add('text-red-500');
        else loadingStatus.classList.remove('text-red-500');
    }
}

export function updateStats() {
    const usersCount = graphData.nodes.filter(n => n.data.type === 'user').length;
    const groupsCount = graphData.nodes.filter(n => n.data.type === 'group').length;
    const compsCount = graphData.nodes.filter(n => n.data.type === 'computer').length;

    const elUsers = document.getElementById('stats-users');
    const elGroups = document.getElementById('stats-groups');
    const elComps = document.getElementById('stats-computers');
    const elContainer = document.getElementById('stats-container');

    if (elUsers) elUsers.textContent = usersCount;
    if (elGroups) elGroups.textContent = groupsCount;
    if (elComps) elComps.textContent = compsCount;

    if (usersCount > 0 || groupsCount > 0 || compsCount > 0) {
        if (elContainer) elContainer.classList.remove('hidden');
    }
}

export function showNodeDetails(nodeId) {
    const node = graphData.nodeMap.get(nodeId);
    if (!node) return;

    const data = node.data;
    const raw = data.raw || {};

    let html = `
        <div class="mb-6">
            <div class="flex items-center gap-2 mb-2">
                <span class="text-xs font-bold uppercase tracking-wider text-neutral-500 dark:text-neutral-400 bg-neutral-100 dark:bg-neutral-800 px-2 py-1 rounded">
                    ${data.type}
                </span>
                <h3 class="text-xl font-bold text-neutral-800 dark:text-neutral-100 truncate" title="${data.label}">
                    ${data.label}
                </h3>
            </div>
            <p class="text-xs text-neutral-500 break-all font-mono">${nodeId}</p>
        </div>
    `;

    // Attributes Table
    html += `<h4 class="text-sm font-bold text-neutral-700 dark:text-neutral-300 mb-2 border-b border-neutral-200 dark:border-neutral-700 pb-1">Attributes</h4>`;
    html += `<div class="overflow-x-auto mb-6"><table class="w-full text-xs text-left"><tbody>`;

    const priorityFields = ['sAMAccountName', 'objectSid', 'description', 'adminCount', 'pwdLastSet', 'lastLogon', 'operatingSystem'];

    function addRow(key, val) {
        if (val === undefined || val === null || val === '') return;
        html += `
            <tr class="border-b border-neutral-100 dark:border-neutral-800 last:border-0 hover:bg-neutral-50 dark:hover:bg-neutral-800/50">
                <td class="py-1.5 pr-2 font-medium text-neutral-600 dark:text-neutral-400 whitespace-nowrap">${key}</td>
                <td class="py-1.5 text-neutral-800 dark:text-neutral-200 font-mono break-all">${val}</td>
            </tr>
            `;
    }

    priorityFields.forEach(f => {
        if (raw[f]) addRow(f, raw[f]);
    });

    Object.keys(raw).forEach(k => {
        if (priorityFields.includes(k) || k === 'nTSecurityDescriptor' || k === 'memberOf' || k === 'distinguishedName') return;
        let val = raw[k];
        if (Array.isArray(val)) {
            val = val.join(', ');
        } else if (typeof val === 'object' && val !== null) {
            val = JSON.stringify(val);
        }
        addRow(k, val);
    });
    html += `</tbody></table></div>`;

    // Member Of
    if (raw.memberOf) {
        html += `<h4 class="text-sm font-bold text-neutral-700 dark:text-neutral-300 mb-2 border-b border-neutral-200 dark:border-neutral-700 pb-1">Member Of</h4>`;
        html += `<ul class="mb-6 space-y-1">`;
        const groups = Array.isArray(raw.memberOf) ? raw.memberOf : [raw.memberOf];
        groups.forEach(g => {
            const gName = g.split(',')[0].split('=')[1] || g;
            html += `<li class="text-xs text-neutral-600 dark:text-neutral-400 break-all flex items-start gap-2">
                <i class="fas fa-users mt-0.5 text-amber-500"></i> ${gName}
                </li>`;
        });
        html += `</ul>`;
    }

    // Potential DACL Section
    html += `<div id="dacl-section-${nodeId.replace(/[^a-z0-9]/gi, '_')}">
        <h4 class="text-sm font-bold text-neutral-700 dark:text-neutral-300 mb-2 border-b border-neutral-200 dark:border-neutral-700 pb-1 flex justify-between items-center">
            Access Control List
            <i class="fas fa-circle-notch fa-spin text-blue-500 hidden dacl-spinner"></i>
        </h4>
        <div class="text-xs text-neutral-500 italic dacl-placeholder">Fetching full DACL...</div>
    </div>`;

    if (panelContent) panelContent.innerHTML = html;
    if (detailsPanel) detailsPanel.classList.remove('translate-x-full');

    // Fetch Full DACL immediately
    fetchFullDACL(nodeId);
}

// Search Logic
let selectedResultIndex = -1;

export function performSearch() {
    if (!searchInput) return;
    const val = searchInput.value.trim();
    if (!val) return;

    // Parse type:value syntax
    let typeFilter = null;
    let query = val.toLowerCase();

    if (val.includes(':')) {
        const parts = val.split(':');
        const t = parts[0].toLowerCase().trim();
        const v = parts.slice(1).join(':').toLowerCase().trim();
        
        typeFilter = t;
        query = v;
    }

    const checkNode = (n, exact = false) => {
        if (typeFilter && n.data.type !== typeFilter) return false;
        
        const label = n.data.label ? n.data.label.toLowerCase() : '';
        const raw = n.data.raw || {};
        const sam = raw.sAMAccountName ? raw.sAMAccountName.toLowerCase() : '';
        const dn = raw.distinguishedName ? raw.distinguishedName.toLowerCase() : '';

        if (exact) {
            return label === query || sam === query || dn === query;
        } else {
            return label.includes(query) || sam.includes(query) || dn.includes(query);
        }
    };

    // Find best match
    const matches = graphData.nodes.filter(n => checkNode(n, true));

    let bestMatch = null;
    if (matches.length > 0) {
        bestMatch = matches[0];
    } else {
        // Fuzzy fallback
        const fuzzyMatches = graphData.nodes.filter(n => checkNode(n, false));

        if (fuzzyMatches.length > 0) bestMatch = fuzzyMatches[0];
    }

    if (bestMatch) {
        console.log("Found match:", bestMatch.data.label);
        addToGraph(bestMatch.data.id);
        // Visual feedback
        searchInput.classList.remove('border-red-500');
        searchInput.classList.add('border-green-500');
        setTimeout(() => searchInput.classList.remove('border-green-500'), 1000);
    } else {
        console.log("No match found for:", query);
        searchInput.classList.add('border-red-500');
        setTimeout(() => searchInput.classList.remove('border-red-500'), 1000);
    }
}

export function updateSearchResults(query) {
    if (!searchResults) return;
    query = query.toLowerCase().trim();
    if (query.length === 0) {
        searchResults.classList.add('hidden');
        return;
    }

    const matches = [];
    const parts = query.split(':');
    const filterType = parts.length > 1 ? parts[0] : null;
    const filterQuery = parts.length > 1 ? parts[1].trim() : parts[0];

    for (const [id, node] of graphData.nodeMap) {
        const label = node.data.label.toLowerCase();
        const type = node.data.type.toLowerCase();
        const raw = node.data.raw || {};
        const sam = raw.sAMAccountName ? raw.sAMAccountName.toLowerCase() : '';
        const dn = raw.distinguishedName ? raw.distinguishedName.toLowerCase() : '';

        let match = false;
        if (filterType) {
            if (type === filterType) {
                if (label.includes(filterQuery) || sam.includes(filterQuery) || dn.includes(filterQuery)) {
                    match = true;
                }
            }
        } else {
            if (label.includes(filterQuery) || type.includes(filterQuery) || sam.includes(filterQuery)) {
                match = true;
            }
        }
        
        if (match) matches.push(node);
        if (matches.length >= 10) break;
    }

    if (matches.length > 0) {
        searchResults.innerHTML = matches.map((m, idx) => {
            let iconClass = 'fa-question-circle text-gray-500';
            if (m.data.type === 'user') iconClass = 'fa-user text-green-500';
            else if (m.data.type === 'group') iconClass = 'fa-users text-amber-500';
            else if (m.data.type === 'computer') iconClass = 'fa-desktop text-blue-500';
            else if (m.data.type === 'foreign') iconClass = 'fa-globe text-neutral-500';

            return `
            <div class="search-result-item px-4 py-2 cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-700 flex items-center gap-2 border-b last:border-0 border-neutral-100 dark:border-neutral-700" 
                    data-id="${m.data.id}">
                <i class="fas ${iconClass} text-xs"></i>
                <div class="flex flex-col overflow-hidden">
                    <span class="text-sm font-medium text-neutral-800 dark:text-neutral-200 truncate">${m.data.label}</span>
                    <span class="text-[10px] text-neutral-500 uppercase">${m.data.type}</span>
                </div>
            </div>
        `}).join('');

        searchResults.classList.remove('hidden');
        selectedResultIndex = -1;

        searchResults.querySelectorAll('.search-result-item').forEach(item => {
            item.addEventListener('click', () => {
                const id = item.getAttribute('data-id');
                if (searchInput) searchInput.value = item.querySelector('.text-sm').textContent;
                addToGraph(id);
                searchResults.classList.add('hidden');
            });
        });
    } else {
        searchResults.classList.add('hidden');
    }
}

export function updateSelectedResult(items) {
    if (!items) return;
    items.forEach((item, idx) => {
        if (idx === selectedResultIndex) {
            item.classList.add('bg-neutral-100', 'dark:bg-neutral-700');
            item.scrollIntoView({ block: 'nearest' });
        } else {
            item.classList.remove('bg-neutral-100', 'dark:bg-neutral-700');
        }
    });
}

export function initSearchListeners() {
    if (searchInput) {
        searchInput.addEventListener('input', (e) => {
            updateSearchResults(e.target.value);
        });

        searchInput.addEventListener('keydown', (e) => {
            if (!searchResults || searchResults.classList.contains('hidden')) {
                if (e.key === 'Enter') performSearch();
                return;
            }

            const items = searchResults.querySelectorAll('.search-result-item');
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                selectedResultIndex = Math.min(selectedResultIndex + 1, items.length - 1);
                updateSelectedResult(items);
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                selectedResultIndex = Math.max(selectedResultIndex - 1, 0);
                updateSelectedResult(items);
            } else if (e.key === 'Enter') {
                e.preventDefault();
                if (selectedResultIndex >= 0 && items[selectedResultIndex]) {
                    items[selectedResultIndex].click();
                } else {
                    performSearch();
                    searchResults.classList.add('hidden');
                }
            } else if (e.key === 'Escape') {
                searchResults.classList.add('hidden');
            }
        });

        searchInput.addEventListener('blur', () => {
            setTimeout(() => {
                if (searchResults) searchResults.classList.add('hidden');
            }, 200);
        });

        searchInput.addEventListener('focus', () => {
            if (searchInput.value.trim().length > 0) {
                updateSearchResults(searchInput.value);
            }
        });
    }
    
    const searchSubmitBtn = document.getElementById('search-submit-btn');
    if (searchSubmitBtn) {
        searchSubmitBtn.addEventListener('click', () => {
            performSearch();
            if (searchResults) searchResults.classList.add('hidden');
        });
    }
}

// Resizable Panel Logic
export function initResizablePanel() {
    const resizer = document.getElementById('panel-resizer');
    if (!resizer || !detailsPanel) return;

    let isResizing = false;

    resizer.addEventListener('mousedown', (e) => {
        isResizing = true;
        document.body.classList.add('cursor-col-resize', 'select-none');
        e.preventDefault();
    });

    document.addEventListener('mousemove', (e) => {
        if (!isResizing) return;

        const windowWidth = window.innerWidth;
        const newWidth = windowWidth - e.clientX;

        // Min/Max constraints
        if (newWidth > 300 && newWidth < (windowWidth * 0.8)) {
            detailsPanel.style.width = `${newWidth}px`;
            // Also ensure it's responsive on small screens if width was auto
            detailsPanel.classList.remove('md:w-96');
        }
    });

    document.addEventListener('mouseup', () => {
        if (isResizing) {
            isResizing = false;
            document.body.classList.remove('cursor-col-resize', 'select-none');
        }
    });
}

// Global modal handling
export function showOpsecModal(show) {
    if (opsecModal) {
        if (show) {
            opsecModal.classList.remove('hidden');
            opsecModal.style.display = 'flex';
        } else {
            opsecModal.classList.add('hidden');
            opsecModal.style.display = 'none';
        }
    }
}
