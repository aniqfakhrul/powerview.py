let activeComputer = null;
let stickyHeaderContainerElement = null;
let smbTableHeadersElement = null;
let contextMenuElement = null;

// Tab Status Functions - Global scope
async function updateTabStatus(computer, status = null) {
    const indicator = document.querySelector(`.status-indicator[data-computer="${computer}"]`);
    if (!indicator) return;
    
    if (status === null) {
        // Fetch current status
        fetchSMBSessions().then(sessions => {
            const normalizedComputer = computer.toLowerCase();
            const session = sessions[normalizedComputer];
            if (session) {
                updateTabStatusIndicator(indicator, session.connected);
            } else {
                updateTabStatusIndicator(indicator, false);
            }
        }).catch(() => {
            updateTabStatusIndicator(indicator, false);
        });
    } else {
        updateTabStatusIndicator(indicator, status);
    }
}

function updateTabStatusIndicator(indicator, isConnected) {
    indicator.className = `status-indicator w-2 h-2 rounded-full ${
        isConnected 
            ? 'bg-green-500 shadow-lg shadow-green-500/30' 
            : 'bg-red-500 shadow-lg shadow-red-500/30'
    }`;
    indicator.title = isConnected ? 'Connected' : 'Disconnected';
}

async function updateAllTabStatuses() {
    fetchSMBSessions().then(sessions => {
        Object.keys(sessions).forEach(key => {
            // Find the original computer name from tabs
            const indicators = document.querySelectorAll('.status-indicator');
            indicators.forEach(ind => {
                if (ind.dataset.computer.toLowerCase() === key) {
                    updateTabStatusIndicator(ind, sessions[key].connected);
                }
            });
        });
        
        // Also update any tabs that might not have active sessions
        document.querySelectorAll('.status-indicator').forEach(indicator => {
            const normalizedComputer = indicator.dataset.computer.toLowerCase();
            if (!sessions[normalizedComputer]) {
                updateTabStatusIndicator(indicator, false);
            }
        });
    }).catch(() => {
        // Mark all as disconnected on error
        document.querySelectorAll('.status-indicator').forEach(indicator => {
            updateTabStatusIndicator(indicator, false);
        });
    });
}

// Add this near the top of the file or after the DOM content loaded event
let renameModalData = {
    computer: null,
    share: null,
    path: null,
    isDirectory: false,
    isShare: false,
    oldName: null,
    dirPath: null
};

// Ensure inline SVG IDs are unique per instance to avoid gradient/defs collisions across tabs
let __pvSvgUid = 0;
function uniquifySvgIds(svgString) {
    try {
        const uid = `pv${++__pvSvgUid}`;
        return svgString
            .replace(/id="([^"]+)"/g, (m, id) => `id="${id}-${uid}"`)
            .replace(/url\(#([^)]+)\)/g, (m, id) => `url(#${id}-${uid})`)
            .replace(/href="#([^"]+)"/g, (m, id) => `href="#${id}-${uid}"`)
            .replace(/xlink:href="#([^"]+)"/g, (m, id) => `xlink:href="#${id}-${uid}"`);
    } catch {
        return svgString;
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    stickyHeaderContainerElement = document.getElementById('sticky-header-container');
    smbTableHeadersElement = document.getElementById('smb-table-headers');
    contextMenuElement = document.getElementById('smb-context-menu');
    updateStickyHeaders();

    const connectButton = document.getElementById('smb-connect-button');
    const connectAsButton = document.getElementById('smb-connect-as-button');
    const connectAsForm = document.getElementById('connect-as-form');
    const pcViews = document.getElementById('pc-views');
    const pcTabs = document.getElementById('pc-tabs');
    const computerInput = document.getElementById('smb-computer');
    
    const urlParams = new URLSearchParams(window.location.search);
    const computerFromUrl = urlParams.get('computer');
    if (computerFromUrl && computerInput) {
        computerInput.value = computerFromUrl;
        setTimeout(() => {
            connectButton.click();
        }, 500);
    }
    
    // Add toggles for search panel
    const searchPanel = document.getElementById('search-panel');
    const closeSearchButton = document.getElementById('close-search-panel');
    const searchButton = document.getElementById('search-button');
    const searchClearButton = document.getElementById('search-clear');
    const searchQuery = document.getElementById('search-query');
    const searchResults = document.getElementById('search-results');
    const searchStatus = document.getElementById('search-status');
    
    // Export CSV button
    const exportCsvButton = document.getElementById('export-search-csv');
    if (exportCsvButton) {
        exportCsvButton.addEventListener('click', () => {
            if (window.lastSearchResults) {
                exportSearchResultsToCSV(
                    window.lastSearchResults.items, 
                    window.lastSearchResults.search_info
                );
            } else {
                showErrorAlert('No search results to export');
            }
        });
    }
    
    // Add properties panel close button handler
    const closePropertiesButton = document.getElementById('close-properties-panel');
    if (closePropertiesButton) {
        closePropertiesButton.addEventListener('click', () => {
            const propertiesPanel = document.getElementById('properties-panel');
            propertiesPanel.classList.add('translate-x-full');
            setTimeout(() => {
                propertiesPanel.classList.add('hidden');
            }, 300);
        });
    }
    
    // Prevent properties panel closing when clicking inside
    const propertiesPanel = document.getElementById('properties-panel');
    if (propertiesPanel) {
        propertiesPanel.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    }

    // Add toggle search panel button handler
    const toggleSearchButton = document.getElementById('toggle-search');
    if (toggleSearchButton) {
        toggleSearchButton.addEventListener('click', async () => {
            // If panel is visible (not translated), hide it
            if (!searchPanel.classList.contains('translate-x-full')) {
                searchPanel.classList.add('translate-x-full');
                setTimeout(() => {
                    searchPanel.classList.add('hidden');
                }, 300);
            } else {
                // Show panel with default computer if active
                if (activeComputer) {
                    await populateHostDropdown(document.getElementById('search-host'), activeComputer);
                    // If we have an active share and path, populate that too
                    const shareHeader = document.querySelector('#sticky-header-container span:first-child');
                    if (shareHeader) {
                        const share = shareHeader.textContent;
                        let path = '';
                        // Collect path segments if they exist
                        const pathSegments = Array.from(document.querySelectorAll('#sticky-header-container span:not(:first-child)'))
                            .filter(span => !span.textContent.includes('>'))
                            .map(span => span.textContent);
                        
                        if (pathSegments.length > 0) {
                            path = pathSegments.join('\\');
                        }
                        
                        const searchPathInput = document.getElementById('search-path');
                        searchPathInput.value = path ? `${share}\\${path}` : share;
                    }
                }
                // Show panel
                searchPanel.classList.remove('hidden');
                setTimeout(() => {
                    searchPanel.classList.remove('translate-x-full');
                    // Focus the search input
                    document.getElementById('search-query').focus();
                }, 10);
            }
        });
    }
    
    // Search panel close button
    if (closeSearchButton) {
        closeSearchButton.addEventListener('click', () => {
            searchPanel.classList.add('translate-x-full');
            setTimeout(() => {
                searchPanel.classList.add('hidden');
            }, 300);
        });
    }
    
    // Search button click handler
    if (searchButton) {
        searchButton.addEventListener('click', () => {
            performSearch();
        });
    }
    
    // Search input enter key handler
    if (searchQuery) {
        searchQuery.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                performSearch();
            }
        });
    }
    
    // Search clear button
    if (searchClearButton) {
        searchClearButton.addEventListener('click', () => {
            searchQuery.value = '';
            searchResults.innerHTML = '';
            searchStatus.textContent = '';
            document.getElementById('search-content').checked = false;
            document.getElementById('search-regex').checked = false;
            document.getElementById('search-case-sensitive').checked = false;
            document.getElementById('search-cred-hunt').checked = false;
            document.getElementById('search-depth').value = '3';
            document.getElementById('search-path').value = '';
            document.getElementById('search-item-type').value = 'all';
            document.getElementById('export-search-csv').classList.add('hidden');
        });
    }
    
    // Keep track of connected PCs
    const connectedPCs = new Set();

    connectButton.onclick = async () => {
        try {
            // Add loading state to button
            const connectIcon = connectButton.querySelector('.fa-plug');
            const buttonText = connectButton.lastChild;
            const originalText = buttonText.textContent;
            
            connectIcon.classList.add('animate-pulse');
            buttonText.textContent = ' Connecting...';
            connectButton.disabled = true;
            
            showLoadingIndicator();
            const computer = computerInput.value;
            if (!computer) {
                throw new Error('Please enter a computer name or IP');
            }

            // Check if already connected
            if (connectedPCs.has(computer)) {
                // Just switch to that tab
                switchToPC(computer);
                return;
            }

            const username = document.getElementById('smb-username').value;
            const authType = document.getElementById('smb-auth-type').value;
            const password = document.getElementById('smb-password').value;
            const nthash = document.getElementById('smb-nthash').value;
            const aesKey = document.getElementById('smb-aeskey').value;

            const connectionData = {
                computer: computer
            };

            let hasCreds = false;
            if (!connectAsForm.classList.contains('hidden') && username) {
                connectionData.username = username;
                hasCreds = true;
            }
            if (!connectAsForm.classList.contains('hidden')) {
                if (authType === 'password' && password) {
                    connectionData.password = password;
                    hasCreds = true;
                } else if (authType === 'nthash' && nthash) {
                    connectionData.nthash = nthash;
                    hasCreds = true;
                } else if (authType === 'aeskey' && aesKey) {
                    connectionData.aesKey = aesKey;
                    hasCreds = true;
                }
            }
            if (hasCreds && authType === 'nthash' && nthash) {
                connectionData.lmhash = 'aad3b435b51404eeaad3b435b51404ee';
            }

            // Connect to SMB
            await connectToSMB(connectionData);
            const shares = await listSMBShares(computer);
            
            // Add new PC tab
            addPCTab(computer);
            
            // Add new PC view
            addPCView(computer, shares);
            
            // Switch to new PC
            switchToPC(computer);
            
            // Show success alert instead of updating status div
            showSuccessAlert(`Connected to ${computer}`);

            // Track this PC
            connectedPCs.add(computer);

        } catch (error) {
            console.error('Connection error:', error);
            showErrorAlert(error.message);
        } finally {
            // Reset button state
            const connectIcon = connectButton.querySelector('.fa-plug');
            const buttonText = connectButton.lastChild;
            
            connectIcon.classList.remove('animate-pulse');
            buttonText.textContent = ' Connect';
            connectButton.disabled = false;
            hideLoadingIndicator();
        }
    };

    function addPCTab(computer) {
        const tabsContainer = document.getElementById('pc-tabs');
        
        // Remove existing tab if present
        const existingTab = document.querySelector(`[data-computer="${computer}"]`);
        if (existingTab) {
            existingTab.remove();
        }
        
        const tab = document.createElement('div');
        tab.id = `tab-${computer}`;
        tab.className = 'flex items-center gap-2 px-3 py-2 border-neutral-200 dark:border-neutral-700 cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800 whitespace-nowrap';
        tab.dataset.computer = computer;
        tab.innerHTML = `
            <div class="flex items-center gap-2">
                <div class="status-indicator w-2 h-2 rounded-full bg-gray-400" data-computer="${computer}" title="Connection status"></div>
                <i class="fas fa-desktop text-neutral-600 dark:text-neutral-400"></i>
                <span class="font-medium text-neutral-900 dark:text-white">${computer}</span>
                <button class="disconnect-btn ml-2 text-neutral-400 hover:text-red-500 dark:hover:text-red-400" 
                        data-computer="${computer}" title="Disconnect">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        // Add click handler for tab switching
        tab.addEventListener('click', (e) => {
            if (!e.target.closest('.disconnect-btn')) {
                switchToPC(computer);
            }
        });
        
        // Add disconnect handler
        tab.querySelector('.disconnect-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            disconnectPC(computer);
        });
        
        tabsContainer.appendChild(tab);
        
        // Set as active
        switchToPC(computer);
        
        // Update status immediately after a short delay to allow connection to establish
        setTimeout(() => updateTabStatus(computer), 1000);
    }

    // Tab status functions are now defined globally above

    function addPCView(computer, shares) {
        const view = document.createElement('div');
        view.id = `view-${computer}`;
        view.dataset.computer = computer;
        view.className = 'hidden';
        view.innerHTML = buildSMBTreeView(shares, computer);
        pcViews.appendChild(view);
        attachTreeViewListeners(computer);
    }

    function switchToPC(computer) {
        console.log('Switching to PC:', computer);
        // Update active computer
        activeComputer = computer;
        updateStickyHeaders(); // Update sticky headers to show computer

        // Update tabs
        document.querySelectorAll('#pc-tabs > div').forEach(tab => {
            tab.classList.remove('bg-neutral-100', 'dark:bg-neutral-800', 'border-b-2', 'border-blue-500', 'dark:border-yellow-500');
            if (tab.id === `tab-${computer}`) {
                tab.classList.add('bg-neutral-100', 'dark:bg-neutral-800', 'border-b-2', 'border-blue-500', 'dark:border-yellow-500');
            }
        });

        // Update views
        document.querySelectorAll('#pc-views > div').forEach(view => {
            view.classList.add('hidden');
            if (view.id === `view-${computer}`) {
                view.classList.remove('hidden');
            }
        });
    }

    async function disconnectPC(computer) {
        // Update tab status to disconnected immediately
        updateTabStatus(computer, false);
        
        // Remove tab
        const tab = document.getElementById(`tab-${computer}`);
        if (tab) tab.remove();

        // Remove view
        const view = document.getElementById(`view-${computer}`);
        if (view) view.remove();

        // Remove from tracking
        connectedPCs.delete(computer);

        // Call the disconnect API
        try {
            const response = await fetch('/api/smb/disconnect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ computer })
            });
            if (!response.ok) {
                const error = await response.json();
                console.error('Failed to disconnect SMB session:', error.error);
                showErrorAlert(`Failed to disconnect from ${computer}: ${error.error}`);
            } else {
                showSuccessAlert(`Disconnected from ${computer}`);
            }
        } catch (error) {
            console.error('Error during SMB disconnect:', error);
            showErrorAlert(`Error disconnecting from ${computer}: ${error.message}`);
        }

        // If we're disconnecting the active computer, switch to another one
        if (activeComputer === computer) {
            activeComputer = null;
            const remainingPC = connectedPCs.values().next().value;
            if (remainingPC) {
                switchToPC(remainingPC);
            } else {
                updateStickyHeaders(); // Clear sticky headers
            }
        }
    }

    // Toggle connect-as form
    connectAsButton.onclick = () => {
        connectAsForm.classList.toggle('hidden');
    };

    // Add file viewer close button handler
    const closeFileViewerButton = document.getElementById('close-file-viewer');
    if (closeFileViewerButton) {
        closeFileViewerButton.addEventListener('click', () => {
            const fileViewer = document.getElementById('file-viewer-panel');
            fileViewer.classList.add('translate-x-full');
            setTimeout(() => {
                fileViewer.classList.add('hidden');
            }, 300);
        });
    }

    // Downloads panel toggle
    const toggleDownloadsButton = document.getElementById('toggle-downloads');
    const downloadsPanel = document.getElementById('downloads-panel');
    const closeDownloadsButton = document.getElementById('close-downloads-panel');

    toggleDownloadsButton.addEventListener('click', () => {
        // If panel is visible (not translated), hide it
        if (!downloadsPanel.classList.contains('translate-x-full')) {
            downloadsPanel.classList.add('translate-x-full');
            setTimeout(() => {
                downloadsPanel.classList.add('hidden');
            }, 300);
        } else {
            // Show panel
            downloadsPanel.classList.remove('hidden');
            setTimeout(() => {
                downloadsPanel.classList.remove('translate-x-full');
            }, 0);
        }
    });

    closeDownloadsButton.addEventListener('click', () => {
        downloadsPanel.classList.add('translate-x-full');
        setTimeout(() => {
            downloadsPanel.classList.add('hidden');
        }, 300);
    });

    // Add click handlers for panels
    document.addEventListener('click', (e) => {
        const fileViewer = document.getElementById('file-viewer-panel');
        const downloadsPanel = document.getElementById('downloads-panel');
        const searchPanel = document.getElementById('search-panel');
        const propertiesPanel = document.getElementById('properties-panel');

        // Handle file viewer panel
        if (fileViewer && !fileViewer.classList.contains('hidden')) {
            // Check if click is outside the panel
            if (!fileViewer.contains(e.target) && !e.target.closest('.view-btn')) {
                fileViewer.classList.add('translate-x-full');
                setTimeout(() => {
                    fileViewer.classList.add('hidden');
                    // Clean up any object URLs if viewing an image
                    const img = fileViewer.querySelector('img');
                    if (img && img.src.startsWith('blob:')) {
                        URL.revokeObjectURL(img.src);
                    }
                }, 300);
            }
        }

        // Handle downloads panel
        if (downloadsPanel && !downloadsPanel.classList.contains('hidden')) {
            // Check if click is outside the panel and not on the toggle button
            if (!downloadsPanel.contains(e.target) && !e.target.closest('#toggle-downloads')) {
                downloadsPanel.classList.add('translate-x-full');
                setTimeout(() => {
                    downloadsPanel.classList.add('hidden');
                }, 300);
            }
        }
        
        // Handle search panel
        if (searchPanel && !searchPanel.classList.contains('hidden')) {
            // Check if click is outside the panel and not on the toggle button
            if (!searchPanel.contains(e.target) && !e.target.closest('#toggle-search') && !e.target.closest('.fa-search')) {
                searchPanel.classList.add('translate-x-full');
                setTimeout(() => {
                    searchPanel.classList.add('hidden');
                }, 300);
            }
        }
        
        // Handle properties panel
        if (propertiesPanel && !propertiesPanel.classList.contains('hidden')) {
            // Check if click is outside the panel and not on context menu elements
            if (!propertiesPanel.contains(e.target) && 
                !e.target.closest('.fa-info-circle') && 
                !contextMenuElement?.contains(e.target)) {
                
                // Add a small delay to ensure we don't close immediately after opening from context menu
                setTimeout(() => {
                    propertiesPanel.classList.add('translate-x-full');
                    setTimeout(() => {
                        propertiesPanel.classList.add('hidden');
                    }, 300);
                }, 50);
            }
        }
    });

    // Prevent panel closing when clicking inside the panels
    const panels = document.querySelectorAll('#file-viewer-panel, #downloads-panel, #search-panel, #properties-panel');
    panels.forEach(panel => {
        panel.addEventListener('click', (e) => {
            e.stopPropagation();
        });
    });

    // Add refresh button handler
    const refreshButton = document.getElementById('smb-refresh-button');
    refreshButton.onclick = async () => {
        if (!activeComputer) {
            showErrorAlert('No active connection to refresh');
            return;
        }

        try {
            // Add spinning class to the icon
            const refreshIcon = refreshButton.querySelector('.fa-sync-alt');
            refreshIcon.classList.add('animate-spin');
            // Disable the button while refreshing
            refreshButton.disabled = true;
            
            showLoadingIndicator();
            const computer = activeComputer;
            
            // Call the reconnect API
            const response = await fetch('/api/smb/reconnect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ computer })
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to reconnect SMB session');
            }
            
            const result = await response.json();
            if (result.status === 'reconnected') {
                showSuccessAlert(`Successfully reconnected to ${computer}`);
                updateTabStatus(computer, true);
            } else {
                throw new Error(result.error || 'Reconnect failed with unknown error');
            }

        } catch (error) {
            console.error('Reconnect error:', error);
            showErrorAlert(error.message);
            updateTabStatus(activeComputer, false);
        } finally {
            // Remove spinning class and re-enable button
            const refreshIcon = refreshButton.querySelector('.fa-sync-alt');
            refreshIcon.classList.remove('animate-spin');
            refreshButton.disabled = false;
            hideLoadingIndicator();
        }
    };

    // Add share button handler
    const addShareButton = document.getElementById('smb-add-share-button');
    addShareButton.onclick = () => {
        if (!activeComputer) {
            showErrorAlert('Please connect to a computer first');
            return;
        }
        showAddShareModal(activeComputer);
    };

    // Add rename modal event listeners
    const renameConfirmBtn = document.getElementById('rename-confirm-btn');
    const renameCancelBtn = document.getElementById('rename-cancel-btn');
    const renameInput = document.getElementById('rename-input');
    
    if (renameConfirmBtn && renameCancelBtn && renameInput) {
        renameConfirmBtn.addEventListener('click', () => {
            const newName = renameInput.value.trim();
            if (newName && newName !== renameModalData.originalFullPath) {
                performRename(newName);
            }
            hideRenameModal();
        });
        
        renameCancelBtn.addEventListener('click', hideRenameModal);
        
        // Handle Enter key in the input
        renameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const newName = renameInput.value.trim();
                if (newName && newName !== renameModalData.originalFullPath) {
                    performRename(newName);
                }
                hideRenameModal();
            } else if (e.key === 'Escape') {
                hideRenameModal();
            }
        });
    }

    const authTypeSelect = document.getElementById('smb-auth-type');
    const passwordInput = document.getElementById('smb-password');
    const nthashInput = document.getElementById('smb-nthash');
    const aesKeyInput = document.getElementById('smb-aeskey');
    function updateAuthInputs() {
        const val = authTypeSelect.value;
        passwordInput.classList.toggle('hidden', val !== 'password');
        nthashInput.classList.toggle('hidden', val !== 'nthash');
        aesKeyInput.classList.toggle('hidden', val !== 'aeskey');
    }
    if (authTypeSelect) {
        authTypeSelect.addEventListener('change', updateAuthInputs);
        updateAuthInputs();
    }

    // Auto-load active sessions
    try {
        const sessions = await fetchSMBSessions();
        const connectedComputers = Object.keys(sessions).filter(key => sessions[key].connected);
        
        if (connectedComputers.length > 0) {
            let firstComputer = null;
            
            for (const key of connectedComputers) {
                // Use the original case from session data or find matching tab
                const computer = Object.keys(sessions).find(original => original.toLowerCase() === key) || key;
                if (!connectedPCs.has(computer)) {
                    connectedPCs.add(computer);
                    addPCTab(computer);
                    const shares = await listSMBShares(computer);
                    addPCView(computer, shares);
                    if (!firstComputer) {
                        firstComputer = computer;
                    }
                }
            }
            
            if (firstComputer) {
                switchToPC(firstComputer);
            }
            updateAllTabStatuses();
        }
    } catch (error) {
        console.error('Error auto-loading sessions:', error);
    }

    // Add Enter key handler for computer input
    computerInput.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            connectButton.click();
        }
    });
});

// Reuse the existing SMB functions from main.js
async function connectToSMB(data) {
    const response = await fetch('/api/smb/connect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    });

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Failed to connect to SMB share');
    }

    const result = await response.json();
    
    // Update tab status immediately on successful connection
    if (result.host) {
        setTimeout(() => updateTabStatus(result.host, true), 500);
    }
    
    return result;
}

// ... (copy the rest of the SMB-related functions from main.js)
// Including: listSMBShares, listSMBPath, buildSMBTreeView, 
// attachTreeViewListeners, buildFileList, downloadSMBFile, 
// uploadSMBFile, and formatFileSize
async function listSMBShares(computer) {
    try {
        const response = await fetch('/api/smb/shares', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list SMB shares');
        }

        return await response.json();
    } catch (error) {
        showErrorAlert(error.message);
        throw error;
    }
}

async function listSMBPath(computer, share, path = '') {
    // Verify we're operating on the active computer
    if (computer !== activeComputer) {
        console.warn(`Attempted to list path from ${computer} while ${activeComputer} is active`);
        return [];
    }

    try {
        const response = await fetch('/api/smb/ls', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to list SMB path');
        }

        return await response.json();
    } catch (error) {
        showErrorAlert(error.message);
        throw error;
    }
}


function buildSMBTreeView(shares, computer) {
    let html = '<ul>';
    shares.forEach(share => {
        const shareName = share.attributes.Name;
        html += `
            <li class="smb-tree-item text-sm" data-share="${shareName}" data-computer="${computer}">
                <div class="grid grid-cols-12 gap-2 items-center hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer py-0 px-1.5">
                    <div class="col-span-6">
                        <div class="flex items-center gap-1.5 min-w-0">
                            <span class="text-yellow-500 flex-shrink-0">${uniquifySvgIds(icons.smbshareIcon)}</span>
                            <span class="text-neutral-900 dark:text-white truncate">${shareName}</span>
                            <span class="text-xs text-neutral-500 dark:text-neutral-400 truncate">${share.attributes.Remark || ''}</span>
                            <span class="spinner-container flex-shrink-0"></span>
                        </div>
                    </div>
                    <div class="col-span-1 text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-1 text-neutral-500 dark:text-neutral-400 text-right">--</div>
                </div>
                <ul class="hidden"></ul>
            </li>
        `;
    });
    html += '</ul>';
    return html;
}

function attachTreeViewListeners() {
    document.querySelectorAll('.smb-tree-item').forEach(item => {
        const shareDiv = item.querySelector('div');
        const subList = item.querySelector('ul');
        const spinnerContainer = item.querySelector('.spinner-container');
        let isLoaded = false;

        shareDiv.onclick = async () => {
            const share = item.dataset.share;
            const computer = item.dataset.computer;
            
            if (activeComputer !== computer) {
                // If the click is on a share of a non-active computer tab, switch first
                switchToPC(computer);
            }

            if (!isLoaded) {
                try {
                    showInlineSpinner(spinnerContainer);
                    const files = await listSMBPath(computer, share);
                    subList.innerHTML = buildFileList(files, share, '', computer);
                    isLoaded = true;
                    subList.classList.remove('hidden');
                    attachFileListeners();
                    updateStickyHeaders(share);
                    // Shares don't toggle folder icons, but we keep symmetry
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            } else {
                subList.classList.toggle('hidden');
                // Update UNC path based on visibility. If visible, it's this share.
                if (!subList.classList.contains('hidden')) {
                    updateStickyHeaders(share);
                } else {
                    // If collapsing the share, path reverts to just computer (or last active folder in another share)
                    // For simplicity, let's show computer path. More complex state needed for perfect recall.
                    updateStickyHeaders();
                }
            }
        };

        // Add context menu listener for shares
        shareDiv.addEventListener('contextmenu', (event) => {
            event.preventDefault();
            const itemData = {
                computer: item.dataset.computer,
                share: item.dataset.share,
                name: item.dataset.share, // Share name acts as the item name here
                path: '', // Path is empty for a share itself
                isDirectory: true, // Treat shares like directories for context actions
                isShare: true // Add a flag to differentiate
            };
            showContextMenu(event, itemData);
        });
    });
}

function showInlineSpinner(element) {
    // Remove existing spinner if any
    removeInlineSpinner(element);
    
    const spinnerTemplate = document.querySelector('#inline-spinner-template');
    if (spinnerTemplate) {
        const spinner = spinnerTemplate.content.cloneNode(true);
        spinner.firstElementChild.classList.add('inline-action-spinner');
        element.appendChild(spinner);
    }
}

function removeInlineSpinner(element) {
    const existingSpinner = element.querySelector('.inline-action-spinner');
    if (existingSpinner) {
        existingSpinner.remove();
    }
}

function attachFileListeners() {
    document.querySelectorAll('.file-item').forEach(item => {
        const isDirectory = item.getAttribute('data-is-dir') === '16' || item.getAttribute('data-is-dir') === '48';
        const computer = item.dataset.computer;
        const share = item.dataset.share;
        const path = item.dataset.path;
        const spinnerContainer = item.querySelector('.spinner-container');
        const fileDiv = item.querySelector('div');
        
        let isLoading = false;

        if (!isDirectory) {
            fileDiv.addEventListener('dblclick', async () => {
                if (isLoading) return;

                try {
                    isLoading = true;
                    showInlineSpinner(spinnerContainer);
                    const cleanPath = path.replace(/^\//, '').replace(/\//g, '\\');
                    await viewSMBFile(computer, share, cleanPath);
                } catch (error) {
                    console.error('Error viewing file:', error);
                    showErrorAlert(error.message);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                    isLoading = false;
                }
            });
        }

        if (isDirectory) {
            const subList = item.querySelector('ul');
            
            if (!fileDiv || !subList) return;

            fileDiv.onclick = async () => {
                if (isLoading) return;

                const currentShare = item.dataset.share;
                const currentItemPath = item.dataset.path; // Path of the directory itself

                if (subList.children.length > 0) {
                    subList.classList.toggle('hidden');
                    // Update UNC path when toggling folder visibility
                    if (!subList.classList.contains('hidden')) {
                        updateStickyHeaders(currentShare, currentItemPath);
                        try { updateDirectoryIcon(item, true); } catch {}
                    } else {
                        // If collapsing, path reverts to parent (share in this case for top-level folder)
                        // Or more accurately, path of the item being clicked itself if we are just collapsing it.
                        // For simplicity, if we collapse a folder, let the path be its parent (the share)
                        const pathSegments = currentItemPath.replace(/^\/+/, '').split('/');
                        if (pathSegments.length > 1) {
                            const parentPath = '/' + pathSegments.slice(0, -1).join('/');
                            updateStickyHeaders(currentShare, parentPath);
                        } else {
                            updateStickyHeaders(currentShare);
                        }
                        try { updateDirectoryIcon(item, false); } catch {}
                    }
                    return;
                }

                try {
                    isLoading = true;
                    showInlineSpinner(spinnerContainer);
                    const cleanPath = currentItemPath.replace(/^\//, '').replace(/\//g, '\\');
                    const files = await listSMBPath(computer, currentShare, cleanPath);
                    subList.innerHTML = buildFileList(files, currentShare, currentItemPath, computer);
                    subList.classList.remove('hidden');
                    attachFileListeners();
                    updateStickyHeaders(currentShare, currentItemPath);
                    try { updateDirectoryIcon(item, true); } catch {}
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                    isLoading = false;
                }
            };

            const uploadBtn = item.querySelector('.upload-btn');
            if (uploadBtn) {
                uploadBtn.onclick = async (e) => {
                    e.stopPropagation();
                    showInlineSpinner(spinnerContainer);
                    try {
                        // Normalize path separators for upload
                        const normalizedPath = item.dataset.path.replace(/\//g, '\\');
                        await uploadSMBFile(computer, share, normalizedPath);
                    } finally {
                        removeInlineSpinner(spinnerContainer);
                    }
                };
            }

            const newFolderBtn = item.querySelector('.new-folder-btn');
            if (newFolderBtn) {
                newFolderBtn.onclick = async (e) => {
                    e.stopPropagation();
                    showInlineSpinner(spinnerContainer);
                    try {
                        // Normalize path separators for new folder creation
                        const normalizedPath = path.replace(/\//g, '\\');
                        await createSMBDirectory(computer, share, normalizedPath);
                    } finally {
                        removeInlineSpinner(spinnerContainer);
                    }
                };
            }
        } else {
            const viewBtn = item.querySelector('.view-btn');
            if (viewBtn) {
                viewBtn.onclick = async (e) => {
                    e.stopPropagation();
                    showInlineSpinner(spinnerContainer);
                    try {
                        // Normalize path separators before viewing
                        const normalizedPath = item.dataset.path.replace(/\//g, '\\');
                        await viewSMBFile(computer, share, normalizedPath);
                    } finally {
                        removeInlineSpinner(spinnerContainer);
                    }
                };
            }
        }

        const downloadBtn = item.querySelector('.download-btn');
        if (downloadBtn) {
            downloadBtn.onclick = async (e) => {
                e.stopPropagation();
                showInlineSpinner(spinnerContainer);
                try {
                    if (isDirectory) {
                        // For directories, use forward slash split to get name, but normalize path for download
                        const dirName = path.split('/').pop();
                        const normalizedPath = path.replace(/\//g, '\\');
                        await downloadSMBDirectory(computer, share, normalizedPath, dirName);
                    } else {
                        // Normalize path separators for file download
                        const normalizedPath = path.replace(/\//g, '\\');
                        await downloadSMBFile(computer, share, normalizedPath);
                    }
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            };
        }
        
        // Add delete button listener
        const deleteBtn = item.querySelector('.delete-btn');
        if (deleteBtn) {
            deleteBtn.onclick = async (e) => {
                e.stopPropagation();
                showInlineSpinner(spinnerContainer);
                try {
                    // Normalize path separators for deletion
                    const normalizedPath = path.replace(/\//g, '\\');
                    await deleteSMBFileOrDirectory(computer, share, normalizedPath, isDirectory);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            };
        }

        // Add context menu listener for files/folders
        fileDiv.addEventListener('contextmenu', (event) => {
            event.preventDefault();
            const itemData = {
                computer: item.dataset.computer,
                share: item.dataset.share,
                name: item.dataset.path.split('/').pop(), // Get name from path
                path: item.dataset.path.replace(/\//g, '\\'), // Normalize path for context menu
                isDirectory: item.getAttribute('data-is-dir') === '16' || item.getAttribute('data-is-dir') === '48',
                isShare: false
            };
            showContextMenu(event, itemData);
        });
    });
}

function updateDirectoryIcon(fileItemElement, expanded) {
    try {
        const isDirectory = fileItemElement.getAttribute('data-is-dir') === '16' || fileItemElement.getAttribute('data-is-dir') === '48';
        if (!isDirectory) return;
        const iconSpan = fileItemElement.querySelector('.dir-icon');
        if (!iconSpan) return;
        const nameNode = fileItemElement.querySelector('.text-neutral-900');
        const fileName = nameNode ? nameNode.textContent : '';
        const iconDef = getFileIcon(fileName, true, expanded === true);
        iconSpan.innerHTML = uniquifySvgIds(iconDef.icon);
    } catch {}
}

// Keep track of downloads
const downloads = new Map();

// Update the downloadSMBFile function to include progress tracking
async function downloadSMBFile(computer, share, path, raw = false) {
    // Verify we're operating on the active computer
    if (computer !== activeComputer) {
        console.warn(`Attempted to download from ${computer} while ${activeComputer} is active`);
        return;
    }

    try {
        showLoadingIndicator();
        // Normalize path separators before extracting filename
        const normalizedPath = path.replace(/\//g, '\\');
        const filename = normalizedPath.split('\\').pop();
        const downloadId = Date.now();

        // Only create download entry if not raw download
        let downloadEntry;
        if (!raw) {
            // Create download entry with computer and share info
            const downloadsList = document.getElementById('downloads-list');
            downloadEntry = document.createElement('div');
            downloadEntry.id = `download-${downloadId}`;
            downloadEntry.className = 'bg-white dark:bg-neutral-800 rounded-md border border-neutral-200 dark:border-neutral-700 p-2 text-sm';
            downloadEntry.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-1.5">
                            <i class="fas fa-file fa-lg text-blue-500 dark:text-yellow-500"></i>
                            <div class="truncate">
                                <div class="font-medium text-neutral-900 dark:text-white truncate">
                                    ${filename}
                                </div>
                                <div class="text-xs text-neutral-500 dark:text-neutral-400">
                                    from \\\\${computer}\\${share}
                                </div>
                            </div>
                        </div>
                        <div class="mt-1 flex items-center gap-1.5">
                            <div class="flex-1 bg-neutral-200 dark:bg-neutral-700 rounded-full h-1">
                                <div class="download-progress bg-blue-500 dark:bg-yellow-500 h-1 rounded-full" style="width: 0%"></div>
                            </div>
                            <span class="text-xs text-neutral-500 dark:text-neutral-400 download-status">Starting...</span>
                        </div>
                    </div>
                    <button onclick="clearDownload(${downloadId})" class="text-neutral-400 hover:text-neutral-500 dark:hover:text-neutral-300 p-0.5">
                        <i class="fas fa-times"></i>
                    </button>
                </div>
            `;

            // Show downloads panel if hidden
            const downloadsPanel = document.getElementById('downloads-panel');
            downloadsPanel.classList.remove('hidden');
            setTimeout(() => {
                downloadsPanel.classList.remove('translate-x-full');
            }, 0);

            // Add the new download entry
            downloadsList.insertBefore(downloadEntry, downloadsList.firstChild);
        }

        // Start download - use original path for API call
        const response = await fetch('/api/smb/get', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to download file');
        }

        const blob = await response.blob();
        
        if (raw) {
            return blob;
        } else {
            // Get the suggested filename from the response headers
            const suggestedFilename = `${computer}_${share}_${filename}`;
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = suggestedFilename;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);

            // Update download entry to show completion
            const progressBar = downloadEntry.querySelector('.download-progress');
            const statusText = downloadEntry.querySelector('.download-status');
            progressBar.style.width = '100%';
            statusText.textContent = 'Complete';

            showSuccessAlert('File downloaded successfully');
        }

    } catch (error) {
        showErrorAlert(error.message);
        console.error('Download error:', error);
    } finally {
        hideLoadingIndicator();
    }
}

function createDownloadEntry(id, filename) {
    const entry = document.createElement('div');
    entry.id = `download-${id}`;
    entry.className = 'bg-neutral-50 dark:bg-neutral-800 rounded-md p-1.5 mb-1.5 text-sm';

    const filenameSpan = document.createElement('span');
    filenameSpan.className = 'text-neutral-900 dark:text-white';
    filenameSpan.textContent = filename;

    entry.innerHTML = `
        <div class="flex items-center justify-between">
            ${filenameSpan.outerHTML}
            <div class="flex items-center gap-1">
                <button onclick="clearDownload('${id}')"
                    class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
        <div class="h-1.5 bg-neutral-200 dark:bg-neutral-700 rounded-full mt-1.5">
            <div id="download-progress-${id}" 
                class="bg-blue-500 dark:bg-yellow-500 h-1.5 rounded-full transition-all duration-300" 
                style="width: 0%">
            </div>
        </div>
        <span class="text-xs text-neutral-500 dark:text-neutral-400" id="download-status-${id}">0%</span>
    `;

    return entry;
}

function updateDownloadProgress(id, receivedOrPercent, totalSize) {
    const progressBar = document.getElementById(`download-progress-${id}`);
    const progressText = document.getElementById(`download-status-${id}`);
    if (!progressBar || !progressText) return;

    let percent;
    if (typeof totalSize === 'number' && totalSize > 0 && typeof receivedOrPercent === 'number') {
        percent = Math.round((receivedOrPercent / totalSize) * 100);
    } else if (typeof receivedOrPercent === 'number') {
        percent = Math.round(receivedOrPercent);
    } else {
        return;
    }
    percent = Math.max(0, Math.min(100, percent));
    progressBar.style.width = `${percent}%`;
    progressText.textContent = `${percent}%`;
}

function completeDownload(id, filename) {
    const entry = document.getElementById(`download-${id}`);
    entry.classList.add('bg-green-50');
    entry.querySelector('.text-xs').textContent = 'Completed';
    entry.querySelector('.text-xs').classList.add('text-green-500');
}

function failDownload(id, error) {
    const entry = document.getElementById(`download-${id}`);
    entry.classList.add('bg-red-50');
    entry.querySelector('.text-xs').textContent = `Failed: ${error}`;
    entry.querySelector('.text-xs').classList.add('text-red-500');
}

function buildFileList(files, share, currentPath, computer) {
    let html = '';
    files.forEach(file => {
        const isDirectory = file.is_directory;
        const fileIcon = getFileIcon(file.name, isDirectory);
        
        const windowsTimestamp = BigInt(file.modified);
        const unixTimestamp = Number((windowsTimestamp - BigInt(116444736000000000)) / BigInt(10000));
        const modifiedDate = new Date(unixTimestamp).toLocaleString([], { year: '2-digit', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });

        const windowsCreatedTimestamp = BigInt(file.created);
        const unixCreatedTimestamp = Number((windowsCreatedTimestamp - BigInt(116444736000000000)) / BigInt(10000));
        const createdDate = new Date(unixCreatedTimestamp).toLocaleString([], { year: '2-digit', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
        
        const pathSegments = currentPath.split('/').filter(segment => segment.length > 0);
        const indentLevel = pathSegments.length + 1;
        const marginLeft = indentLevel * 1.25;
        
        html += `
            <li class="file-item text-sm" 
                data-path="${currentPath}/${file.name}" 
                data-is-dir="${file.is_directory ? '16' : '0'}"
                data-computer="${computer}"
                data-share="${share}"
                title="${file.name}">
                <div class="grid grid-cols-12 gap-2 items-center hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer py-0 px-1.5">
                    <div class="col-span-6">
                        <div class="flex items-center gap-1.5 min-w-0" style="margin-left: ${marginLeft}rem;">
                            ${fileIcon.isCustomSvg 
                                ? `<span class="w-4 h-4 flex-shrink-0 ${fileIcon.iconClass} dir-icon">${uniquifySvgIds(fileIcon.icon)}</span>`
                                : `<i class="fas ${fileIcon.icon} ${fileIcon.iconClass} flex-shrink-0"></i>`
                            }
                            <span class="text-neutral-900 dark:text-white truncate">${file.name}</span>
                            <span class="spinner-container flex-shrink-0"></span>
                        </div>
                    </div>
                    <div class="col-span-1 text-neutral-500 dark:text-neutral-400">
                        ${formatFileSize(file.size)}
                    </div>
                    <div class="col-span-2 text-neutral-500 dark:text-neutral-400">
                        ${createdDate}
                    </div>
                    <div class="col-span-2 text-neutral-500 dark:text-neutral-400">
                        ${modifiedDate}
                    </div>
                    <div class="col-span-1 flex items-center gap-1 justify-end">
                        ${isDirectory ? `
                            <button class="upload-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="Upload">
                                <i class="fas fa-upload fa-sm"></i>
                            </button>
                            <button class="new-folder-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="New Folder">
                                <i class="fas fa-folder-plus fa-sm"></i>
                            </button>
                            <button class="download-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="Download Directory">
                                <i class="fas fa-download fa-sm"></i>
                            </button>
                        ` : `
                            <button class="view-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="View">
                                <i class="fas fa-eye fa-sm"></i>
                            </button>
                            <button class="download-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="Download">
                                <i class="fas fa-download fa-sm"></i>
                            </button>
                        `}
                        <button class="delete-btn text-neutral-500 hover:text-red-600 dark:hover:text-red-400 p-0.5" title="Delete">
                            <i class="fas fa-trash fa-sm"></i>
                        </button>
                    </div>
                </div>
                ${isDirectory ? '<ul class="hidden"></ul>' : ''}
            </li>
        `;
    });
    return html;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Add file upload functionality
async function uploadSMBFile(computer, share, currentPath) {
    // Verify we're operating on the active computer
    if (computer !== activeComputer) {
        console.warn(`Attempted to upload to ${computer} while ${activeComputer} is active`);
        return;
    }

    const fileInput = document.createElement('input');
    fileInput.type = 'file';
    fileInput.style.display = 'none';
    document.body.appendChild(fileInput);

    fileInput.onchange = async function() {
        if (!this.files || !this.files[0]) return;

        try {
            showLoadingIndicator();
            const formData = new FormData();
            formData.append('file', this.files[0]);
            formData.append('computer', computer);
            formData.append('share', share);
            formData.append('path', currentPath);

            const response = await fetch('/api/smb/put', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to upload file');
            }

            // Use refreshDirectory to update the directory content
            const normalizedUploadPath = currentPath.replace(/\\/g, '/');
            const parentPathForRefresh = '/' + normalizedUploadPath.replace(/^\/+/, '');
            
            try {
                await refreshDirectory(computer, share, currentPath, parentPathForRefresh);
                
                // Ensure the list is visible if it was previously empty/hidden
                if (currentPath === '') {
                    const listElement = document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > ul`);
                    if (listElement) {
                        listElement.classList.remove('hidden');
                    }
                } else {
                    const listElement = document.querySelector(`.file-item[data-path="${parentPathForRefresh}"][data-share="${share}"][data-computer="${computer}"] > ul`);
                    if (listElement) {
                        listElement.classList.remove('hidden');
                    }
                }
            } catch (refreshError) {
                console.error('Could not refresh directory after upload:', refreshError);
                // Fallback: force a full refresh of the share as a last resort
                const shareRootElement = document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > div`);
                shareRootElement?.click();
            }
            
            showSuccessAlert('File uploaded successfully');

        } catch (error) {
            showErrorAlert(error.message);
            console.error('Upload error:', error);
        } finally {
            hideLoadingIndicator();
            document.body.removeChild(fileInput);
        }
    };

    fileInput.click();
}

// Add this helper function to check if a file is an image based on extension
function isImageFile(filename) {
    const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'];
    return imageExtensions.some(ext => filename.toLowerCase().endsWith(ext));
}

// Add the file viewer function
async function viewSMBFile(computer, share, path) {
    if (computer !== activeComputer) {
        console.warn(`Attempted to view file from ${computer} while ${activeComputer} is active`);
        return;
    }

    const spinner = document.getElementById('file-viewer-spinner');

    try {
        showLoadingIndicator();
        // Normalize path separators before extracting filename
        const normalizedPath = path.replace(/\//g, '\\');
        const filename = normalizedPath.split('\\').pop();
        const isImage = isImageFile(filename);
        const isPdf = isPdfFile(filename);
        
        // Show loading spinner
        spinner.classList.remove('hidden');
        
        // Reset viewers
        document.getElementById('image-viewer').classList.add('hidden');
        document.getElementById('text-viewer').classList.add('hidden');
        document.getElementById('pdf-viewer').classList.add('hidden');

        // Use original path for API call
        const response = await fetch('/api/smb/cat', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to read file');
        }

        // Clone the response for different uses
        const responseClone = response.clone();

        // Update title and show panel
        const fileViewer = document.getElementById('file-viewer-panel');
        const fileViewerTitle = document.getElementById('file-viewer-title');
        fileViewerTitle.textContent = filename;

        // Setup download button
        const downloadBtn = document.getElementById('file-viewer-download');
        downloadBtn.onclick = () => downloadSMBFile(computer, share, path);

        if (isPdf) {
            const arrayBuffer = await responseClone.arrayBuffer();
            const pdfViewer = document.getElementById('pdf-viewer');
            
            // Reset PDF viewer state
            pageNum = 1;
            zoomLevel = 1.0;
            document.getElementById('pdf-zoom-level').textContent = '100%';
            
            // Load PDF
            pdfDoc = await pdfjsLib.getDocument({ data: arrayBuffer }).promise;
            
            // Setup controls and render first page
            setupPdfControls();
            await renderPdfPage();
            
            pdfViewer.classList.remove('hidden');
            
            // Update file info
            document.getElementById('file-size').textContent = formatFileSize(arrayBuffer.byteLength);
            document.getElementById('file-type').textContent = 'application/pdf';
        } else if (isImage) {
            const blob = await responseClone.blob();
            const objectUrl = URL.createObjectURL(blob);
            
            const imageViewer = document.getElementById('image-viewer');
            const img = document.getElementById('image-content');
            
            img.src = objectUrl;
            img.onload = () => {
                imageViewer.classList.remove('hidden');
                // Update file info
                document.getElementById('file-size').textContent = formatFileSize(blob.size);
                document.getElementById('file-type').textContent = blob.type;
            };
        } else {
            const content = await response.text();
            const textViewer = document.getElementById('text-viewer');
            const textContent = document.getElementById('text-content');
            
            textContent.textContent = content;
            textViewer.classList.remove('hidden');
            
            // Update file info
            document.getElementById('file-size').textContent = formatFileSize(content.length);
            document.getElementById('file-type').textContent = 'text/plain';
        }

        // Show the panel
        fileViewer.classList.remove('hidden');
        setTimeout(() => fileViewer.classList.remove('translate-x-full'), 0);

    } catch (error) {
        showErrorAlert(error.message);
        console.error('View error:', error);
    } finally {
        // Hide spinner
        spinner.classList.add('hidden');
        hideLoadingIndicator();
    }
}

// Add the clear download function
function clearDownload(id) {
    const entry = document.getElementById(`download-${id}`);
    if (entry) {
        // Add a fade-out animation
        entry.style.transition = 'opacity 0.3s ease-out';
        entry.style.opacity = '0';
        
        // Remove the element after the animation
        setTimeout(() => {
            entry.remove();
            
            // If no more downloads, hide the panel
            const downloadsList = document.getElementById('downloads-list');
            if (downloadsList.children.length === 0) {
                const downloadsPanel = document.getElementById('downloads-panel');
                downloadsPanel.classList.add('translate-x-full');
                setTimeout(() => {
                    downloadsPanel.classList.add('hidden');
                }, 300);
            }
        }, 300);
    }
}

// Add these functions near the bottom of the file
function showRenameModal(computer, share, path, isDirectory, isShare) {
    const modal = document.getElementById('rename-modal');
    const renameInput = document.getElementById('rename-input');
    const pathDisplay = document.getElementById('rename-modal-path');
    const titleElement = document.getElementById('rename-modal-title');
    
    // Normalize path to use backslashes for consistent processing
    const normalizedPath = path.replace(/\//g, '\\');
    
    // Parse the path to get the filename/folder name
    const pathParts = normalizedPath.split('\\');
    // Filter out empty parts in case of leading/trailing slashes
    const filteredParts = pathParts.filter(part => part.length > 0); 
    
    // The last part is the filename/folder name
    const oldName = filteredParts.length > 0 ? filteredParts[filteredParts.length - 1] : '';
    
    // Get the directory path (everything before the last part)
    let dirPath = '';
    if (filteredParts.length > 1) {
        // Remove the last part (file/folder name) and join the rest
        dirPath = filteredParts.slice(0, -1).join('\\');
    }
    
    // Update modal title based on item type
    titleElement.textContent = `Rename/Move ${isDirectory ? 'Folder' : 'File'}`;
    
    // Display the path using UNC format
    pathDisplay.textContent = `\\\\${computer}\\${share}\\${path}`;
    
    // Set initial value in the input - use full path for absolute path support
    renameInput.value = normalizedPath;
    renameInput.placeholder = 'Enter new name or full path (e.g., "newname.txt" or "folder\\subfolder\\newname.txt")';
    
    // Store data for later use
    renameModalData = {
        computer,
        share,
        path: normalizedPath,  // Store normalized path with backslashes
        isDirectory,
        isShare,
        oldName,
        dirPath,
        originalFullPath: normalizedPath  // Store original full path for comparison
    };
    
    console.log('Path parts:', filteredParts);
    console.log('Modal data:', renameModalData);
    
    // Show modal
    modal.classList.remove('hidden');
    
    // Focus and select all text in input for easy editing
    setTimeout(() => {
        renameInput.focus();
        renameInput.select();
    }, 100);
}

function hideRenameModal() {
    const modal = document.getElementById('rename-modal');
    modal.classList.add('hidden');
}

// Replace the existing renameSMBFileOrDirectory function with this
async function renameSMBFileOrDirectory(computer, share, path, isDirectory, isShare) {
    if (computer !== activeComputer) {
        console.warn(`Attempted to rename file from ${computer} while ${activeComputer} is active`);
        return;
    }   

    // Show the custom modal instead of prompt()
    showRenameModal(computer, share, path, isDirectory, isShare);
}

// Add this new function that does the actual rename operation
async function performRename(newName) {
    const { computer, share, path, dirPath, isDirectory, isShare, oldName, originalFullPath } = renameModalData;
    
    console.log('renameModalData:', renameModalData);
    try {
        showLoadingIndicator();
        
        // Construct the source and destination paths
        const source = path;
        
        // Determine if newName is an absolute path or just a filename
        let destination;
        if (newName.includes('\\') || newName.includes('/')) {
            // User provided an absolute path - normalize it
            destination = newName.replace(/\//g, '\\');
            console.log('Using absolute path destination:', destination);
        } else {
            // User provided just a filename - keep it in the same directory
            destination = dirPath ? `${dirPath}\\${newName}` : newName;
            console.log('Using relative filename destination:', destination);
        }
        
        console.log('Source:', source);
        console.log('Destination:', destination);
        
        const response = await fetch('/api/smb/mv', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                computer, 
                share, 
                source, 
                destination 
            })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to rename/move file');
        }

        // Determine what type of operation was performed for user feedback
        const isMove = destination.includes('\\') && 
                      (destination.split('\\').slice(0, -1).join('\\') !== dirPath);
        const operationType = isMove ? 'moved' : 'renamed';
        
        // Refresh the directory where the renamed/moved item was located
        try {
            // For shares, refresh the whole view
            if (isShare) {
                const shareRootElement = document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > div`);
                if (shareRootElement) {
                    shareRootElement.click();
                }
                showSuccessAlert(`Successfully ${operationType} item`);
                return;
            }
            
            // Normalize paths for comparison
            const parentPathNormalized = '/' + (dirPath || '').replace(/\\/g, '/');
            
            // If it's a move operation, we might need to refresh multiple directories
            if (isMove) {
                // Refresh the source directory
                await refreshDirectory(computer, share, dirPath, parentPathNormalized);
                
                // If the destination is in a different directory, try to refresh that too
                const destParts = destination.split('\\');
                if (destParts.length > 1) {
                    const destDirPath = destParts.slice(0, -1).join('\\');
                    const destPathNormalized = '/' + destDirPath.replace(/\\/g, '/');
                    
                    // Only refresh destination if it's different from source
                    if (destDirPath !== dirPath) {
                        try {
                            await refreshDirectory(computer, share, destDirPath, destPathNormalized);
                        } catch (error) {
                            console.warn('Could not refresh destination directory:', error);
                        }
                    }
                }
            } else {
                // Check if the renamed item is a directory and currently expanded
                if (isDirectory) {
                    // If we're renaming a directory, check if it's currently expanded
                    const normalizedItemPath = '/' + path.replace(/\\/g, '/');
                    const renamedDirElement = document.querySelector(`.file-item[data-path="${normalizedItemPath}"][data-share="${share}"][data-computer="${computer}"]`);
                    if (renamedDirElement && renamedDirElement.querySelector('ul') && !renamedDirElement.querySelector('ul').classList.contains('hidden')) {
                        // Directory is expanded, we need to update its path and refresh its contents
                        // First, refresh the parent to update the folder listing with new name
                        await refreshDirectory(computer, share, dirPath, parentPathNormalized);
                        
                        // Then, find and click the renamed folder to expand it again
                        setTimeout(() => {
                            // Construct the new path with the new name
                            const newPathNormalized = parentPathNormalized === '/' ? 
                                `/${newName}` : 
                                `${parentPathNormalized}/${newName}`;
                            
                            console.log('Looking for renamed folder at:', newPathNormalized);
                            const newFolderElement = document.querySelector(`.file-item[data-path="${newPathNormalized}"][data-share="${share}"][data-computer="${computer}"] > div`);
                            if (newFolderElement) {
                                newFolderElement.click();
                            } else {
                                console.warn('Could not find renamed folder element:', newPathNormalized);
                            }
                        }, 100);
                        showSuccessAlert(`Successfully ${operationType} to ${destination}`);
                        return;
                    }
                }
                
                // Standard case: Just refresh the parent directory
                await refreshDirectory(computer, share, dirPath, parentPathNormalized);
            }
            
        } catch (error) {
            console.error('Error refreshing directory after rename/move:', error);
        }
        
        showSuccessAlert(`Successfully ${operationType} to ${destination}`);
    } catch (error) {
        showErrorAlert(error.message);
        console.error('Rename/move error:', error);
    } finally {
        hideLoadingIndicator();
    }   
}

async function refreshDirectory(computer, share, dirPath, normalizedPath) {
    try {
        const files = await listSMBPath(computer, share, dirPath);
        let parentList;
        
        if (dirPath === '') {
            parentList = document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > ul`);
        } else {
            const cleanNormalizedPath = normalizedPath.startsWith('/') ? normalizedPath : '/' + normalizedPath;
            parentList = document.querySelector(`.file-item[data-path="${cleanNormalizedPath}"][data-share="${share}"][data-computer="${computer}"] > ul`);
        }
        
        if (parentList) {
            const parentScrollContainer = document.getElementById('pc-views');
            const scrollTop = parentScrollContainer ? parentScrollContainer.scrollTop : 0;
            
            let currentPathFormatted = dirPath;
            
            if (dirPath.startsWith('/') || dirPath.startsWith('\\')) {
                currentPathFormatted = dirPath.substring(1);
            }
            
            currentPathFormatted = currentPathFormatted.replace(/\\/g, '/');
            
            console.log('Refreshing directory with formatted path:', currentPathFormatted);
            
            parentList.innerHTML = buildFileList(files, share, currentPathFormatted, computer);
            attachFileListeners();
            
            if (parentScrollContainer) {
                parentScrollContainer.scrollTop = scrollTop;
            }
        }
    } catch (error) {
        console.error(`Error refreshing directory ${dirPath}:`, error);
        throw error;
    }
}

async function deleteSMBFileOrDirectory(computer, share, path, isDirectory) {
    // Verify we're operating on the active computer
    if (computer !== activeComputer) {
        console.warn(`Attempted to delete file from ${computer} while ${activeComputer} is active`);
        return;
    }

    // Ask for confirmation
    if (!confirm('Are you sure you want to delete this file?')) {
        return;
    }

    try {
        showLoadingIndicator();
        const response = await fetch(isDirectory ? '/api/smb/rmdir' : '/api/smb/rm', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete file');
        }

        // Remove the file from the list
        const fileItem = document.querySelector(`[data-path="${path}"]`);
        if (fileItem) {
            fileItem.remove();
        }

        showSuccessAlert('File deleted successfully');

    } catch (error) {
        showErrorAlert(error.message);
        console.error('Delete error:', error);
    } finally {
        hideLoadingIndicator();
    }
}

async function createSMBDirectory(computer, share, path) {
    // Verify we're operating on the active computer
    if (computer !== activeComputer) {
        console.warn(`Attempted to create directory on ${computer} while ${activeComputer} is active`);
        return;
    }

    // Prompt for directory name
    const dirName = prompt('Enter new folder name:');
    if (!dirName) return;

    try {
        showLoadingIndicator();
        const newPath = path ? `${path}\\${dirName}` : dirName;
        
        const response = await fetch('/api/smb/mkdir', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path: newPath })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to create directory');
        }

        // Refresh the current directory listing
        const currentPath = path || '';
        const files = await listSMBPath(computer, share, currentPath);
        const parentList = document.querySelector(`[data-path="${currentPath}"]`)?.parentElement || 
                          document.querySelector(`[data-share="${share}"]`)?.querySelector('ul');
        
        if (parentList) {
            parentList.innerHTML = buildFileList(files, share, currentPath, computer);
            attachFileListeners();
        }
        
        showSuccessAlert('Directory created successfully');

    } catch (error) {
        showErrorAlert(error.message);
        console.error('Create directory error:', error);
    } finally {
        hideLoadingIndicator();
    }
}

// Add this new function to recursively list all files in a directory
async function listSMBDirectoryContents(computer, share, path, files = []) {
    try {
        const response = await listSMBPath(computer, share, path);
        
        for (const item of response) {
            const itemPath = path ? `${path}\\${item.name}` : item.name;
            
            if (item.is_directory) {
                // Recursively list contents of subdirectories
                await listSMBDirectoryContents(computer, share, itemPath, files);
            } else {
                // Add file with its full path
                files.push({
                    name: item.name,
                    path: itemPath,
                    size: item.size
                });
            }
        }
        
        return files;
    } catch (error) {
        console.error('Error listing directory contents:', error);
        throw error;
    }
}

// Add this function to handle directory downloads
async function downloadSMBDirectory(computer, share, path, directoryName) {
    try {
        // Create a unique download ID for the directory
        const downloadId = Date.now().toString();
        
        // Add directory download entry to the downloads panel
        const downloadsList = document.getElementById('downloads-list');
        const entry = createDownloadEntry(downloadId, `📁 ${directoryName}`);
        downloadsList.appendChild(entry);
        
        // Show downloads panel
        const downloadsPanel = document.getElementById('downloads-panel');
        downloadsPanel.classList.remove('hidden', 'translate-x-full');
        
        // Normalize the root path for the directory being downloaded.
        // path comes from item.dataset.path (e.g., "/FolderA" or "/FolderA/SubFolder")
        const initialPathForListing = path.replace(/^\/+/, ''); // Remove leading slash

        // List all files in the directory recursively.
        // listSMBDirectoryContents returns file paths relative to the share root, using \ separator.
        const files = await listSMBDirectoryContents(computer, share, initialPathForListing, []);
        const totalFiles = files.length;
        let completedFiles = 0;
        
        // Update status to show file count
        const statusElement = document.getElementById(`download-status-${downloadId}`);
        statusElement.textContent = `0/${totalFiles} files`;
        
        // Create a JSZip instance
        const zip = new JSZip();

        // This is the root path of the download operation, normalized (e.g., "FolderA" or "FolderA\SubFolder")
        const normalizedDownloadRootPath = initialPathForListing.replace(/\//g, '\\');
        const lowerNormalizedDownloadRootPath = normalizedDownloadRootPath.toLowerCase();

        // Download each file
        for (const file of files) {
            // file.path is the full path from share root, e.g., "Users\Administrator\Desktop\testfolder\file.txt"
            // file.name is the basename, e.g., "file.txt"
            
            // Normalize file path to use consistent backslashes for comparison
            const normalizedFilePath = file.path.replace(/\//g, '\\');
            const lowerFilePath = normalizedFilePath.toLowerCase();

            let pathInZip;

            if (normalizedDownloadRootPath === '') { 
                // Downloading from share root - use full path
                pathInZip = normalizedFilePath;
            } else {
                // Calculate relative path from download root
                const prefixOriginalCase = normalizedDownloadRootPath + '\\';
                const prefixLowerCase = lowerNormalizedDownloadRootPath + '\\';

                if (lowerFilePath.startsWith(prefixLowerCase)) {
                    // Remove the download root prefix to get relative path
                    // This makes the downloaded folder the root of the zip
                    pathInZip = normalizedFilePath.substring(prefixOriginalCase.length);
                } else if (lowerFilePath === lowerNormalizedDownloadRootPath) {
                    // File is exactly the download root (single file download)
                    pathInZip = file.name;
                } else {
                    // File doesn't match expected prefix - this shouldn't happen with proper recursive listing
                    // But if it does, try to preserve relative structure from the download point
                    console.warn(`File path ${normalizedFilePath} doesn't match expected prefix ${prefixOriginalCase}. Attempting to preserve relative structure.`);
                    
                    // Try to find the download root in the file path and extract everything after it
                    const downloadRootParts = normalizedDownloadRootPath.split('\\').filter(p => p);
                    const fileParts = normalizedFilePath.split('\\').filter(p => p);
                    
                    // Find the last occurrence of the download root pattern in the file path
                    let matchIndex = -1;
                    for (let i = 0; i <= fileParts.length - downloadRootParts.length; i++) {
                        let matches = true;
                        for (let j = 0; j < downloadRootParts.length; j++) {
                            if (fileParts[i + j].toLowerCase() !== downloadRootParts[j].toLowerCase()) {
                                matches = false;
                                break;
                            }
                        }
                        if (matches) {
                            matchIndex = i + downloadRootParts.length;
                        }
                    }
                    
                    if (matchIndex !== -1 && matchIndex < fileParts.length) {
                        // Use everything after the matched download root
                        pathInZip = fileParts.slice(matchIndex).join('\\');
                    } else {
                        // Final fallback: just use the filename
                        console.warn(`Could not determine relative path for ${normalizedFilePath}. Using filename only.`);
                        pathInZip = file.name;
                    }
                }
            }

            // Ensure pathInZip is valid and preserves structure
            if (!pathInZip || pathInZip === '\\' || pathInZip === '') {
                // Last resort: use filename but warn about structure loss
                console.warn(`Invalid pathInZip for ${normalizedFilePath}. Using filename only: ${file.name}`);
                pathInZip = file.name;
            }

            try {
                const blob = await downloadSMBFile(computer, share, file.path, true);
                if (blob) {
                    // Convert backslashes to forward slashes for JSZip compatibility
                    const zipPath = pathInZip.replace(/\\/g, '/');
                    zip.file(zipPath, blob);
                }
                completedFiles++;
                
                // Update progress
                const progress = (completedFiles / totalFiles) * 100;
                updateDownloadProgress(downloadId, completedFiles, totalFiles);
                statusElement.textContent = `${completedFiles}/${totalFiles} files`;
            } catch (error) {
                console.error(`Error downloading file ${normalizedFilePath}:`, error);
                // Continue with next file even if one fails
            }
        }

        // Generate the zip file
        const zipBlob = await zip.generateAsync({ 
            type: 'blob',
            compression: 'DEFLATE',
            compressionOptions: { level: 6 }
        }, (metadata) => {
            // Update compression progress
            if (typeof metadata.percent === 'number') {
                updateDownloadProgress(downloadId, metadata.percent);
                statusElement.textContent = `Compressing: ${Math.round(metadata.percent)}%`;
            }
        });
        
        // Create download link for the zip
        const url = URL.createObjectURL(zipBlob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${directoryName}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        
        // Mark download as complete
        completeDownload(downloadId, directoryName);
        statusElement.textContent = `Completed: ${completedFiles}/${totalFiles} files`;
        
    } catch (error) {
        console.error('Directory download error:', error);
        failDownload(downloadId, 'Failed to download directory');
        throw error;
    }
}

// Add to your helper functions
function isPdfFile(filename) {
    return filename.toLowerCase().endsWith('.pdf');
}

// Add PDF viewer state
let pdfDoc = null;
let pageNum = 1;
let zoomLevel = 1.0;

// Add PDF viewer controls
async function renderPdfPage() {
    const page = await pdfDoc.getPage(pageNum);
    const canvas = document.getElementById('pdf-canvas');
    const context = canvas.getContext('2d');

    // Calculate viewport with zoom
    const viewport = page.getViewport({ scale: zoomLevel });
    canvas.width = viewport.width;
    canvas.height = viewport.height;

    await page.render({
        canvasContext: context,
        viewport: viewport
    }).promise;

    // Update page counter
    document.getElementById('pdf-page-num').textContent = 
        `Page ${pageNum} of ${pdfDoc.numPages}`;
}

function setupPdfControls() {
    // Page navigation
    document.getElementById('pdf-prev').onclick = async () => {
        if (pageNum <= 1) return;
        pageNum--;
        await renderPdfPage();
    };

    document.getElementById('pdf-next').onclick = async () => {
        if (pageNum >= pdfDoc.numPages) return;
        pageNum++;
        await renderPdfPage();
    };

    // Zoom controls
    document.getElementById('pdf-zoom-out').onclick = async () => {
        if (zoomLevel <= 0.5) return;
        zoomLevel -= 0.25;
        document.getElementById('pdf-zoom-level').textContent = `${Math.round(zoomLevel * 100)}%`;
        await renderPdfPage();
    };

    document.getElementById('pdf-zoom-in').onclick = async () => {
        if (zoomLevel >= 3) return;
        zoomLevel += 0.25;
        document.getElementById('pdf-zoom-level').textContent = `${Math.round(zoomLevel * 100)}%`;
        await renderPdfPage();
    };
}

// Add cleanup to closeFileViewer
function closeFileViewer() {
    const fileViewer = document.getElementById('file-viewer-panel');
    fileViewer.classList.add('translate-x-full');
    setTimeout(() => {
        fileViewer.classList.add('hidden');
        // Clean up any object URLs
        const img = fileViewer.querySelector('img');
        if (img && img.src.startsWith('blob:')) {
            URL.revokeObjectURL(img.src);
        }
        // Reset PDF state
        pdfDoc = null;
        pageNum = 1;
        zoomLevel = 1.0;
    }, 300);
}

// Helper function to add a separator to sticky headers
function addStickySeparator(container) {
    const separator = document.createElement('span');
    separator.className = 'text-neutral-400 dark:text-neutral-500 px-0.5';
    separator.textContent = '>';
    container.appendChild(separator);
}

// Function to update the sticky directory headers
function updateStickyHeaders(currentShare = '', currentDirectoryPath = '') {
    if (!stickyHeaderContainerElement || !smbTableHeadersElement) return;

    stickyHeaderContainerElement.innerHTML = ''; // Clear existing headers

    // If no share is selected, or no active computer, hide the sticky header.
    if (!activeComputer || !currentShare) {
        stickyHeaderContainerElement.classList.add('hidden');
        smbTableHeadersElement.style.top = '0px'; // Table headers stick to the very top
        return;
    }

    stickyHeaderContainerElement.classList.remove('hidden');
    // Ensure sticky header itself uses text-sm, which should be inherited by spans if not overridden
    stickyHeaderContainerElement.classList.remove('text-xs'); // Remove if present from an older version
    stickyHeaderContainerElement.classList.add('text-sm');


    // Share part (now the first element if present)
    const shareSpan = document.createElement('span');
    shareSpan.className = 'cursor-pointer hover:underline text-neutral-700 dark:text-neutral-300';
    shareSpan.textContent = currentShare;
    shareSpan.onclick = () => {
        console.log('Navigate to share:', currentShare);
        // TODO: Implement navigation to share root.
        updateStickyHeaders(currentShare);
        // Also ensure UI reflects this (e.g., specific share is highlighted/expanded, no subfolders selected)
        // And list the root of the share.
        const shareListItem = document.querySelector(`.smb-tree-item[data-share="${currentShare}"][data-computer="${activeComputer}"] > div`);
        if (shareListItem) {
            shareListItem.click(); // Simulate click to expand/load share root
             // After clicking, ensure only the share is in the path, not deeper folders from previous state
            setTimeout(() => updateStickyHeaders(currentShare, ''), 0);
        }
    };
    stickyHeaderContainerElement.appendChild(shareSpan);

    if (currentDirectoryPath) {
        const normalizedPath = currentDirectoryPath.replace(/^\/+/, ''); // Remove leading slashes
        const pathSegments = normalizedPath.split('/').filter(Boolean); // Filter out empty segments
        
        let accumulatedPath = '';
        pathSegments.forEach((segment, index) => {
            accumulatedPath += (index === 0 ? '' : '/') + segment;
            addStickySeparator(stickyHeaderContainerElement);
            const segmentSpan = document.createElement('span');
            segmentSpan.className = 'cursor-pointer hover:underline text-neutral-700 dark:text-neutral-300';
            segmentSpan.textContent = segment;
            
            const fullPathForSegment = '/' + accumulatedPath;
            segmentSpan.onclick = () => {
                console.log('Navigate to path segment:', fullPathForSegment, 'within share:', currentShare);
                // TODO: Implement proper navigation to this specific path.
                updateStickyHeaders(currentShare, fullPathForSegment);
                // This would involve finding the directory list item for fullPathForSegment and programmatically clicking it.
                const targetDirElement = document.querySelector(`.file-item[data-share="${currentShare}"][data-computer="${activeComputer}"][data-path="${fullPathForSegment}"] > div`);
                if (targetDirElement) {
                    targetDirElement.click();
                }
            };
            stickyHeaderContainerElement.appendChild(segmentSpan);
        });
    }

    // After populating stickyHeaderContainerElement, set top for smbTableHeadersElement
    const stickyHeaderHeight = stickyHeaderContainerElement.offsetHeight;
    smbTableHeadersElement.style.top = `${stickyHeaderHeight}px`;
}

// Add this function to fetch and populate available SMB sessions
async function fetchSMBSessions() {
    try {
        const response = await fetch('/api/smb/sessions');
        if (!response.ok) {
            throw new Error('Failed to fetch SMB sessions');
        }
        
        const data = await response.json();
        // Normalize session keys to lowercase for case-insensitive matching
        const normalizedSessions = {};
        Object.entries(data.sessions || {}).forEach(([key, value]) => {
            normalizedSessions[key.toLowerCase()] = value;
        });
        return normalizedSessions;
    } catch (error) {
        console.error('Error fetching SMB sessions:', error);
        return {};
    }
}

// Start periodic status updates
setInterval(() => {
    updateAllTabStatuses();
}, 30000); // Update every 30 seconds

// Search Functions
async function openSearchPanel(computer, share, path = '') {
    const searchPanel = document.getElementById('search-panel');
    const searchStatus = document.getElementById('search-status');
    const searchHostSelect = document.getElementById('search-host');
    const searchPathInput = document.getElementById('search-path');
    
    // Hide export button
    const exportCsvButton = document.getElementById('export-search-csv');
    exportCsvButton.classList.add('hidden');
    
    // Populate the host dropdown
    await populateHostDropdown(searchHostSelect, computer);
    
    // Format the combined share and path
    let combinedPath = share || '';
    if (path) {
        const formattedPath = path.replace(/^\/+/, '').replace(/\//g, '\\');
        combinedPath += formattedPath ? '\\' + formattedPath : '';
    }
    searchPathInput.value = combinedPath;
    
    // Update search status
    searchStatus.innerHTML = `Ready to search`;
    
    // Clear previous results
    document.getElementById('search-results').innerHTML = '';
    
    // Show panel
    searchPanel.classList.remove('hidden');
    setTimeout(() => {
        searchPanel.classList.remove('translate-x-full');
        // Focus the search input
        document.getElementById('search-query').focus();
    }, 10);
}

async function populateHostDropdown(selectElement, selectedComputer) {
    // Clear existing options
    selectElement.innerHTML = '';
    
    // Get all active SMB sessions
    const sessions = await fetchSMBSessions();
    
    // If no sessions, add a default option
    if (Object.keys(sessions).length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.text = 'No active SMB connections';
        selectElement.appendChild(option);
        return;
    }
    
    // Add options for each computer
    for (const [computer, sessionInfo] of Object.entries(sessions)) {
        const option = document.createElement('option');
        option.value = computer;
        option.text = computer;
        
        // Set as selected if it matches the provided computer
        if (computer === selectedComputer) {
            option.selected = true;
        }
        
        selectElement.appendChild(option);
    }
}

function convertToCSV(searchResults, searchInfo) {
    // Create headers
    const headers = ['Name', 'Path', 'Share', 'Computer', 'Type', 'Size', 'Match Type', 'Content Match'];
    let csv = headers.join(',') + '\n';
    
    // Add search info as comment in first line
    const searchMode = searchInfo.search_mode || 'pattern';
    const searchPattern = searchInfo.pattern || '';
    const caseInfo = searchInfo.case_sensitive ? 'case-sensitive' : 'case-insensitive';
    csv = `# Search: ${searchPattern}, Mode: ${searchMode}, ${caseInfo}, Host: ${searchInfo.host}, Share: ${searchInfo.share}\n` + csv;
    
    // Process each result item
    searchResults.forEach(item => {
        const type = item.is_directory ? 'Directory' : 'File';
        const size = item.size || 0;
        const matchType = item.match_type || 'name';
        // Escape any commas or quotes in content match
        let contentMatch = (item.content_match || '').replace(/"/g, '""');
        contentMatch = contentMatch ? `"${contentMatch}"` : '';
        
        // Escape any commas or quotes in name & path
        const safeName = item.name.includes(',') ? `"${item.name}"` : item.name;
        const safePath = item.path.includes(',') ? `"${item.path}"` : item.path;
        
        const row = [
            safeName,
            safePath,
            item.share,
            searchInfo.host,
            type,
            size,
            matchType,
            contentMatch
        ];
        
        csv += row.join(',') + '\n';
    });
    
    return csv;
}

function exportSearchResultsToCSV(items, searchInfo) {
    if (!items || items.length === 0) return;
    
    // Convert the search results to CSV
    const csv = convertToCSV(items, searchInfo);
    
    // Create a Blob and generate download link
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    
    // Generate filename with timestamp
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const filename = `smb_search_${searchInfo.host}_${searchInfo.share}_${timestamp}.csv`;
    
    // Create download link and trigger click
    const link = document.createElement('a');
    link.setAttribute('href', url);
    link.setAttribute('download', filename);
    document.body.appendChild(link);
    link.click();
    
    // Clean up
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    
    showSuccessAlert(`Exported ${items.length} results to ${filename}`);
}

async function performSearch() {
    const searchPanel = document.getElementById('search-panel');
    const searchResults = document.getElementById('search-results');
    const searchStatus = document.getElementById('search-status');
    const searchQuery = document.getElementById('search-query').value;
    const searchHostSelect = document.getElementById('search-host');
    const searchPathInput = document.getElementById('search-path').value;
    const exportCsvButton = document.getElementById('export-search-csv');
    
    // Hide export button until we have results
    exportCsvButton.classList.add('hidden');
    
    // Get the selected host
    const computer = searchHostSelect.value;
    if (!computer) {
        searchStatus.innerHTML = '<span class="text-red-500 font-medium">Please select a host</span>';
        return;
    }
    
    // Parse the share and path from the path input
    if (!searchPathInput) {
        searchStatus.innerHTML = '<span class="text-red-500 font-medium">Please enter a share and path</span>';
        return;
    }
    
    // Extract share and path from the combined input
    const pathParts = searchPathInput.split('\\');
    const share = pathParts[0];
    const startPath = pathParts.length > 1 ? pathParts.slice(1).join('/') : '';
    
    if (!share) {
        searchStatus.innerHTML = '<span class="text-red-500 font-medium">Please specify a share in the path field</span>';
        return;
    }
    
    // Get search parameters
    const depth = parseInt(document.getElementById('search-depth').value);
    const contentSearch = document.getElementById('search-content').checked;
    const useRegex = document.getElementById('search-regex').checked;
    const caseSensitive = document.getElementById('search-case-sensitive').checked;
    const credHunt = document.getElementById('search-cred-hunt').checked;
    const itemType = document.getElementById('search-item-type').value;

    // Validate search query
    if (!credHunt && !searchQuery) {
        searchStatus.innerHTML = '<span class="text-red-500 font-medium">Please enter a search query or enable Cred Hunt</span>';
        return;
    }

    // Prepare the search data
    const searchData = {
        computer: computer,
        share: share,
        start_path: startPath,
        depth: depth,
        content_search: contentSearch,
        use_regex: useRegex,
        case_sensitive: caseSensitive,
        cred_hunt: credHunt,
        item_type: itemType
    };
    
    // Only add query if it's present or if credHunt is not enabled
    if (searchQuery || !credHunt) {
        searchData.query = searchQuery;
    }
    
    // --- Progressive search via Server-Sent Events ---
    const params = new URLSearchParams();
    Object.entries(searchData).forEach(([k, v]) => {
        if (v !== undefined && v !== null) params.append(k, v);
    });
    const url = `/api/smb/search-stream?${params.toString()}`;

    searchStatus.innerHTML = `<div class="flex items-center gap-2"><span class="animate-spin h-4 w-4 border-2 border-blue-500 dark:border-yellow-500 border-t-transparent dark:border-t-transparent rounded-full"></span> Searching in \\${computer}\\${share}${startPath ? '\\' + startPath.replace(/\//g, '\\') : ''}...</div>`;
    searchResults.innerHTML = '';

    window.lastSearchResults = { items: [], search_info: { host: computer, share: share, search_mode: useRegex ? 'regex' : 'pattern' } };

    const es = new EventSource(url);

    es.onmessage = (ev) => {
        const data = JSON.parse(ev.data);
        if (data.type === 'found') {
            window.lastSearchResults.items.push(data.item);
            searchResults.insertAdjacentHTML('beforeend', buildSearchResultItemHTML(data.item, computer, share));
            attachSearchResultListeners();
            if (window.lastSearchResults.items.length % 5 === 0) {
                searchStatus.innerHTML = `<div class="text-neutral-500 dark:text-neutral-400">Found ${window.lastSearchResults.items.length} so far...</div>`;
            }
        } else if (data.type === 'done') {
            es.close();
            const total = data.total || window.lastSearchResults.items.length;
            searchStatus.innerHTML = `<div class="mb-2"><div class="text-neutral-900 dark:text-white font-medium">Search Results (${total})</div></div>`;
            if (total > 0) {
                exportCsvButton.classList.remove('hidden');
            }
        }
    };

    es.onerror = (err) => {
        console.error('SSE search error', err);
        es.close();
        searchStatus.innerHTML = '<span class="text-red-500 font-medium">Search failed</span>';
    };
    return;
}

function buildSearchResultItemHTML(item, computer, share) {
    const isDirectory = item.is_directory;
    const fileIcon = getFileIcon(item.name, isDirectory);
    const matchType = item.match_type || 'name';
    let matchBadge = '';
    if (matchType === 'content') {
        matchBadge = '<span class="text-xs px-1.5 py-0.5 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200 rounded">Content</span>';
    } else if (matchType === 'credential_file') {
        matchBadge = '<span class="text-xs px-1.5 py-0.5 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded">Credential</span>';
    }
    return `
        <div class="search-result-item bg-white dark:bg-neutral-800 rounded-md border border-neutral-200 dark:border-neutral-700 p-2 hover:bg-neutral-50 dark:hover:bg-neutral-700">
            <div class="flex items-center justify-between gap-2">
                <div class="flex items-center gap-2 min-w-0">
                    ${fileIcon.isCustomSvg ? `<span class="w-4 h-4 flex-shrink-0 ${fileIcon.iconClass}">${fileIcon.icon}</span>` : `<i class="fas ${fileIcon.icon} ${fileIcon.iconClass} flex-shrink-0"></i>`}
                    <div class="truncate">
                        <div class="font-medium text-neutral-900 dark:text-white truncate">${item.name}</div>
                        <div class="text-xs text-neutral-500 dark:text-neutral-400 truncate">${item.path.replace(/\\/g, "\\\\")}</div>
                    </div>
                    ${matchBadge}
                </div>
                <div class="flex items-center gap-1">
                    ${isDirectory ? `
                        <button class="open-result-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="Open" data-computer="${computer}" data-share="${share}" data-path="${item.path}"><i class="fas fa-folder-open fa-sm"></i></button>` : `
                        <button class="view-result-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="View" data-computer="${computer}" data-share="${share}" data-path="${item.path}"><i class="fas fa-eye fa-sm"></i></button>`}
                    <button class="download-result-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-0.5" title="Download" data-computer="${computer}" data-share="${share}" data-path="${item.path}" data-is-dir="${isDirectory}"><i class="fas fa-download fa-sm"></i></button>
                </div>
            </div>
            ${item.content_match ? `<div class="mt-1.5 p-1.5 bg-neutral-100 dark:bg-neutral-900 rounded text-xs font-mono whitespace-pre-wrap text-neutral-800 dark:text-neutral-200 max-h-20 overflow-y-auto">${escapeHTML(item.content_match)}</div>` : ''}
        </div>
    `;
}

function attachSearchResultListeners() {
    const searchPanel = document.getElementById('search-panel');
    
    // Function to hide search panel
    const hideSearchPanel = () => {
        searchPanel.classList.add('translate-x-full');
        setTimeout(() => {
            searchPanel.classList.add('hidden');
        }, 300);
    };
    
    // Attach view button listeners
    document.querySelectorAll('.search-result-item .view-result-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const computer = btn.dataset.computer;
            const share = btn.dataset.share;
            const path = btn.dataset.path;
            hideSearchPanel();
            viewSMBFile(computer, share, path);
        });
    });
    
    // Attach open button listeners
    document.querySelectorAll('.search-result-item .open-result-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const computer = btn.dataset.computer;
            const share = btn.dataset.share;
            const path = btn.dataset.path;
            hideSearchPanel();
            // Simulate navigation to this directory
            if (computer !== activeComputer) {
                switchToPC(computer);
            }
            
            // Find the directory in the tree view and click it
            const targetElement = findTreeElement(computer, share, path);
            if (targetElement) {
                targetElement.click();
            } else {
                // If element not found in tree (not expanded yet), expand from the share
                navigateToPath(computer, share, path);
            }
        });
    });
    
    // Attach download button listeners
    document.querySelectorAll('.search-result-item .download-result-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const computer = btn.dataset.computer;
            const share = btn.dataset.share;
            const path = btn.dataset.path;
            const isDir = btn.dataset.isDir === 'true';
            hideSearchPanel();
            
            if (isDir) {
                const dirName = path.split('\\').pop();
                downloadSMBDirectory(computer, share, path, dirName);
            } else {
                downloadSMBFile(computer, share, path);
            }
        });
    });
}

function findTreeElement(computer, share, path) {
    if (!path) {
        return document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > div`);
    }
    
    // Normalize path - convert backslashes to forward slashes
    const normalizedPath = '/' + path.replace(/\\/g, '/').replace(/^\/+/, '');
    return document.querySelector(`.file-item[data-share="${share}"][data-computer="${computer}"][data-path="${normalizedPath}"] > div`);
}

async function navigateToPath(computer, share, path) {
    // This function handles navigating to a path by expanding the tree
    // Starting from the share root
    const shareElement = document.querySelector(`.smb-tree-item[data-share="${share}"][data-computer="${computer}"] > div`);
    if (!shareElement) return;
    
    // First click on the share to expand it
    shareElement.click();
    
    // Split the path into segments
    const pathSegments = path.replace(/\\/g, '/').replace(/^\/+/, '').split('/');
    let currentPath = '';
    
    // Navigate through each segment
    for (let i = 0; i < pathSegments.length; i++) {
        const segment = pathSegments[i];
        if (!segment) continue;
        
        currentPath += '/' + segment;
        const elementSelector = `.file-item[data-share="${share}"][data-computer="${computer}"][data-path="${currentPath}"] > div`;
        
        // Wait for the element to be available (after previous click has loaded its children)
        let element = null;
        let attempts = 0;
        while (!element && attempts < 10) {
            element = document.querySelector(elementSelector);
            if (!element) {
                await new Promise(resolve => setTimeout(resolve, 100));
                attempts++;
            }
        }
        
        if (element) {
            element.click();
        } else {
            console.error(`Could not find element for path segment: ${currentPath}`);
            break;
        }
    }
}

// Helper function to safely escape HTML
function escapeHTML(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// --- Context Menu Functions ---

function hideContextMenu() {
    if (contextMenuElement) {
        contextMenuElement.classList.add('hidden');
        contextMenuElement.innerHTML = ''; // Clear menu items
    }
}

function createMenuItem(text, iconClass, action) {
    const menuItem = document.createElement('a');
    menuItem.href = '#'; // Prevent default link behavior
    menuItem.className = 'flex items-center gap-2 px-4 py-1.5 text-neutral-700 dark:text-neutral-200 hover:bg-neutral-100 dark:hover:bg-neutral-700';
    menuItem.innerHTML = `<i class="${iconClass} fa-fw"></i> ${text}`;
    menuItem.onclick = (e) => {
        e.preventDefault();
        e.stopPropagation(); // Prevent document click listener from firing immediately
        action();
        hideContextMenu();
    };
    return menuItem;
}

function createMenuSeparator() {
    const separator = document.createElement('div');
    separator.className = 'my-1 h-px bg-neutral-200 dark:bg-neutral-700';
    return separator;
}

function showContextMenu(event, itemData) {
    if (!contextMenuElement) return;

    hideContextMenu(); // Hide any existing menu first

    // Populate menu based on item type
    if (itemData.isDirectory) {
        // Folder/Share actions
        if (!itemData.isShare) { // Don't allow opening a share inside itself
            contextMenuElement.appendChild(createMenuItem('Open', 'fas fa-folder-open', () => {
                // Find the element and simulate a click
                const targetElement = document.querySelector(`.file-item[data-path="${itemData.path}"] > div`);
                targetElement?.click();
            }));
        }
        contextMenuElement.appendChild(createMenuItem('Download', 'fas fa-download', () => {
            downloadSMBDirectory(itemData.computer, itemData.share, itemData.path, itemData.name);
        }));
        // Add Search option for directories and shares
        contextMenuElement.appendChild(createMenuItem('Search', 'fas fa-search', () => {
            openSearchPanel(itemData.computer, itemData.share, itemData.path);
        }));
        contextMenuElement.appendChild(createMenuSeparator());
        contextMenuElement.appendChild(createMenuItem('Upload Here', 'fas fa-upload', () => {
            uploadSMBFile(itemData.computer, itemData.share, itemData.path);
        }));
        contextMenuElement.appendChild(createMenuItem('New Folder', 'fas fa-folder-plus', () => {
            createSMBDirectory(itemData.computer, itemData.share, itemData.path);
        }));
        
        // Add Share option for directories (not shares themselves)
        if (!itemData.isShare) {
            contextMenuElement.appendChild(createMenuItem('Add Share Here', 'fas fa-share-alt text-blue-600 dark:text-blue-400', () => {
                showAddShareModalForDirectory(itemData.computer, itemData.share, itemData.path, itemData.name);
            }));
        }
        
        // Share management options (only for shares)
        if (itemData.isShare) {
            contextMenuElement.appendChild(createMenuSeparator());
            contextMenuElement.appendChild(createMenuItem('Add Share', 'fas fa-plus-circle text-green-600 dark:text-green-400', () => {
                showAddShareModal(itemData.computer);
            }));
            contextMenuElement.appendChild(createMenuItem('Delete Share', 'fas fa-minus-circle text-red-600 dark:text-red-500', () => {
                deleteSMBShare(itemData.computer, itemData.share);
            }));
        }
    } else {
        // File actions
        contextMenuElement.appendChild(createMenuItem('View', 'fas fa-eye', () => {
            viewSMBFile(itemData.computer, itemData.share, itemData.path);
        }));
        contextMenuElement.appendChild(createMenuItem('Download', 'fas fa-download', () => {
            downloadSMBFile(itemData.computer, itemData.share, itemData.path);
        }));
    }

    // Common actions (Delete, Rename, Properties)
    contextMenuElement.appendChild(createMenuSeparator());
    contextMenuElement.appendChild(createMenuItem('Delete', 'fas fa-trash text-red-600 dark:text-red-500', () => {
        deleteSMBFileOrDirectory(itemData.computer, itemData.share, itemData.path, itemData.isDirectory);
    }));
    
    // Rename is now functional - don't add the disabled styling classes
    contextMenuElement.appendChild(createMenuItem('Rename', 'fas fa-pencil-alt', () => {
        renameSMBFileOrDirectory(itemData.computer, itemData.share, itemData.path, itemData.isDirectory, itemData.isShare);
    }));
    
    // Properties is now functional
    contextMenuElement.appendChild(createMenuItem('Properties', 'fas fa-info-circle', () => {
        showProperties(itemData.computer, itemData.share, itemData.path, itemData.isDirectory, itemData.isShare);
    }));

    // Position and show the menu
    const x = event.pageX;
    const y = event.pageY;

    contextMenuElement.style.left = `${x}px`;
    contextMenuElement.style.top = `${y}px`;
    contextMenuElement.classList.remove('hidden');

    // Adjust position if menu goes off-screen (basic implementation)
    const menuRect = contextMenuElement.getBoundingClientRect();
    if (menuRect.right > window.innerWidth) {
        contextMenuElement.style.left = `${x - menuRect.width}px`;
    }
    if (menuRect.bottom > window.innerHeight) {
        contextMenuElement.style.top = `${y - menuRect.height}px`;
    }
}

// Add global listener to hide context menu on left-click
document.addEventListener('click', (event) => {
    // Check if the click is outside the context menu
    if (contextMenuElement && !contextMenuElement.contains(event.target)) {
        hideContextMenu();
    }
});

// Also hide on scroll within the pc-views container
document.getElementById('pc-views')?.addEventListener('scroll', hideContextMenu);

// Add this after the context menu code section

// Properties Functions
async function showProperties(computer, share, path, isDirectory, isShare) {
    const propertiesPanel = document.getElementById('properties-panel');
    const propertiesSpinner = document.getElementById('properties-spinner');
    const propertiesContent = document.getElementById('properties-content');
    const propertiesItemIcon = document.getElementById('properties-item-icon');
    const propertiesItemName = document.getElementById('properties-item-name');
    const propertiesItemPath = document.getElementById('properties-item-path');
    const propertiesBasicInfo = document.getElementById('properties-basic-info');
    const propertiesAttributes = document.getElementById('properties-attributes');
    const propertiesExtendedSection = document.getElementById('properties-extended-section');
    const propertiesExtendedInfo = document.getElementById('properties-extended-info');
    const propertiesSecuritySection = document.getElementById('properties-security-section');
    const propertiesSecurityInfo = document.getElementById('properties-security-info');
    
    // Reset and show the panel
    propertiesBasicInfo.innerHTML = '';
    propertiesAttributes.innerHTML = '';
    propertiesExtendedInfo.innerHTML = '';
    propertiesSecurityInfo.innerHTML = '';
    propertiesExtendedSection.classList.add('hidden');
    propertiesSecuritySection.classList.add('hidden');
    
    // Show the properties panel
    propertiesPanel.classList.remove('hidden');
    setTimeout(() => {
        propertiesPanel.classList.remove('translate-x-full');
    }, 10);
    
    // Store data attributes for delete functionality
    propertiesPanel.setAttribute('data-computer', computer);
    propertiesPanel.setAttribute('data-share', share);
    propertiesPanel.setAttribute('data-path', path || '');
    propertiesPanel.setAttribute('data-is-directory', isDirectory.toString());
    propertiesPanel.setAttribute('data-is-share', isShare.toString());
    
    // Show loading state
    propertiesSpinner.classList.remove('hidden');
    propertiesContent.classList.add('opacity-50');
    
    try {
        // Normalize path separators for display - Windows uses backslashes
        const normalizedPath = path.replace(/\//g, '\\');
        
        // Get file/folder name from path
        const itemName = normalizedPath.split('\\').pop();
        propertiesItemName.textContent = itemName;
        
        // Format UNC path properly - make sure there are no double slashes
        const uncPath = `\\\\${computer}\\${share}\\${normalizedPath.replace(/^[\/\\]+/, '')}`;
        propertiesItemPath.textContent = uncPath;
        
        // Set icon based on type
        if (isDirectory) {
            propertiesItemIcon.className = 'fas fa-folder text-yellow-500';
        } else {
            const fileIcon = getFileIcon(itemName, false);
            if (fileIcon.isCustomSvg) {
                propertiesItemIcon.outerHTML = `<span id="properties-item-icon" class="w-4 h-4 ${fileIcon.iconClass}">${fileIcon.icon}</span>`;
            } else {
                propertiesItemIcon.className = `fas ${fileIcon.icon} ${fileIcon.iconClass}`;
            }
        }
        
        // Fetch properties from API
        const response = await fetch('/api/smb/properties', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to fetch properties');
        }
        
        const properties = await response.json();
        
        // Basic info table
        const basicInfoFields = [];
        if(!isShare) {
            basicInfoFields.push({
                key: 'type', label: 'Type', value: isDirectory ? 'Folder' : getFileType(itemName)
            });
            basicInfoFields.push({
                key: 'size', label: 'Size', value: formatFileSize(properties.size || 0)
            });
            basicInfoFields.push({
                key: 'owner', label: 'Owner', value: properties.owner || 'Unknown', highlight: true
            });
            basicInfoFields.push({ key: 'created', label: 'Created', value: convertWindowsTime(properties.created) });
            basicInfoFields.push({ key: 'modified', label: 'Modified', value: convertWindowsTime(properties.modified) });
            basicInfoFields.push({ key: 'accessed', label: 'Last Accessed', value: convertWindowsTime(properties.accessed) });
        } else {
            basicInfoFields.push({
                key: 'type', label: 'Type', value: 'Share'
            });
            basicInfoFields.push({
                key: 'name', label: 'Name', value: properties.name || ''
            });
            basicInfoFields.push({
                key: 'Remark', label: 'Remark', value: properties.remark || ''
            });
            basicInfoFields.push({
                key: 'Path', label: 'Path', value: properties.path || ''
            });
        }
        
        // Add Windows timestamps in raw format (useful for red teamers)
        if (properties.created_windows) {
            basicInfoFields.push({ 
                key: 'created_windows', 
                label: 'Created (Win)', 
                value: properties.created_windows,
                class: 'text-xs font-mono'
            });
        }
        
        if (properties.modified_windows) {
            basicInfoFields.push({ 
                key: 'modified_windows', 
                label: 'Modified (Win)', 
                value: properties.modified_windows,
                class: 'text-xs font-mono'
            });
        }
        
        // UNC path - useful for exploitation
        basicInfoFields.push({ 
            key: 'unc_path', 
            label: 'UNC Path', 
            value: properties.full_path || `\\\\${computer}\\${share}\\${path}`,
            class: 'text-xs font-mono break-all'
        });
        
        basicInfoFields.forEach(field => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td class="py-1 pr-2 text-neutral-600 dark:text-neutral-400">${field.label}:</td>
                <td class="py-1 text-neutral-900 dark:text-white ${field.highlight ? 'font-medium' : ''} ${field.class || ''}">${field.value}</td>
            `;
            propertiesBasicInfo.appendChild(row);
        });
        
        // Attributes badges
        if (properties.attribute_flags && properties.attribute_flags.length > 0) {
            const securityRelevantAttributes = ['HIDDEN', 'SYSTEM', 'ENCRYPTED', 'REPARSE_POINT', 'OFFLINE', 'INTEGRITY_STREAM'];
            
            properties.attribute_flags.forEach(attr => {
                const badge = document.createElement('span');
                // Highlight security-relevant attributes
                const isSecurityRelevant = securityRelevantAttributes.includes(attr);
                badge.className = `px-1.5 py-0.5 ${isSecurityRelevant ? 'bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-200' : 'bg-neutral-100 dark:bg-neutral-800 text-neutral-600 dark:text-neutral-400'} rounded-md text-xs whitespace-nowrap mb-1 mr-1 inline-block`;
                badge.textContent = attr;
                propertiesAttributes.appendChild(badge);
            });
            
            // Add raw attribute value
            if (properties.attributes !== undefined) {
                const hexValue = document.createElement('div');
                hexValue.className = 'mt-1 text-xs font-mono text-neutral-500 dark:text-neutral-400';
                hexValue.textContent = `Hex: 0x${properties.attributes.toString(16).toUpperCase()}`;
                propertiesAttributes.appendChild(hexValue);
            }
        } else {
            propertiesAttributes.innerHTML = '<span class="text-neutral-500 dark:text-neutral-400 text-xs">No attributes</span>';
        }
        
        // Security information
        if (properties.dacl && properties.dacl.length > 0) {
            propertiesSecuritySection.classList.remove('hidden');
            
            // Group permissions by trustee for a Windows-like display
            const permissionsByTrustee = {};
            properties.dacl.forEach(ace => {
                if (!permissionsByTrustee[ace.trustee]) {
                    permissionsByTrustee[ace.trustee] = {
                        trustee: ace.trustee,
                        permissions: new Set(),
                        isHighRisk: false,
                        details: []
                    };
                }
                
                // Add the permission
                if (typeof ace.permissions === 'string') {
                    permissionsByTrustee[ace.trustee].permissions.add(ace.permissions);
                } else if (Array.isArray(ace.permissions)) {
                    ace.permissions.forEach(perm => {
                        permissionsByTrustee[ace.trustee].permissions.add(perm);
                    });
                }
                
                // Check if this is a high-risk permission
                if ((typeof ace.permissions === 'string' && 
                     (ace.permissions === 'FullControl' || ace.permissions.includes('Write'))) ||
                    (Array.isArray(ace.permissions) && 
                     ace.permissions.some(p => p === 'FullControl' || p.includes('Write')))) {
                    permissionsByTrustee[ace.trustee].isHighRisk = true;
                }
                
                // Store detailed information
                permissionsByTrustee[ace.trustee].details.push({
                    type: ace.type,
                    flags: ace.ace_flags,
                    access_mask: ace.access_mask_raw
                });
            });
            
            // Create permission table
            const permissionTable = document.createElement('table');
            permissionTable.className = 'w-full text-xs border-collapse';
            const tableHead = document.createElement('thead');
            tableHead.innerHTML = `
                <tr>
                    <th class="text-left py-1 font-medium text-neutral-700 dark:text-neutral-300">Principal</th>
                    <th class="text-left py-1 font-medium text-neutral-700 dark:text-neutral-300">Permissions</th>
                </tr>
            `;
            permissionTable.appendChild(tableHead);
            
            const tableBody = document.createElement('tbody');
            
            // Sort trustees to show Administrator/System first, then others
            const sortedTrustees = Object.keys(permissionsByTrustee).sort((a, b) => {
                // Administrator and system accounts first
                const isAPriority = a.includes('Administrator') || a.includes('SYSTEM') || a === 'Local System';
                const isBPriority = b.includes('Administrator') || b.includes('SYSTEM') || b === 'Local System';
                
                if (isAPriority && !isBPriority) return -1;
                if (!isAPriority && isBPriority) return 1;
                
                // Then sort by high-risk permissions
                if (permissionsByTrustee[a].isHighRisk && !permissionsByTrustee[b].isHighRisk) return -1;
                if (!permissionsByTrustee[a].isHighRisk && permissionsByTrustee[b].isHighRisk) return 1;
                
                // Then alphabetically
                return a.localeCompare(b);
            });
            
            sortedTrustees.forEach(trustee => {
                const trusteeInfo = permissionsByTrustee[trustee];
                const row = document.createElement('tr');
                row.className = trusteeInfo.isHighRisk ? 'hover:bg-red-50 dark:hover:bg-red-900/20' : 'hover:bg-neutral-50 dark:hover:bg-neutral-800';
                
                // Format permissions nicely
                let formattedPermissions = Array.from(trusteeInfo.permissions).join(', ');
                
                // Simplify permissions if needed
                if (trusteeInfo.permissions.has('FullControl')) {
                    formattedPermissions = 'Full Control';
                } else if (trusteeInfo.permissions.has('ReadAndExecute') && 
                          !Array.from(trusteeInfo.permissions).some(p => p.includes('Write') || p.includes('Modify'))) {
                    formattedPermissions = 'Read & Execute';
                } else if (trusteeInfo.permissions.has('GenericRead') && 
                          trusteeInfo.permissions.has('GenericExecute') &&
                          !Array.from(trusteeInfo.permissions).some(p => p.includes('Write') || p.includes('Modify'))) {
                    formattedPermissions = 'Read & Execute';
                }
                
                row.innerHTML = `
                    <td class="py-1 border-t border-neutral-200 dark:border-neutral-700 pr-2 font-medium ${trusteeInfo.isHighRisk ? 'text-red-600 dark:text-red-400' : 'text-neutral-800 dark:text-neutral-200'}">${trustee}</td>
                    <td class="py-1 border-t border-neutral-200 dark:border-neutral-700 ${trusteeInfo.isHighRisk ? 'text-red-600 dark:text-red-400' : 'text-neutral-600 dark:text-neutral-400'}">${formattedPermissions}</td>
                `;
                
                // Add click handler to show more details
                row.style.cursor = 'pointer';
                row.addEventListener('click', () => {
                    showPermissionDetails(trustee, trusteeInfo);
                });
                
                tableBody.appendChild(row);
            });
            
            permissionTable.appendChild(tableBody);
            
            // Add a subtle row for adding new permissions
            const addPermissionRow = document.createElement('tr');
            addPermissionRow.className = 'border-t border-neutral-200 dark:border-neutral-700 hover:bg-neutral-50 dark:hover:bg-neutral-800 cursor-pointer';
            addPermissionRow.innerHTML = `
                <td colspan="2" class="py-1 text-center">
                    <button class="inline-flex items-center justify-center w-6 h-6 text-neutral-400 hover:text-neutral-600 dark:text-neutral-500 dark:hover:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-neutral-700 rounded-full transition-colors">
                        <i class="fas fa-plus fa-sm"></i>
                    </button>
                </td>
            `;
            addPermissionRow.addEventListener('click', () => {
                showAddPermissionModal(computer, share, path, isDirectory, isShare);
            });
            
            tableBody.appendChild(addPermissionRow);
            permissionTable.appendChild(tableBody);
            propertiesSecurityInfo.appendChild(permissionTable);
            
            // Add a note about clicking for more details
            const detailsNote = document.createElement('div');
            detailsNote.className = 'mt-2 text-xs text-neutral-500 dark:text-neutral-400 text-center';
            detailsNote.innerHTML = '<i class="fas fa-info-circle mr-1"></i> Click on a principal to view detailed permissions';
            propertiesSecurityInfo.appendChild(detailsNote);
        }
        
        // Alternate streams - often important for red teamers
        if (properties.extended_attributes && properties.extended_attributes.alternate_streams && 
            properties.extended_attributes.alternate_streams.length > 0) {
            propertiesExtendedSection.classList.remove('hidden');
            
            const adsTitle = document.createElement('div');
            adsTitle.className = 'font-medium text-neutral-700 dark:text-neutral-300 mb-1';
            adsTitle.textContent = 'Alternate Data Streams';
            propertiesExtendedInfo.appendChild(adsTitle);
            
            const adsTable = document.createElement('table');
            adsTable.className = 'w-full text-xs border-collapse';
            
            properties.extended_attributes.alternate_streams.forEach(stream => {
                const row = document.createElement('tr');
                row.innerHTML = `
                    <td class="py-1 text-neutral-600 dark:text-neutral-400">${stream.name}:</td>
                    <td class="py-1 text-red-600 dark:text-red-400 font-medium">${formatFileSize(stream.size)} (ADS)</td>
                `;
                adsTable.appendChild(row);
            });
            
            propertiesExtendedInfo.appendChild(adsTable);
            
            // Add a security warning about ADS
            const adsWarning = document.createElement('div');
            adsWarning.className = 'mt-2 text-xs text-red-500 dark:text-red-400';
            adsWarning.innerHTML = '<i class="fas fa-exclamation-triangle mr-1"></i> Alternate Data Streams can be used to hide malicious content';
            propertiesExtendedInfo.appendChild(adsWarning);
        }
        
    } catch (error) {
        console.error('Properties error:', error);
        showErrorAlert(error.message);
    } finally {
        // Hide loading state
        propertiesSpinner.classList.add('hidden');
        propertiesContent.classList.remove('opacity-50');
    }
}

// Add this function to display detailed permissions for a specific trustee
function showPermissionDetails(trustee, trusteeInfo) {
    // Create modal for showing detailed permissions
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-white dark:bg-neutral-900 rounded-lg shadow-lg p-4 max-w-lg w-full max-h-[80vh] overflow-y-auto permission-details-modal">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-semibold text-neutral-900 dark:text-white">Permissions for ${trustee}</h3>
                <button class="text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200 p-1 close-modal-btn">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div>
                <h4 class="text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2">Effective Permissions</h4>
                <div class="flex flex-wrap gap-1 mb-4">
                    ${Array.from(trusteeInfo.permissions).map(perm => 
                        `<span class="px-1.5 py-0.5 bg-neutral-100 dark:bg-neutral-800 text-neutral-800 dark:text-neutral-200 rounded-md text-xs">${perm}</span>`
                    ).join('')}
                </div>
                
                <h4 class="text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-2">Access Control Entries</h4>
                <div class="space-y-2">
                    ${trusteeInfo.details.map((detail, index) => `
                        <div class="p-2 bg-neutral-50 dark:bg-neutral-800 rounded-md">
                            <div class="flex items-center justify-between">
                                <div class="text-xs font-medium text-neutral-900 dark:text-white">${detail.type}</div>
                                <button class="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 p-1 rounded hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors remove-ace-btn" 
                                        title="Remove this ACE"
                                        data-trustee="${trustee}" 
                                        data-ace-index="${index}">
                                    <i class="fas fa-trash fa-xs"></i>
                                </button>
                            </div>
                            ${detail.flags && detail.flags.length > 0 ? `
                                <div class="text-xs text-neutral-600 dark:text-neutral-400 mt-1">
                                    <span class="font-medium">Flags:</span> ${detail.flags.join(', ')}
                                </div>
                            ` : ''}
                            <div class="text-xs text-neutral-600 dark:text-neutral-400 mt-1">
                                <span class="font-medium">Access Mask:</span> 0x${detail.access_mask.toString(16).toUpperCase()}
                            </div>
                        </div>
                    `).join('')}
                </div>
            </div>
            <div class="mt-4 flex justify-end">
                <button class="px-3 py-1 bg-neutral-900 dark:bg-yellow-500 text-white dark:text-black rounded-md text-sm font-medium close-modal-btn">Close</button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Prevent clicks inside the modal from propagating to document
    const modalContent = modal.querySelector('.permission-details-modal');
    modalContent.addEventListener('click', e => {
        e.stopPropagation();
    });
    
    // Add event listeners to close the modal
    const closeButtons = modal.querySelectorAll('.close-modal-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', e => {
            e.preventDefault();
            e.stopPropagation(); // Stop event from reaching document
            document.body.removeChild(modal);
        });
    });
    
    // Close on click outside of modal content
    modal.addEventListener('click', e => {
        if (e.target === modal) {
            e.preventDefault();
            e.stopPropagation(); // Stop event from reaching document
            document.body.removeChild(modal);
        }
    });
    
    // Add event listeners for ACE delete buttons
    const removeButtons = modal.querySelectorAll('.remove-ace-btn');
    removeButtons.forEach(button => {
        button.addEventListener('click', async (e) => {
            e.preventDefault();
            e.stopPropagation();
            
            const trusteeToRemove = button.getAttribute('data-trustee');
            
            if (confirm(`Are you sure you want to remove all ACEs for ${trusteeToRemove}?`)) {
                try {
                    // Get the current properties to extract computer, share, path
                    const propertiesPanel = document.getElementById('properties-panel');
                    const computer = propertiesPanel.getAttribute('data-computer');
                    const share = propertiesPanel.getAttribute('data-share');
                    const path = propertiesPanel.getAttribute('data-path');
                    const isDirectory = propertiesPanel.getAttribute('data-is-directory') === 'true';
                    const isShare = propertiesPanel.getAttribute('data-is-share') === 'true';
                    
                    await removeSMBSecurity(computer, share, path, trusteeToRemove, isDirectory, isShare);
                    
                    // Close the modal and refresh properties
                    document.body.removeChild(modal);
                    showProperties(computer, share, path, isDirectory, isShare);
                } catch (error) {
                    showErrorAlert(error.message);
                }
            }
        });
    });
}

// Helper to get readable file type
function getFileType(filename) {
    const ext = filename.split('.').pop().toLowerCase();
    const typeMap = {
        'txt': 'Text Document',
        'doc': 'Word Document',
        'docx': 'Word Document',
        'pdf': 'PDF Document',
        'jpg': 'JPEG Image',
        'jpeg': 'JPEG Image',
        'png': 'PNG Image',
        'gif': 'GIF Image',
        'mp3': 'MP3 Audio',
        'mp4': 'MP4 Video',
        'zip': 'ZIP Archive',
        'rar': 'RAR Archive',
        'exe': 'Executable',
        'dll': 'Dynamic Link Library',
        'xls': 'Excel Spreadsheet',
        'xlsx': 'Excel Spreadsheet',
        'ppt': 'PowerPoint Presentation',
        'pptx': 'PowerPoint Presentation',
        'html': 'HTML Document',
        'htm': 'HTML Document',
        'css': 'CSS Stylesheet',
        'js': 'JavaScript File',
        'json': 'JSON File',
        'xml': 'XML File',
        'bat': 'Batch File',
        'sh': 'Shell Script',
        'py': 'Python Script',
        'c': 'C Source File',
        'cpp': 'C++ Source File',
        'h': 'Header File',
        'java': 'Java Source File',
        'php': 'PHP Script',
        'ini': 'Configuration File',
        'cfg': 'Configuration File',
        'conf': 'Configuration File',
        'log': 'Log File'
    };
    
    return typeMap[ext] || `${ext.toUpperCase()} File`;
}

// (duplicate showContextMenu removed)

function convertWindowsTime(fileTime) {
    if (!fileTime || fileTime === '0') return 'Not available';
    
    try {
        // Special cases for strings that already look like a date
        if (typeof fileTime === 'string' && fileTime.includes('-') && fileTime.includes(':')) {
            return fileTime; // Already in readable format
        }
        
        // Convert to BigInt to handle large values safely
        const windowsTime = typeof fileTime === 'string' ? BigInt(fileTime) : BigInt(0);
        
        // Windows FILETIME format starts from January 1, 1601 (UTC)
        // Need to adjust to Unix epoch (January 1, 1970)
        const windowsEpochInUnixTime = 11644473600000n;
        
        // Windows timestamps are in 100-nanosecond intervals
        const unixTimeMs = Number((windowsTime / 10000n) - windowsEpochInUnixTime);
        
        // Create a Date object using the adjusted time
        const date = new Date(unixTimeMs);
        
        // Check if the date is valid
        if (isNaN(date.getTime())) {
            return fileTime.toString();
        }
        
        // Format the date to include milliseconds for forensic precision
        const formatOptions = { 
            year: 'numeric', 
            month: '2-digit', 
            day: '2-digit',
            hour: '2-digit', 
            minute: '2-digit', 
            second: '2-digit',
            hour12: false
        };
        
        // Format: YYYY-MM-DD HH:MM:SS.mmm
        const formattedDate = date.toLocaleString(undefined, formatOptions)
            .replace(',', '')
            .replace('/', '-')
            .replace('/', '-');
            
        return `${formattedDate}.${date.getMilliseconds().toString().padStart(3, '0')}`;
    } catch (error) {
        // If conversion fails, just return the original value
        return fileTime.toString();
    }
}

// Add this function to display a modal for adding new permissions
function showAddPermissionModal(computer, share, path, isDirectory, isShare) {
    // Create modal for adding new permissions
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-white dark:bg-neutral-900 rounded-lg shadow-lg p-4 max-w-md w-full max-h-[80vh] overflow-y-auto add-permission-modal">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-semibold text-neutral-900 dark:text-white">Add Permission</h3>
                <button class="text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200 p-1 close-modal-btn">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div class="space-y-4">
                <!-- Target info -->
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800 rounded-md">
                    <div class="flex items-center justify-between mb-1">
                        <div class="text-xs font-medium text-neutral-900 dark:text-white">Target</div>
                        <span class="text-xs px-1.5 py-0.5 rounded-md ${isShare ? 'bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200' : 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200'}">
                            ${isShare ? 'Share' : (isDirectory ? 'Folder' : 'File')}
                        </span>
                    </div>
                    <div class="text-xs text-neutral-600 dark:text-neutral-400 break-all">
                        ${isShare ? `\\\\${computer}\\${share}` : `\\\\${computer}\\${share}\\${path}`}
                    </div>
                </div>
                
                <!-- User/Principal input -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Principal (Username or SID)
                    </label>
                    <input type="text" id="add-permission-principal" 
                           placeholder="DOMAIN\\username or S-1-5-..." 
                           class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Enter a domain username (e.g., DOMAIN\\user) or SID (e.g., S-1-5-21-...)
                    </div>
                </div>
                
                <!-- ACE Type selection -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Permission Type
                    </label>
                    <select id="add-permission-type" class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                        <option value="allow">Allow</option>
                        <option value="deny">Deny</option>
                    </select>
                </div>
                
                <!-- Permission Level (informational - backend uses full control) -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Permission Level
                    </label>
                    <select id="add-permission-level" class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                        <option value="fullcontrol">Full Control</option>
                        <option value="modify">Modify</option>
                        <option value="readandwrite">Read & Write</option>
                        <option value="readandexecute">Read & Execute</option>
                        <option value="read">Read</option>
                        <option value="write">Write</option>
                    </select>
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Select the permission level to grant or deny
                    </div>
                </div>
                
                <!-- Warning for deny permissions -->
                <div id="deny-warning" class="hidden p-2 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md">
                    <div class="flex items-start gap-2">
                        <i class="fas fa-exclamation-triangle text-red-500 dark:text-red-400 mt-0.5"></i>
                        <div class="text-xs text-red-700 dark:text-red-300">
                            <strong>Warning:</strong> Deny permissions take precedence over Allow permissions and can lock out access, including your own.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="mt-6 flex justify-end gap-2">
                <button class="px-3 py-1 bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-300 rounded-md text-sm font-medium close-modal-btn hover:bg-neutral-300 dark:hover:bg-neutral-600">
                    Cancel
                </button>
                <button id="add-permission-confirm" class="px-3 py-1 bg-green-600 dark:bg-green-500 text-white dark:text-black rounded-md text-sm font-medium hover:bg-green-700 dark:hover:bg-green-600">
                    <i class="fas fa-plus fa-sm mr-1"></i>
                    Add Permission
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Get modal elements
    const modalContent = modal.querySelector('.add-permission-modal');
    const principalInput = modal.querySelector('#add-permission-principal');
    const typeSelect = modal.querySelector('#add-permission-type');
    const levelSelect = modal.querySelector('#add-permission-level');
    const denyWarning = modal.querySelector('#deny-warning');
    const confirmBtn = modal.querySelector('#add-permission-confirm');
    
    // Show/hide deny warning based on selection
    typeSelect.addEventListener('change', () => {
        if (typeSelect.value === 'deny') {
            denyWarning.classList.remove('hidden');
        } else {
            denyWarning.classList.add('hidden');
        }
    });
    
    // Focus on principal input
    setTimeout(() => principalInput.focus(), 100);
    
    // Handle form submission
    confirmBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        const principal = principalInput.value.trim();
        const aceType = typeSelect.value;
        const permissionLevel = levelSelect.value;
        
        if (!principal) {
            showErrorAlert('Please enter a principal (username or SID)');
            return;
        }
        
        // Show loading state
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin fa-sm mr-1"></i> Adding...';
        
        try {
            // Determine which endpoint to use based on whether this is a share or file/directory
            const endpoint = isShare ? '/api/smb/set-share-security' : '/api/smb/set-security';
            
            // Prepare request body - shares don't need path parameter
            const requestBody = {
                computer: computer,
                share: share,
                username: principal,
                ace_type: aceType,
                mask: permissionLevel
            };
            
            // Only add path for files/directories, not for shares
            if (!isShare) {
                requestBody.path = path;
            }
            
            const response = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(requestBody)
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to add permission');
            }
            
            const result = await response.json();
            
            // Close modal
            document.body.removeChild(modal);
            
            // Show success message - use the message from the server response if available
            let successMessage;
            if (result.message) {
                successMessage = result.message;
            } else {
                const permissionNames = {
                    'fullcontrol': 'Full Control',
                    'modify': 'Modify',
                    'readandwrite': 'Read & Write',
                    'readandexecute': 'Read & Execute',
                    'read': 'Read',
                    'write': 'Write'
                };
                const permissionName = permissionNames[permissionLevel] || permissionLevel;
                const targetType = isShare ? 'share' : (isDirectory ? 'folder' : 'file');
                successMessage = `${permissionName} permission ${aceType === 'allow' ? 'granted' : 'denied'} for ${principal} on ${targetType} ${isShare ? share : path}`;
            }
            showSuccessAlert(successMessage);
            
            // Refresh the properties panel to show the new permission
            setTimeout(() => {
                showProperties(computer, share, path, isDirectory, isShare);
            }, 500);
            
        } catch (error) {
            console.error('Add permission error:', error);
            showErrorAlert(error.message);
            
            // Reset button state
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '<i class="fas fa-plus fa-sm mr-1"></i> Add Permission';
        }
    });
    
    // Prevent clicks inside the modal from propagating to document
    modalContent.addEventListener('click', e => {
        e.stopPropagation();
    });
    
    // Add event listeners to close the modal
    const closeButtons = modal.querySelectorAll('.close-modal-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', e => {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        });
    });
    
    // Close on click outside of modal content
    modal.addEventListener('click', e => {
        if (e.target === modal) {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        }
    });
    
    // Close on Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            document.body.removeChild(modal);
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
}

// Function to remove SMB security (ACE deletion)
async function removeSMBSecurity(computer, share, path, username, isDirectory, isShare) {
    try {
        // Determine which endpoint to use based on whether this is a share or file/directory
        const endpoint = isShare ? '/api/smb/remove-share-security' : '/api/smb/remove-security';
        
        // Prepare request body - shares don't need path parameter
        const requestBody = {
            computer: computer,
            share: share,
            username: username
        };
        
        // Only add path for files/directories, not for shares
        if (!isShare) {
            requestBody.path = path;
        }
        
        const response = await fetch(endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });

        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Failed to remove ACE');
        }
        
        const targetType = isShare ? 'share' : (isDirectory ? 'folder' : 'file');
        const successMessage = result.message || `ACE removed for ${username} from ${targetType} ${isShare ? share : path}`;
        showSuccessAlert(successMessage);
        return result;
    } catch (error) {
        console.error('Remove security error:', error);
        throw error;
    }
}

// Share Management Functions
function showAddShareModal(computer) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    modal.innerHTML = `
        <div class="bg-white dark:bg-neutral-900 rounded-lg shadow-lg p-4 max-w-md w-full max-h-[80vh] overflow-y-auto add-share-modal">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-semibold text-neutral-900 dark:text-white">Add New Share</h3>
                <button class="text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200 p-1 close-modal-btn">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div class="space-y-4">
                <!-- Target computer info -->
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800 rounded-md">
                    <div class="flex items-center justify-between mb-1">
                        <div class="text-xs font-medium text-neutral-900 dark:text-white">Target Computer</div>
                        <span class="text-xs px-1.5 py-0.5 rounded-md bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                            Remote Host
                        </span>
                    </div>
                    <div class="text-xs text-neutral-600 dark:text-neutral-400 break-all">
                        ${computer}
                    </div>
                </div>
                
                <!-- Share name input -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Share Name <span class="text-red-500">*</span>
                    </label>
                    <input type="text" id="add-share-name" 
                           placeholder="ShareName (e.g., PowerViewShare)" 
                           class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Enter a name for the new share (no spaces or special characters recommended)
                    </div>
                </div>
                
                <!-- Local path input -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Local Path <span class="text-red-500">*</span>
                    </label>
                    <input type="text" id="add-share-path" 
                           placeholder="C:\\temp\\shared (local path on target)" 
                           class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Enter the local directory path on the target computer to share
                    </div>
                </div>
                
                <!-- Warning for red team operations -->
                <div class="p-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
                    <div class="flex items-start gap-2">
                        <i class="fas fa-exclamation-triangle text-yellow-500 dark:text-yellow-400 mt-0.5"></i>
                        <div class="text-xs text-yellow-700 dark:text-yellow-300">
                            <strong>Red Team Note:</strong> Creating shares can be detected by security monitoring. Ensure this aligns with your engagement scope and cleanup procedures.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="mt-6 flex justify-end gap-2">
                <button class="px-3 py-1 bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-300 rounded-md text-sm font-medium close-modal-btn hover:bg-neutral-300 dark:hover:bg-neutral-600">
                    Cancel
                </button>
                <button id="add-share-confirm" class="px-3 py-1 bg-green-600 dark:bg-green-500 text-white dark:text-black rounded-md text-sm font-medium hover:bg-green-700 dark:hover:bg-green-600">
                    <i class="fas fa-plus fa-sm mr-1"></i>
                    Create Share
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Get modal elements
    const modalContent = modal.querySelector('.add-share-modal');
    const shareNameInput = modal.querySelector('#add-share-name');
    const sharePathInput = modal.querySelector('#add-share-path');
    const confirmBtn = modal.querySelector('#add-share-confirm');
    
    // Focus on share name input
    setTimeout(() => shareNameInput.focus(), 100);
    
    // Handle form submission
    confirmBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        const shareName = shareNameInput.value.trim();
        const sharePath = sharePathInput.value.trim();
        
        if (!shareName) {
            showErrorAlert('Please enter a share name');
            return;
        }
        
        if (!sharePath) {
            showErrorAlert('Please enter a local path');
            return;
        }
        
        // Show loading state
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin fa-sm mr-1"></i> Creating...';
        
        try {
            const response = await fetch('/api/smb/add-share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    computer: computer,
                    share_name: shareName,
                    share_path: sharePath
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to create share');
            }
            
            const result = await response.json();
            
            // Close modal
            document.body.removeChild(modal);
            
            // Show success message
            const successMessage = result.message || `Share "${shareName}" created successfully at ${sharePath}`;
            showSuccessAlert(successMessage);
            
            // Refresh the shares list for this computer
            setTimeout(async () => {
                try {
                    const shares = await listSMBShares(computer);
                    // Find the view for this computer and update it
                    const computerView = document.getElementById(`view-${computer}`);
                    if (computerView) {
                        computerView.innerHTML = buildSMBTreeView(shares, computer);
                        attachTreeViewListeners();
                    }
                } catch (error) {
                    console.error('Error refreshing shares after creation:', error);
                }
            }, 500);
            
        } catch (error) {
            console.error('Add share error:', error);
            showErrorAlert(error.message);
            
            // Reset button state
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '<i class="fas fa-plus fa-sm mr-1"></i> Create Share';
        }
    });
    
    // Prevent clicks inside the modal from propagating to document
    modalContent.addEventListener('click', e => {
        e.stopPropagation();
    });
    
    // Add event listeners to close the modal
    const closeButtons = modal.querySelectorAll('.close-modal-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', e => {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        });
    });
    
    // Close on click outside of modal content
    modal.addEventListener('click', e => {
        if (e.target === modal) {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        }
    });
    
    // Close on Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            document.body.removeChild(modal);
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
}

function showAddShareModalForDirectory(computer, share, directoryPath, directoryName) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black/50 flex items-center justify-center z-50';
    
    const normalizedPath = directoryPath.replace(/^[\/\\]+/, '').replace(/\//g, '\\');
    const suggestedLocalPath = share === 'C$' ? `C:\\${normalizedPath}` : 
                              share.endsWith('$') ? `${share.charAt(0)}:\\${normalizedPath}` :
                              `\\\\${computer}\\${share}\\${normalizedPath}`;
    
    const suggestedShareName = directoryName ? directoryName.replace(/[^a-zA-Z0-9]/g, '') : 'NewShare';
    
    modal.innerHTML = `
        <div class="bg-white dark:bg-neutral-900 rounded-lg shadow-lg p-4 max-w-md w-full max-h-[80vh] overflow-y-auto add-share-modal">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-base font-semibold text-neutral-900 dark:text-white">Add Share for Directory</h3>
                <button class="text-neutral-500 hover:text-neutral-700 dark:text-neutral-400 dark:hover:text-neutral-200 p-1 close-modal-btn">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <div class="space-y-4">
                <!-- Target computer and directory info -->
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800 rounded-md">
                    <div class="flex items-center justify-between mb-1">
                        <div class="text-xs font-medium text-neutral-900 dark:text-white">Target Directory</div>
                        <span class="text-xs px-1.5 py-0.5 rounded-md bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200">
                            ${computer}
                        </span>
                    </div>
                    <div class="text-xs text-neutral-600 dark:text-neutral-400 break-all">
                        \\\\${computer}\\${share}\\${normalizedPath}
                    </div>
                </div>
                
                <!-- Share name input -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Share Name <span class="text-red-500">*</span>
                    </label>
                    <input type="text" id="add-share-name" 
                           value="${suggestedShareName}"
                           placeholder="ShareName (e.g., PowerViewShare)" 
                           class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Enter a name for the new share (no spaces or special characters recommended)
                    </div>
                </div>
                
                <!-- Local path input -->
                <div>
                    <label class="block text-sm font-medium text-neutral-700 dark:text-neutral-300 mb-1">
                        Local Path <span class="text-red-500">*</span>
                    </label>
                    <input type="text" id="add-share-path" 
                           value="${suggestedLocalPath}"
                           placeholder="C:\\temp\\shared (local path on target)" 
                           class="w-full px-2 py-1 text-sm border border-neutral-300 dark:border-neutral-600 rounded-md bg-white dark:bg-neutral-800 text-neutral-900 dark:text-white focus:ring-1 focus:ring-blue-500 dark:focus:ring-yellow-500 outline-none">
                    <div class="text-xs text-neutral-500 dark:text-neutral-400 mt-1">
                        Local directory path on the target computer (auto-suggested based on current location)
                    </div>
                </div>
                
                <!-- Info about the operation -->
                <div class="p-2 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-md">
                    <div class="flex items-start gap-2">
                        <i class="fas fa-info-circle text-blue-500 dark:text-blue-400 mt-0.5"></i>
                        <div class="text-xs text-blue-700 dark:text-blue-300">
                            <strong>Directory Share:</strong> This will create a new share pointing to the selected directory, making it accessible via SMB from other systems.
                        </div>
                    </div>
                </div>
                
                <!-- Warning for red team operations -->
                <div class="p-2 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-md">
                    <div class="flex items-start gap-2">
                        <i class="fas fa-exclamation-triangle text-yellow-500 dark:text-yellow-400 mt-0.5"></i>
                        <div class="text-xs text-yellow-700 dark:text-yellow-300">
                            <strong>Red Team Note:</strong> Creating shares can be detected by security monitoring. Ensure this aligns with your engagement scope and cleanup procedures.
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="mt-6 flex justify-end gap-2">
                <button class="px-3 py-1 bg-neutral-200 dark:bg-neutral-700 text-neutral-700 dark:text-neutral-300 rounded-md text-sm font-medium close-modal-btn hover:bg-neutral-300 dark:hover:bg-neutral-600">
                    Cancel
                </button>
                <button id="add-share-confirm" class="px-3 py-1 bg-green-600 dark:bg-green-500 text-white dark:text-black rounded-md text-sm font-medium hover:bg-green-700 dark:hover:bg-green-600">
                    <i class="fas fa-share-alt fa-sm mr-1"></i>
                    Create Share
                </button>
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
    
    // Get modal elements
    const modalContent = modal.querySelector('.add-share-modal');
    const shareNameInput = modal.querySelector('#add-share-name');
    const sharePathInput = modal.querySelector('#add-share-path');
    const confirmBtn = modal.querySelector('#add-share-confirm');
    
    // Select the suggested share name for easy editing
    setTimeout(() => {
        shareNameInput.focus();
        shareNameInput.select();
    }, 100);
    
    // Handle form submission
    confirmBtn.addEventListener('click', async (e) => {
        e.preventDefault();
        e.stopPropagation();
        
        const shareName = shareNameInput.value.trim();
        const sharePath = sharePathInput.value.trim();
        
        if (!shareName) {
            showErrorAlert('Please enter a share name');
            return;
        }
        
        if (!sharePath) {
            showErrorAlert('Please enter a local path');
            return;
        }
        
        // Show loading state
        confirmBtn.disabled = true;
        confirmBtn.innerHTML = '<i class="fas fa-spinner fa-spin fa-sm mr-1"></i> Creating...';
        
        try {
            const response = await fetch('/api/smb/add-share', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    computer: computer,
                    share_name: shareName,
                    share_path: sharePath
                })
            });
            
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.error || 'Failed to create share');
            }
            
            const result = await response.json();
            
            // Close modal
            document.body.removeChild(modal);
            
            // Show success message
            const successMessage = result.message || `Share "${shareName}" created successfully for directory "${directoryName}"`;
            showSuccessAlert(successMessage);
            
            // Refresh the shares list for this computer
            setTimeout(async () => {
                try {
                    const shares = await listSMBShares(computer);
                    // Find the view for this computer and update it
                    const computerView = document.getElementById(`view-${computer}`);
                    if (computerView) {
                        computerView.innerHTML = buildSMBTreeView(shares, computer);
                        attachTreeViewListeners();
                    }
                } catch (error) {
                    console.error('Error refreshing shares after creation:', error);
                }
            }, 500);
            
        } catch (error) {
            console.error('Add share error:', error);
            showErrorAlert(error.message);
            
            // Reset button state
            confirmBtn.disabled = false;
            confirmBtn.innerHTML = '<i class="fas fa-share-alt fa-sm mr-1"></i> Create Share';
        }
    });
    
    // Prevent clicks inside the modal from propagating to document
    modalContent.addEventListener('click', e => {
        e.stopPropagation();
    });
    
    // Add event listeners to close the modal
    const closeButtons = modal.querySelectorAll('.close-modal-btn');
    closeButtons.forEach(button => {
        button.addEventListener('click', e => {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        });
    });
    
    // Close on click outside of modal content
    modal.addEventListener('click', e => {
        if (e.target === modal) {
            e.preventDefault();
            e.stopPropagation();
            document.body.removeChild(modal);
        }
    });
    
    // Close on Escape key
    const handleEscape = (e) => {
        if (e.key === 'Escape') {
            document.body.removeChild(modal);
            document.removeEventListener('keydown', handleEscape);
        }
    };
    document.addEventListener('keydown', handleEscape);
}

async function deleteSMBShare(computer, shareName) {
    // Show confirmation dialog
    if (!confirm(`Are you sure you want to delete the share "${shareName}" on ${computer}?\n\nThis action cannot be undone and may affect other users accessing this share.`)) {
        return;
    }
    
    try {
        showLoadingIndicator();
        
        const response = await fetch('/api/smb/delete-share', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                computer: computer,
                share: shareName
            })
        });
        
        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to delete share');
        }
        
        const result = await response.json();
        
        // Show success message
        const successMessage = result.message || `Share "${shareName}" deleted successfully`;
        showSuccessAlert(successMessage);
        
        // Remove the share from the UI
        const shareElement = document.querySelector(`.smb-tree-item[data-share="${shareName}"][data-computer="${computer}"]`);
        if (shareElement) {
            shareElement.remove();
        }
        
        // If this was the active share, clear the sticky headers
        const shareHeader = document.querySelector('#sticky-header-container span:first-child');
        if (shareHeader && shareHeader.textContent === shareName) {
            updateStickyHeaders();
        }
        
    } catch (error) {
        console.error('Delete share error:', error);
        showErrorAlert(error.message);
    } finally {
        hideLoadingIndicator();
    }
}