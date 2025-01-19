let activeComputer = null;

document.addEventListener('DOMContentLoaded', () => {
    const connectButton = document.getElementById('smb-connect-button');
    const connectAsButton = document.getElementById('smb-connect-as-button');
    const connectAsForm = document.getElementById('connect-as-form');
    const pcViews = document.getElementById('pc-views');
    const pcTabs = document.getElementById('pc-tabs');
    const computerInput = document.getElementById('smb-computer');
    
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
            const password = document.getElementById('smb-password').value;

            // Prepare connection data
            const connectionData = {
                computer: computer
            };

            if (!connectAsForm.classList.contains('hidden') && username && password) {
                connectionData.username = username;
                connectionData.password = password;
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
        const tab = document.createElement('div');
        tab.dataset.computer = computer;
        tab.id = `tab-${computer}`;
        tab.className = 'flex items-center gap-2 px-4 py-2 text-sm font-medium text-neutral-500 dark:text-neutral-400 hover:text-neutral-900 dark:hover:text-white cursor-pointer border-b-2 border-transparent';
        tab.innerHTML = `
            <i class="fas fa-computer"></i>
            <span>${computer}</span>
            <button class="close-tab ml-2 text-neutral-400 hover:text-red-500">
                <i class="fas fa-times"></i>
            </button>
        `;
        
        tab.onclick = () => switchToPC(computer);
        
        // Handle close button
        const closeBtn = tab.querySelector('.close-tab');
        closeBtn.onclick = (e) => {
            e.stopPropagation();
            disconnectPC(computer);
        };
        
        pcTabs.appendChild(tab);
    }

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

        // Update tabs
        document.querySelectorAll('#pc-tabs > div').forEach(tab => {
            tab.classList.remove('text-neutral-900', 'dark:text-white', 'border-blue-500', 'dark:border-yellow-500');
            if (tab.id === `tab-${computer}`) {
                tab.classList.add('text-neutral-900', 'dark:text-white', 'border-blue-500', 'dark:border-yellow-500');
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

    function disconnectPC(computer) {
        // Remove tab
        const tab = document.getElementById(`tab-${computer}`);
        if (tab) tab.remove();

        // Remove view
        const view = document.getElementById(`view-${computer}`);
        if (view) view.remove();

        // Remove from tracking
        connectedPCs.delete(computer);

        // If we're disconnecting the active computer, switch to another one
        if (activeComputer === computer) {
            activeComputer = null;
            const remainingPC = connectedPCs.values().next().value;
            if (remainingPC) {
                switchToPC(remainingPC);
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
    });

    // Prevent panel closing when clicking inside the panels
    const panels = document.querySelectorAll('#file-viewer-panel, #downloads-panel');
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
            
            // Reconnect to SMB
            await connectToSMB({computer});
            
            showSuccessAlert(`Refreshed connection to ${computer}`);
        } catch (error) {
            console.error('Refresh error:', error);
            showErrorAlert(error.message);
        } finally {
            // Remove spinning class and re-enable button
            const refreshIcon = refreshButton.querySelector('.fa-sync-alt');
            refreshIcon.classList.remove('animate-spin');
            refreshButton.disabled = false;
            hideLoadingIndicator();
        }
    };
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

    return response.json();
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
            <li class="smb-tree-item" data-share="${shareName}" data-computer="${computer}">
                <div class="grid grid-cols-12 gap-4 items-center hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer py-0.5 px-2">
                    <div class="col-span-6">
                        <div class="flex items-center gap-2 min-w-0">
                            <span class="text-yellow-500 flex-shrink-0">${icons.smbshareIcon}</span>
                            <span class="text-neutral-900 dark:text-white truncate">${shareName}</span>
                            <span class="text-xs text-neutral-500 dark:text-neutral-400">${share.attributes.Remark}</span>
                            <span class="spinner-container flex-shrink-0"></span>
                        </div>
                    </div>
                    <div class="col-span-1 text-sm text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-1 text-sm text-neutral-500 dark:text-neutral-400 text-right">--</div>
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
            
            if (!isLoaded) {
                try {
                    showInlineSpinner(spinnerContainer);
                    const files = await listSMBPath(computer, share);
                    subList.innerHTML = buildFileList(files, share, '', computer);
                    isLoaded = true;
                    subList.classList.remove('hidden');
                    attachFileListeners();
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            } else {
                subList.classList.toggle('hidden');
            }
        };
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
        
        // Add loading state tracking
        let isLoading = false;

        // Handle double click for files
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

                if (subList.children.length > 0) {
                    subList.classList.toggle('hidden');
                    return;
                }

                try {
                    isLoading = true;
                    showInlineSpinner(spinnerContainer);
                    const currentPath = item.dataset.path;
                    const cleanPath = currentPath.replace(/^\//, '').replace(/\//g, '\\');
                    const files = await listSMBPath(computer, share, cleanPath);
                    subList.innerHTML = buildFileList(files, share, currentPath, computer);
                    subList.classList.remove('hidden');
                    attachFileListeners();
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
                        await uploadSMBFile(computer, share, item.dataset.path);
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
                        await createSMBDirectory(computer, share, path);
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
                        await viewSMBFile(computer, share, item.dataset.path);
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
                        const dirName = path.split('/').pop();
                        await downloadSMBDirectory(computer, share, path, dirName);
                    } else {
                        await downloadSMBFile(computer, share, path);
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
                    await deleteSMBFileOrDirectory(computer, share, path, isDirectory);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            };
        }
    });
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
        const filename = path.split('\\').pop();
        const downloadId = Date.now();

        // Only create download entry if not raw download
        let downloadEntry;
        if (!raw) {
            // Create download entry with computer and share info
            const downloadsList = document.getElementById('downloads-list');
            downloadEntry = document.createElement('div');
            downloadEntry.id = `download-${downloadId}`;
            downloadEntry.className = 'bg-white dark:bg-neutral-800 rounded-lg border border-neutral-200 dark:border-neutral-700 p-3';
            downloadEntry.innerHTML = `
                <div class="flex items-center justify-between gap-2">
                    <div class="flex-1 min-w-0">
                        <div class="flex items-center gap-2">
                            <i class="fas fa-file text-blue-500 dark:text-yellow-500"></i>
                            <div class="truncate">
                                <div class="text-sm font-medium text-neutral-900 dark:text-white truncate">
                                    ${filename}
                                </div>
                                <div class="text-xs text-neutral-500 dark:text-neutral-400">
                                    from \\\\${computer}\\${share}
                                </div>
                            </div>
                        </div>
                        <div class="mt-1 flex items-center gap-2">
                            <div class="flex-1 bg-neutral-200 dark:bg-neutral-700 rounded-full h-1.5">
                                <div class="download-progress bg-blue-500 dark:bg-yellow-500 h-1.5 rounded-full" style="width: 0%"></div>
                            </div>
                            <span class="text-xs text-neutral-500 dark:text-neutral-400 download-status">Starting...</span>
                        </div>
                    </div>
                    <button onclick="clearDownload(${downloadId})" class="text-neutral-400 hover:text-neutral-500 dark:hover:text-neutral-300">
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

        // Start download
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
            document.body.removeChild(a);

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
    entry.className = 'bg-neutral-50 dark:bg-neutral-800 rounded-lg p-2 mb-2';

    const filenameSpan = document.createElement('span');
    filenameSpan.className = 'text-sm text-neutral-900 dark:text-white';
    filenameSpan.textContent = filename;

    entry.innerHTML = `
        <div class="flex items-center justify-between">
            ${filenameSpan.outerHTML}
            <div class="flex items-center gap-2">
                <button onclick="clearDownload('${id}')"
                    class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-1">
                    <i class="fas fa-trash"></i>
                </button>
            </div>
        </div>
        <div class="h-2 bg-neutral-200 dark:bg-neutral-700 rounded-full mt-2">
            <div id="download-progress-${id}" 
                class="bg-blue-500 dark:bg-yellow-500 h-2 rounded-full transition-all duration-300" 
                style="width: 0%">
            </div>
        </div>
        <span class="text-xs text-neutral-500 dark:text-neutral-400" id="download-status-${id}">0%</span>
    `;

    return entry;
}

function updateDownloadProgress(id, receivedSize, totalSize) {
    const progressBar = document.getElementById(`download-${id}`).querySelector('.bg-neutral-200');
    const progressPercentage = document.getElementById(`download-${id}`).querySelector('.text-xs');

    const percentage = Math.round((receivedSize / totalSize) * 100);
    progressBar.style.width = `${percentage}%`;
    progressPercentage.textContent = `${percentage}%`;
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
        
        // Convert Windows FILETIME to JavaScript Date
        const windowsTimestamp = BigInt(file.modified);
        const unixTimestamp = Number((windowsTimestamp - BigInt(116444736000000000)) / BigInt(10000));
        const modifiedDate = new Date(unixTimestamp).toLocaleString();

        // Convert Windows FILETIME to JavaScript Date for created date
        const windowsCreatedTimestamp = BigInt(file.created);
        const unixCreatedTimestamp = Number((windowsCreatedTimestamp - BigInt(116444736000000000)) / BigInt(10000));
        const createdDate = new Date(unixCreatedTimestamp).toLocaleString();
        
        // Calculate indentation level based on path depth
        const pathSegments = currentPath.split('/').filter(segment => segment.length > 0);
        const indentLevel = pathSegments.length + 1;
        const marginLeft = indentLevel * 1.5;
        
        html += `
            <li class="file-item" 
                data-path="${currentPath}/${file.name}" 
                data-is-dir="${file.is_directory ? '16' : '0'}"
                data-computer="${computer}"
                data-share="${share}"
                title="${file.name}">
                <div class="grid grid-cols-12 gap-4 items-center hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer py-0.5 px-2">
                    <div class="col-span-6">
                        <div class="flex items-center gap-2 min-w-0" style="margin-left: ${marginLeft}rem;">
                            ${fileIcon.isCustomSvg 
                                ? `<span class="w-4 h-4 flex-shrink-0">${fileIcon.icon}</span>`
                                : `<i class="fas ${fileIcon.icon} ${fileIcon.iconClass} flex-shrink-0"></i>`
                            }
                            <span class="text-neutral-900 dark:text-white truncate">${file.name}</span>
                            <span class="spinner-container flex-shrink-0"></span>
                        </div>
                    </div>
                    <div class="col-span-1 text-sm text-neutral-500 dark:text-neutral-400">
                        ${formatFileSize(file.size)}
                    </div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">
                        ${createdDate}
                    </div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">
                        ${modifiedDate}
                    </div>
                    <div class="col-span-1 flex items-center gap-2 justify-end">
                        ${isDirectory ? `
                            <button class="upload-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="Upload">
                                <i class="fas fa-upload"></i>
                            </button>
                            <button class="new-folder-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="New Folder">
                                <i class="fas fa-folder-plus"></i>
                            </button>
                            <button class="download-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="Download Directory">
                                <i class="fas fa-download"></i>
                            </button>
                        ` : `
                            <button class="view-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="View">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="download-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="Download">
                                <i class="fas fa-download"></i>
                            </button>
                        `}
                        <button class="delete-btn text-neutral-500 hover:text-red-600 dark:hover:text-red-400" title="Delete">
                            <i class="fas fa-trash"></i>
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

            // Refresh the current directory listing
            const files = await listSMBPath(computer, share, currentPath);
            const parentList = document.querySelector(`[data-path="${currentPath}"]`).parentElement;
            parentList.innerHTML = buildFileList(files, share, currentPath, computer);
            attachFileListeners();
            
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
        const filename = path.split('\\').pop();
        const isImage = isImageFile(filename);
        const isPdf = isPdfFile(filename);
        
        // Show loading spinner
        spinner.classList.remove('hidden');
        
        // Reset viewers
        document.getElementById('image-viewer').classList.add('hidden');
        document.getElementById('text-viewer').classList.add('hidden');
        document.getElementById('pdf-viewer').classList.add('hidden');

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
        
        // List all files in the directory recursively
        const files = await listSMBDirectoryContents(computer, share, path);
        const totalFiles = files.length;
        let completedFiles = 0;
        
        // Update status to show file count
        const statusElement = document.getElementById(`download-status-${downloadId}`);
        statusElement.textContent = `0/${totalFiles} files`;
        
        // Create a JSZip instance
        const zip = new JSZip();

        // Download each file
        for (const file of files) {
            try {
                const blob = await downloadSMBFile(computer, share, file.path, true);
                if (blob) {
                    zip.file(file.name, blob);
                }
                completedFiles++;
                
                // Update progress
                const progress = (completedFiles / totalFiles) * 100;
                updateDownloadProgress(downloadId, completedFiles, totalFiles);
                statusElement.textContent = `${completedFiles}/${totalFiles} files`;
            } catch (error) {
                console.error(`Error downloading file ${file.path}:`, error);
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
            if (metadata.percent) {
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