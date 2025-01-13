document.addEventListener('DOMContentLoaded', () => {
    const connectButton = document.getElementById('smb-connect-button');
    const connectAsButton = document.getElementById('smb-connect-as-button');
    const connectAsForm = document.getElementById('connect-as-form');
    const statusDiv = document.getElementById('smb-connection-status');
    const treeDiv = document.getElementById('smb-tree');
    const computerInput = document.getElementById('smb-computer');

    // Toggle connect-as form
    connectAsButton.onclick = () => {
        connectAsForm.classList.toggle('hidden');
    };

    connectButton.onclick = async () => {
        try {
            showLoadingIndicator();
            const computer = computerInput.value;
            if (!computer) {
                throw new Error('Please enter a computer name or IP');
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
            
            // Update status
            statusDiv.innerHTML = `
                <div class="flex items-center gap-2 text-green-600 dark:text-green-500">
                    <i class="fas fa-check-circle"></i>
                    <span>Connected to ${computer}</span>
                </div>
            `;

            // Build tree view
            treeDiv.innerHTML = buildSMBTreeView(shares);
            attachTreeViewListeners(computer);

        } catch (error) {
            statusDiv.innerHTML = `
                <div class="flex items-center gap-2 text-red-600 dark:text-red-500">
                    <i class="fas fa-exclamation-circle"></i>
                    <span>${error.message}</span>
                </div>
            `;
        } finally {
            hideLoadingIndicator();
        }
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


function buildSMBTreeView(shares) {
    let html = '<ul class="space-y-1">';
    shares.forEach(share => {
        const shareName = share.attributes.Name;
        html += `
            <li class="smb-tree-item" data-share="${shareName}">
                <div class="flex items-center justify-between hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer">
                    <div class="flex items-center gap-2">
                        <i class="fas fa-folder text-yellow-500"></i>
                        <span class="text-neutral-900 dark:text-white">${shareName}</span>
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">${share.attributes.Remark}</span>
                    </div>
                </div>
                <ul class="ml-6 space-y-1 hidden"></ul>
            </li>
        `;
    });
    html += '</ul>';
    return html;
}

function attachTreeViewListeners(computer) {
    document.querySelectorAll('.smb-tree-item').forEach(item => {
        const shareDiv = item.querySelector('div');
        const subList = item.querySelector('ul');
        let isLoaded = false;

        shareDiv.onclick = async () => {
            const share = item.dataset.share;
            
            if (!isLoaded) {
                try {
                    showLoadingIndicator();
                    const files = await listSMBPath(computer, share);
                    subList.innerHTML = buildFileList(files, share);
                    isLoaded = true;
                    subList.classList.remove('hidden');
                    attachFileListeners(computer, share);
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    hideLoadingIndicator();
                }
            } else {
                subList.classList.toggle('hidden');
            }
        };
    });
}

function attachFileListeners(computer, share) {
    document.querySelectorAll('.file-item').forEach(item => {
        const isDirectory = item.getAttribute('data-is-dir') === '16' || item.getAttribute('data-is-dir') === '48';
        
        if (isDirectory) {
            const fileDiv = item.querySelector('div');
            const subList = item.querySelector('ul');
            
            if (!fileDiv || !subList) return; // Skip if elements not found

            fileDiv.onclick = async () => {
                // If the folder is already loaded and just hidden, simply toggle it
                if (subList.children.length > 0) {
                    subList.classList.toggle('hidden');
                    return;
                }

                // Only make API call if folder hasn't been loaded yet
                try {
                    showLoadingIndicator();
                    const currentPath = item.dataset.path;
                    const cleanPath = currentPath.replace(/^\//, '').replace(/\//g, '\\');
                    const files = await listSMBPath(computer, share, cleanPath);
                    subList.innerHTML = buildFileList(files, share, currentPath);
                    subList.classList.remove('hidden');
                    // Recursively attach listeners to new files
                    attachFileListeners(computer, share);
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    hideLoadingIndicator();
                }
            };
        }
    });
}

// Keep track of downloads
const downloads = new Map();

// Update the downloadSMBFile function to include progress tracking
async function downloadSMBFile(computer, share, path) {
    try {
        const filename = path.split('\\').pop();
        
        // Create download entry
        const downloadId = Date.now().toString();
        const downloadEntry = createDownloadEntry(downloadId, filename);
        document.getElementById('downloads-list').prepend(downloadEntry);
        
        // Show downloads panel
        const downloadsPanel = document.getElementById('downloads-panel');
        downloadsPanel.classList.remove('hidden', 'translate-x-full');

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

        // Get total size from headers
        const totalSize = parseInt(response.headers.get('Content-Length') || '0');
        const reader = response.body.getReader();
        let receivedSize = 0;

        // Create a new ReadableStream to process the download chunks
        const stream = new ReadableStream({
            async start(controller) {
                while (true) {
                    const {done, value} = await reader.read();
                    if (done) break;
                    
                    receivedSize += value.length;
                    updateDownloadProgress(downloadId, receivedSize, totalSize);
                    controller.enqueue(value);
                }
                controller.close();
            }
        });

        // Create download link
        const blob = await new Response(stream).blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);

        // Mark download as complete
        completeDownload(downloadId, filename);

    } catch (error) {
        showErrorAlert(error.message);
        failDownload(downloadId, error.message);
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

// Update the buildFileList function to add download functionality for files
function buildFileList(files, share, currentPath = '') {
    let html = '<ul class="space-y-1">';
    files.forEach(file => {
        const isDirectory = file.is_directory;
        const icon = isDirectory ? 'fa-folder' : 'fa-file';
        const iconColor = isDirectory ? 'text-yellow-500' : 'text-neutral-400';
        const computerInput = document.getElementById('smb-computer');
        
        html += `
            <li class="file-item" data-path="${currentPath}/${file.name}" data-is-dir="${isDirectory ? '16' : '0'}">
                <div class="flex items-center justify-between hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer">
                    <div class="flex items-center gap-2">
                        <i class="fas ${icon} ${iconColor}"></i>
                        <span class="text-neutral-900 dark:text-white">${file.name}</span>
                        <span class="text-xs text-neutral-500 dark:text-neutral-400">${formatFileSize(file.size)}</span>
                    </div>
                    <div class="flex items-center gap-2">
                        ${isDirectory ? `
                            <button onclick="event.stopPropagation(); uploadSMBFile('${computerInput.value}', '${share}', '${currentPath}/${file.name}')"
                                class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-1">
                                <i class="fas fa-upload"></i>
                            </button>
                        ` : `
                            <button onclick="event.stopPropagation(); viewSMBFile('${computerInput.value}', '${share}', '${currentPath}/${file.name}')" 
                                class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-1">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button onclick="event.stopPropagation(); downloadSMBFile('${computerInput.value}', '${share}', '${currentPath}/${file.name}')" 
                                class="text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300 p-1">
                                <i class="fas fa-download"></i>
                            </button>
                        `}
                    </div>
                </div>
                ${isDirectory ? '<ul class="ml-6 space-y-1 hidden"></ul>' : ''}
            </li>
        `;
    });
    html += '</ul>';
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
            parentList.innerHTML = buildFileList(files, share, currentPath);
            attachFileListeners(computer, share);
            
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

// Add the file viewer function
async function viewSMBFile(computer, share, path) {
    try {
        showLoadingIndicator();
        const response = await fetch('/api/smb/cat', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ computer, share, path })
        });

        if (!response.ok) {
            const error = await response.json();
            throw new Error(error.error || 'Failed to read file');
        }

        const content = await response.text();
        
        // Get filename for the title
        const filename = path.split('\\').pop();

        // Update the file viewer panel
        const fileViewer = document.getElementById('file-viewer-panel');
        const fileViewerTitle = document.getElementById('file-viewer-title');
        const fileViewerContent = document.getElementById('file-viewer-content');
        
        fileViewerTitle.textContent = filename;
        fileViewerContent.textContent = content;
        
        // Show the panel
        fileViewer.classList.remove('hidden');
        setTimeout(() => {
            fileViewer.classList.remove('translate-x-full');
        }, 0);

    } catch (error) {
        showErrorAlert(error.message);
        console.error('View error:', error);
    } finally {
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