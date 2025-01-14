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
    let html = '<ul>';
    shares.forEach(share => {
        const shareName = share.attributes.Name;
        html += `
            <li class="smb-tree-item" data-share="${shareName}">
                <div class="grid grid-cols-12 gap-4 items-center hover:bg-neutral-100 dark:hover:bg-neutral-800 rounded cursor-pointer py-0.5 px-2">
                    <div class="col-span-6">
                        <div class="flex items-center gap-2 min-w-0">
                            <i class="fas fa-folder text-yellow-500 flex-shrink-0"></i>
                            <span class="text-neutral-900 dark:text-white truncate">${shareName}</span>
                             <span class="text-xs text-neutral-500 dark:text-neutral-400">${share.attributes.Remark}</span>
                            <span class="spinner-container flex-shrink-0"></span>
                        </div>
                    </div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">--</div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400 text-right">--</div>
                </div>
                <ul class="hidden"></ul>
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
        const spinnerContainer = item.querySelector('.spinner-container');
        let isLoaded = false;

        shareDiv.onclick = async () => {
            const share = item.dataset.share;
            
            if (!isLoaded) {
                try {
                    showInlineSpinner(spinnerContainer);
                    const files = await listSMBPath(computer, share);
                    subList.innerHTML = buildFileList(files, share);
                    isLoaded = true;
                    subList.classList.remove('hidden');
                    attachFileListeners(computer, share);
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

function attachFileListeners(computer, share) {
    document.querySelectorAll('.file-item').forEach(item => {
        const isDirectory = item.getAttribute('data-is-dir') === '16' || item.getAttribute('data-is-dir') === '48';
        const spinnerContainer = item.querySelector('.spinner-container');
        
        if (isDirectory) {
            const fileDiv = item.querySelector('div');
            const subList = item.querySelector('ul');
            const uploadBtn = item.querySelector('.upload-btn');
            
            if (!fileDiv || !subList) return;

            fileDiv.onclick = async () => {
                if (subList.children.length > 0) {
                    subList.classList.toggle('hidden');
                    return;
                }

                try {
                    showInlineSpinner(spinnerContainer);
                    const currentPath = item.dataset.path;
                    const cleanPath = currentPath.replace(/^\//, '').replace(/\//g, '\\');
                    const files = await listSMBPath(computer, share, cleanPath);
                    subList.innerHTML = buildFileList(files, share, currentPath);
                    subList.classList.remove('hidden');
                    attachFileListeners(computer, share);
                } catch (error) {
                    console.error('Error loading files:', error);
                } finally {
                    removeInlineSpinner(spinnerContainer);
                }
            };

            // Handle upload button
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
        } else {
            // Handle view button
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

            // Handle download button
            const downloadBtn = item.querySelector('.download-btn');
            if (downloadBtn) {
                downloadBtn.onclick = async (e) => {
                    e.stopPropagation();
                    showInlineSpinner(spinnerContainer);
                    try {
                        await downloadSMBFile(computer, share, item.dataset.path);
                    } finally {
                        removeInlineSpinner(spinnerContainer);
                    }
                };
            }
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

function getFileIcon(fileName, isDirectory) {
    if (isDirectory) {
        return {
            icon: icons.folderIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    const fileExt = fileName.toLowerCase().substring(fileName.lastIndexOf('.'));
    
    // Check for Excel file extensions
    const excelExtensions = ['.xlsx', '.xls', '.xlsm', '.xlsb', '.xltx', '.xltm', '.xlt', '.csv'];
    if (excelExtensions.includes(fileExt)) {
        return {
            icon: icons.xlsxIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for Word file extensions
    const wordExtensions = ['.docx', '.doc', '.docm', '.dotx', '.dotm', '.dot'];
    if (wordExtensions.includes(fileExt)) {
        return {
            icon: icons.docxIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for Text file extensions
    const textExtensions = ['.txt', '.log', '.ini', '.cfg', '.conf', '.text', '.md'];
    if (textExtensions.includes(fileExt)) {
        return {
            icon: icons.txtIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for DLL file extensions
    const dllExtensions = ['.dll', '.sys', '.drv', '.ocx'];
    if (dllExtensions.includes(fileExt)) {
        return {
            icon: icons.dllIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for Outlook file extensions
    const outlookExtensions = ['.pst', '.ost', '.msg', '.eml', '.nst', '.oft'];
    if (outlookExtensions.includes(fileExt)) {
        return {
            icon: icons.outlookIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for PowerPoint file extensions
    const powerpointExtensions = ['.ppt', '.pptx', '.pptm', '.potx', '.potm', '.ppsx', '.ppsm'];
    if (powerpointExtensions.includes(fileExt)) {
        return {
            icon: icons.powerpointIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for Compressed file extensions
    const compressedExtensions = ['.zip', '.rar', '.7z', '.gz', '.tar', '.bz2', '.xz', '.cab'];
    if (compressedExtensions.includes(fileExt)) {
        return {
            icon: icons.zipIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    // Check for PDF file extension
    if (fileExt === '.pdf') {
        return {
            icon: icons.pdfIcon,
            iconClass: '',
            isCustomSvg: true
        };
    }

    return {
        icon: 'fa-file',
        iconClass: 'text-neutral-400',
        isCustomSvg: false
    };
}

function buildFileList(files, share, currentPath = '') {
    let html = '';
    files.forEach(file => {
        const isDirectory = file.is_directory;
        const fileIcon = getFileIcon(file.name, isDirectory);
        
        // Convert Windows FILETIME to JavaScript Date
        const windowsTimestamp = BigInt(file.modified);
        const unixTimestamp = Number((windowsTimestamp - BigInt(116444736000000000)) / BigInt(10000));
        const modifiedDate = new Date(unixTimestamp).toLocaleString();
        
        // Calculate indentation level based on path depth, removing empty segments
        const pathSegments = currentPath.split('/').filter(segment => segment.length > 0);
        const indentLevel = pathSegments.length + 1; // Add 1 to indent share contents
        const marginLeft = indentLevel * 1.5; // 1.5rem per level
        
        html += `
            <li class="file-item" data-path="${currentPath}/${file.name}" data-is-dir="${file.is_directory ? '16' : '0'}">
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
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">
                        ${formatFileSize(file.size)}
                    </div>
                    <div class="col-span-2 text-sm text-neutral-500 dark:text-neutral-400">
                        ${modifiedDate}
                    </div>
                    <div class="col-span-2 flex items-center gap-2 justify-end">
                        ${isDirectory ? `
                            <button class="upload-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="Upload">
                                <i class="fas fa-upload"></i>
                            </button>
                        ` :  `
                            <button class="view-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="View">
                                <i class="fas fa-eye"></i>
                            </button>
                            <button class="download-btn text-neutral-500 hover:text-neutral-700 dark:hover:text-neutral-300" title="Download">
                                <i class="fas fa-download"></i>
                            </button>
                        `}
                    </div>
                </div>
                ${isDirectory ? `<ul class="hidden"></ul>` : ''}
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