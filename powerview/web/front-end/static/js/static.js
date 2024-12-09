document.addEventListener('DOMContentLoaded', function() {
    const toggles = document.querySelectorAll('.dropdown-toggle');

    toggles.forEach(toggle => {
        toggle.addEventListener('click', function() {
            const content = this.nextElementSibling;
            if (content.style.display === 'none' || content.style.display === '') {
                content.style.display = 'block';
            } else {
                content.style.display = 'none';
            }
        });
    });

    const commandHistoryButton = document.getElementById('toggle-command-history');
    const commandHistoryPanel = document.getElementById('command-history-panel');
    const commandHistoryEntries = document.getElementById('command-history-entries');
    const detailsPanel = document.getElementById('details-panel');

    async function fetchCommandLogs() {
        try {
            const response = await fetch('/api/logs');
            const logsData = await response.json();

            if (!response.ok) {
                console.error('Failed to fetch command logs:', logsData.error || 'Unknown error');
                return;
            }

            // Clear existing entries
            commandHistoryEntries.innerHTML = '';

            // Sort logs by timestamp
            logsData.logs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

            // Append new log entries
            logsData.logs.forEach(log => {
                const entryDiv = createLogEntry(log);
                commandHistoryEntries.appendChild(entryDiv);
            });
        } catch (error) {
            console.error('Error fetching command logs:', error);
        }
    }

    async function fetchSingleCommandLogs() {
        try {
            const response = await fetch('/api/logs?limit=1');
            const logsData = await response.json();

            if (!response.ok) {
                console.error('Failed to fetch single command log:', logsData.error || 'Unknown error');
                return;
            }

            // Check if the log already exists to avoid redundancy
            logsData.logs.forEach(log => {
                const existingEntries = Array.from(commandHistoryEntries.children);
                const logExists = existingEntries.some(entry => {
                    const timestamp = entry.querySelector('span.text-sm.text-gray-500').textContent;
                    const debugMessage = entry.querySelector('code').textContent;
                    return timestamp === log.timestamp && debugMessage === log.debug_message;
                });

                if (!logExists) {
                    const entryDiv = createLogEntry(log);
                    commandHistoryEntries.insertBefore(entryDiv, commandHistoryEntries.firstChild);
                }
            });
        } catch (error) {
            console.error('Error fetching single command log:', error);
        }
    }

    function createLogEntry(log) {
        const entryDiv = document.createElement('div');
        entryDiv.className = 'p-4 hover:bg-gray-50 cursor-pointer group';

        const headerDiv = document.createElement('div');
        headerDiv.className = 'flex items-center justify-between mb-1';

        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'text-sm text-gray-500';
        timestampSpan.textContent = log.timestamp;

        const statusSpan = document.createElement('span');
        statusSpan.className = 'text-sm px-2 py-0.5 rounded-full';

        switch (log.log_type) {
            case 'INFO':
                statusSpan.classList.add('bg-blue-100', 'text-blue-800');
                break;
            case 'WARNING':
                statusSpan.classList.add('bg-yellow-100', 'text-yellow-800');
                break;
            case 'SUCCESS':
                statusSpan.classList.add('bg-green-100', 'text-green-800');
                break;
            case 'ERROR':
                statusSpan.classList.add('bg-red-100', 'text-red-800');
                break;
            default:
                statusSpan.classList.add('bg-gray-100', 'text-gray-800');
        }

        statusSpan.textContent = log.log_type;

        headerDiv.appendChild(timestampSpan);
        headerDiv.appendChild(statusSpan);

        const commandDiv = document.createElement('div');
        commandDiv.className = 'flex items-center gap-2';

        const commandCode = document.createElement('code');
        commandCode.className = 'text-sm font-mono text-gray-700 flex-1';
        commandCode.textContent = log.debug_message;

        const arrowIcon = document.createElement('svg');
        arrowIcon.className = 'w-4 h-4 text-blue-500 opacity-0 group-hover:opacity-100 transition-opacity';
        arrowIcon.setAttribute('fill', 'none');
        arrowIcon.setAttribute('stroke', 'currentColor');
        arrowIcon.setAttribute('viewBox', '0 0 24 24');
        arrowIcon.setAttribute('xmlns', 'http://www.w3.org/2000/svg');
        arrowIcon.innerHTML = '<path d="M9 5l7 7-7 7"></path>';

        commandDiv.appendChild(commandCode);
        commandDiv.appendChild(arrowIcon);

        entryDiv.appendChild(headerDiv);
        entryDiv.appendChild(commandDiv);

        return entryDiv;
    }

    commandHistoryButton.addEventListener('click', function() {
        fetchCommandLogs();
        if (commandHistoryPanel.classList.contains('hidden')) {
            commandHistoryPanel.classList.remove('hidden');
            detailsPanel.classList.add('hidden');
        } else {
            commandHistoryPanel.classList.add('hidden');
        }
    });

    const closeCommandHistoryButton = document.getElementById('close-command-history-panel');
    if (closeCommandHistoryButton) {
        closeCommandHistoryButton.addEventListener('click', () => {
            const commandHistoryPanel = document.getElementById('command-history-panel');
            if (commandHistoryPanel) {
                commandHistoryPanel.classList.add('hidden');
            }
        });
    }

    // Run fetchSingleCommandLogs in the background
    setInterval(fetchSingleCommandLogs, 10000); // Fetch every 10 seconds
});

async function handleHttpError(response) {
    if (!response.ok) {
        const alertBox = document.querySelector('div[role="alert"]');
        const alertMessage = document.getElementById('alert-message');

        if (response.status === 400) {
            const errorResponse = await response.json();
            if (errorResponse.error) {
                alertMessage.textContent = errorResponse.error;
            } else {
                alertMessage.textContent = 'An unknown error occurred.';
            }
        } else {
            alertMessage.textContent = `HTTP error! status: ${response.status}`;
        }

        // Show the alert box
        alertBox.hidden = false;

        // Optionally, add a timeout to hide the alert after a few seconds
        setTimeout(() => {
            alertBox.hidden = true;
        }, 5000);
    }
}