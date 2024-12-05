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

    commandHistoryButton.addEventListener('click', function() {
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

    const resizers = document.querySelectorAll('.resizer');
    let currentResizer;

    resizers.forEach(resizer => {
        resizer.addEventListener('mousedown', (e) => {
            currentResizer = resizer;
            document.addEventListener('mousemove', resize);
            document.addEventListener('mouseup', stopResize);
        });
    });

    function resize(e) {
        const prevPanel = currentResizer.previousElementSibling;
        const nextPanel = currentResizer.nextElementSibling;

        const prevPanelWidth = e.clientX - prevPanel.getBoundingClientRect().left;
        const nextPanelWidth = nextPanel.getBoundingClientRect().right - e.clientX;

        if (prevPanelWidth > 100 && nextPanelWidth > 100) { // Minimum width of 100px
            prevPanel.style.width = prevPanelWidth + 'px';
            nextPanel.style.width = nextPanelWidth + 'px';
        }
    }

    function stopResize() {
        document.removeEventListener('mousemove', resize);
        document.removeEventListener('mouseup', stopResize);
    }
});