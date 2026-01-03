import { initStorageKey, loadGraphData } from './network.js';
import { loadFromStorage, clearData, setStorageKey, getStorageKey } from './state.js';
import { initializeCytoscape, clearGraph, centerGraph, cy } from './viz.js';
import { showLoading, updateStatus, showOpsecModal, initSearchListeners, updateStats, initResizablePanel, initContextMenu } from './ui.js';

async function initializeGraph() {
    console.log("Graph Page: Initializing script...");

    // 1. SELECT ELEMENTS
    const cyContainer = document.getElementById('cy');
    const refreshBtn = document.getElementById('clear-btn');
    const fetchDataBtn = document.getElementById('fetch-data-btn');
    const clearGraphBtn = document.getElementById('clear-graph-btn');
    const centerGraphBtn = document.getElementById('center-graph-btn');
    const confirmLoadBtn = document.getElementById('confirm-load-btn');
    const cancelLoadBtn = document.getElementById('cancel-load-btn');
    const closePanelBtn = document.getElementById('close-panel-btn');
    const detailsPanel = document.getElementById('details-panel');

    // 2. ATTACH LISTENERS
    if (fetchDataBtn) {
        fetchDataBtn.addEventListener('click', () => {
            showOpsecModal(true);
        });
    }

    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            if (confirm("Are you sure you want to clear all graph data for this session? This will require re-fetching data.")) {
                const key = getStorageKey();
                if (key) localStorage.removeItem(key);
                location.reload();
            }
        });
    }

    if (confirmLoadBtn) {
        confirmLoadBtn.addEventListener('click', () => {
            showOpsecModal(false);
            loadGraphData();
        });
    }

    if (cancelLoadBtn) {
        cancelLoadBtn.addEventListener('click', () => {
            showOpsecModal(false);
            updateStatus("Data fetch cancelled.");
        });
    }

    if (closePanelBtn && detailsPanel) {
        closePanelBtn.addEventListener('click', () => {
            detailsPanel.classList.add('translate-x-full');
        });
    }

    if (clearGraphBtn) {
        clearGraphBtn.addEventListener('click', () => {
            clearGraph();
        });
    }

    if (centerGraphBtn) {
        centerGraphBtn.addEventListener('click', () => {
            centerGraph();
        });
    }

    initSearchListeners();
    initResizablePanel();
    initContextMenu();

    // 3. INITIALIZE
    initializeCytoscape(cyContainer);

    async function start() {
        try {
            showLoading(true);
            updateStatus("Initializing connection...");

            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 5000);

            await initStorageKey(controller.signal);
            clearTimeout(timeoutId);

            if (loadFromStorage()) {
                console.log("Graph loaded from cache. Ready.");
                updateStats();
                showLoading(false);
                updateStatus("Ready (Cached).");
            } else {
                console.log("No cache found. Showing OPSEC warning.");
                showLoading(false);
                showOpsecModal(true);
            }
        } catch (e) {
            console.error("Start failed:", e);
            showLoading(false);
            showOpsecModal(true);
        }
    }

    start();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeGraph);
} else {
    initializeGraph();
}
