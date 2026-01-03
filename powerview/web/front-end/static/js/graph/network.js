import { graphData, addNode, addEdge, getId, saveToStorage, setStorageKey, clearData } from './state.js';
import { showLoading, updateStatus, showNodeDetails, updateStats } from './ui.js';
import { clearGraph } from './viz.js';

export async function initStorageKey(signal) {
    try {
        const res = await fetch('/api/connectioninfo', { signal });
        if (res.ok) {
            const data = await res.json();
            if (data.username && data.domain) {
                const user = data.username.toLowerCase().replace(/[^a-z0-9]/g, '_');
                const domain = data.domain.toLowerCase().replace(/[^a-z0-9]/g, '_');
                setStorageKey(`powerview_graph_data_${domain}_${user}`);
            }
        }
    } catch (e) {
        console.error("Failed to fetch connection info", e);
    }
}

export async function loadGraphData() {
    showLoading(true);
    updateStatus("Fetching users, groups, and computers...");

    try {
        console.log("Fetching graph data from backend...");
        const [usersRes, groupsRes, computersRes] = await Promise.all([
            fetch('/api/get/domainuser?properties=*'),
            fetch('/api/get/domaingroup?properties=*'),
            fetch('/api/get/domaincomputer?properties=*')
        ]);

        const users = await usersRes.json();
        const groups = await groupsRes.json();
        const computers = await computersRes.json();

        console.log(`Fetched: ${users.length} users, ${groups.length} groups, ${computers.length} computers`);

        if (users.error || groups.error || computers.error) {
            throw new Error(users.error || groups.error || computers.error);
        }

        updateStatus("Processing data...");

        // Clear old data
        clearData();

        (Array.isArray(groups) ? groups : []).forEach(g => addNode(g, 'group'));
        (Array.isArray(users) ? users : []).forEach(u => addNode(u, 'user'));
        (Array.isArray(computers) ? computers : []).forEach(c => addNode(c, 'computer'));

        const processMemberOf = (items) => {
            (items || []).forEach(item => {
                const attrs = item.attributes;
                const sourceId = getId(attrs.distinguishedName);
                if (!sourceId) return;

                let memberOf = attrs.memberOf;
                if (!memberOf) return;
                if (!Array.isArray(memberOf)) memberOf = [memberOf];

                memberOf.forEach(groupDn => {
                    const targetId = getId(groupDn);
                    addEdge(sourceId, targetId, 'memberOf');
                });
            });
        };

        processMemberOf(users);
        processMemberOf(groups);
        processMemberOf(computers);

        // Save to Cache
        saveToStorage();
        updateStats();

        updateStatus("Ready.");
        showLoading(false);

        // Do NOT render by default
        if (typeof clearGraph === 'function') {
            clearGraph();
        }

    } catch (error) {
        console.error('Failed to load graph data:', error);
        updateStatus(`Error: ${error.message}`, true);
    }
}

export async function fetchFullDACL(nodeId) {
    const container = document.getElementById(`dacl-section-${nodeId.replace(/[^a-z0-9]/gi, '_')}`);
    if (!container) return;

    const placeholder = container.querySelector('.dacl-placeholder');
    const spinner = container.querySelector('.dacl-spinner');
    if (spinner) spinner.classList.remove('hidden');

    try {
        const node = graphData.nodeMap.get(nodeId);
        if (!node || !node.data.raw || !node.data.raw.distinguishedName) {
            if (placeholder) placeholder.textContent = "Unavailable (No DN)";
            return;
        }

        const res = await fetch(`/api/get/domainobjectacl?identity=${encodeURIComponent(node.data.raw.distinguishedName)}`);
        const json = await res.json();

        if (json.error) throw new Error(json.error);
        if (!Array.isArray(json) || json.length === 0) {
            if (placeholder) placeholder.textContent = "No ACL entries found.";
            return;
        }

        const attributes = json[0].attributes;
        const aces = Array.isArray(attributes) ? attributes : [attributes];

        let aceHtml = `<div class="mt-2 space-y-2 pr-2">`;
        aces.forEach(ace => {
            const type = ace.ACEType || 'Unknown';
            const mask = ace.AccessMask || 'Unknown';
            const principal = ace.SecurityIdentifier || 'Unknown';
            const isInherited = ace.IsInherited === 'True';

            aceHtml += `
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800/50 rounded border border-neutral-100 dark:border-neutral-700">
                    <div class="flex justify-between items-start mb-1">
                        <span class="font-bold text-[10px] uppercase px-1.5 py-0.5 rounded ${type.includes('ALLOWED') ? 'bg-green-100 text-green-700 dark:bg-green-900/30' : 'bg-red-100 text-red-700 dark:bg-red-900/30'}">
                            ${type}
                        </span>
                        ${isInherited ? '<span class="text-[9px] text-neutral-400">Inherited</span>' : ''}
                    </div>
                    <div class="font-mono text-[10px] text-neutral-800 dark:text-neutral-200 mb-1 break-all">${principal}</div>
                    <div class="text-[10px] text-blue-600 dark:text-blue-400 font-medium">${mask}</div>
                </div>
            `;
        });
        aceHtml += `</div>`;

        if (placeholder) placeholder.outerHTML = aceHtml;
    } catch (e) {
        console.error("DACL Dump Failed:", e);
        if (placeholder) placeholder.textContent = "Failed to fetch DACL.";
    } finally {
        if (spinner) spinner.classList.add('hidden');
    }
}

export async function fetchACLs(nodeId) {
    try {
        const node = graphData.nodeMap.get(nodeId);
        if (!node) return false;

        // Fallback to ID if DN is missing
        const dn = (node.data.raw && node.data.raw.distinguishedName) ? node.data.raw.distinguishedName : node.data.id;
        
        console.log(`Requesting ACLs for DN: ${dn}`);
        const res = await fetch(`/api/get/domainobjectacl?identity=${encodeURIComponent(dn)}`);
        const json = await res.json();

        if (json.error) {
            console.warn("ACL Fetch Error:", json.error);
            return false;
        }
        if (!Array.isArray(json) || json.length === 0) {
            console.log("No ACLs returned.");
            return false;
        }

        let newEdges = false;
        const attributes = json[0].attributes;
        const aces = Array.isArray(attributes) ? attributes : [attributes];

        console.log(`Processing ${aces.length} ACEs...`);

        aces.forEach(ace => {
            const mask = ace.AccessMask;
            const interesting = ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'FullControl'];
            if (!interesting.includes(mask) && !interesting.some(i => mask.includes(i))) return;
            if (!ace.ACEType || !ace.ACEType.includes("ALLOWED")) return;

            const sourceSid = ace.SecurityIdentifier;
            let sourceId = sourceSid;

            if (sourceSid && sourceSid.startsWith("S-1-")) {
                const mapped = graphData.sidMap.get(sourceSid);
                if (mapped) sourceId = mapped;
            }

            // Create foreign node if missing
            if (!graphData.nodeMap.has(sourceId)) {
                const foreignNode = {
                    data: {
                        id: sourceId,
                        label: sourceId,
                        type: 'foreign',
                        raw: { objectSid: sourceSid }
                    },
                    style: { 'background-color': '#64748b' }
                };
                graphData.nodes.push(foreignNode);
                graphData.nodeMap.set(sourceId, foreignNode);
                if (sourceSid && sourceSid.startsWith("S-1-")) graphData.sidMap.set(sourceSid, sourceId);
            }

            const edge = addEdge(sourceId, nodeId, mask, true);
            if (edge) {
                newEdges = true;
            }
        });

        if (newEdges) {
            saveToStorage();
            // Refresh panel if showing this node
            const openId = document.getElementById('panel-content')?.querySelector('.font-mono')?.innerText;
            if (openId === nodeId) showNodeDetails(nodeId);
        }
        return newEdges;
    } catch (e) {
        console.error("Failed to fetch ACLs", e);
        return false;
    }
}
