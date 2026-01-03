import { graphData, addNode, addEdge, addForeignNode, getId, saveToStorage, setStorageKey, clearData } from './state.js';
import { showLoading, updateStatus, showNodeDetails, updateStats } from './ui.js';
import { clearGraph } from './viz.js';

const ensureOk = (res, label) => {
    if (!res.ok) throw new Error(`${label} failed (${res.status})`);
    return res;
};

const escapeHtml = (v) => {
    if (v === undefined || v === null) return '';
    return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
};

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
    updateStatus("Fetching Active Directory objects...");

    try {
        console.log("Fetching graph data from backend...");
        const [usersRes, groupsRes, computersRes, domainsRes, ouRes, gpoRes] = await Promise.all([
            fetch('/api/get/domainuser?properties=*').then(r => ensureOk(r, 'Users')),
            fetch('/api/get/domaingroup?properties=*').then(r => ensureOk(r, 'Groups')),
            fetch('/api/get/domaincomputer?properties=*').then(r => ensureOk(r, 'Computers')),
            fetch('/api/get/domain?properties=*').then(r => ensureOk(r, 'Domains')),
            fetch('/api/get/domainou?properties=*').then(r => ensureOk(r, 'OUs')),
            fetch('/api/get/domaingpo?properties=*').then(r => ensureOk(r, 'GPOs'))
        ]);

        const users = await usersRes.json();
        const groups = await groupsRes.json();
        const computers = await computersRes.json();
        const domains = await domainsRes.json();
        const ous = await ouRes.json();
        const gpos = await gpoRes.json();

        updateStatus("Processing data...");

        // Clear old data
        clearData();

        // Add Nodes
        (Array.isArray(domains) ? domains : []).forEach(d => addNode(d, 'domain'));
        (Array.isArray(ous) ? ous : []).forEach(o => addNode(o, 'ou'));
        (Array.isArray(gpos) ? gpos : []).forEach(g => addNode(g, 'gpo'));
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

        const processContainment = (items) => {
            (items || []).forEach(item => {
                const dn = item.attributes.distinguishedName;
                if (!dn) return;
                const sourceId = getId(dn);
                
                // Extract parent DN
                const parts = dn.split(',');
                if (parts.length > 1) {
                    const parentDn = parts.slice(1).join(',');
                    const targetId = getId(parentDn);
                    // Only add edge if the target node (Domain or OU) exists in our map
                    if (graphData.nodeMap.has(targetId)) {
                        addEdge(sourceId, targetId, 'contains');
                    }
                }
            });
        };

        const processGPOLinks = (containers) => {
            (containers || []).forEach(container => {
                const attrs = container.attributes;
                const gpcLink = attrs.gPLink;
                if (!gpcLink) return;

                const targetId = getId(attrs.distinguishedName);
                
                // gpcLink format: [LDAP://CN={GUID},CN=Policies...;0]
                const matches = gpcLink.match(/CN=({.*?})/gi);
                if (matches) {
                    matches.forEach(match => {
                        const guid = match.split('=')[1].toLowerCase();
                        // Find GPO node by GUID in its DN or CN
                        for (const [id, node] of graphData.nodeMap) {
                            if (node.data.type === 'gpo' && id.toLowerCase().includes(guid)) {
                                addEdge(id, targetId, 'gpoLink');
                                break;
                            }
                        }
                    });
                }
            });
        };

        processMemberOf(users);
        processMemberOf(groups);
        processMemberOf(computers);
        
        processContainment(ous);
        processContainment(users);
        processContainment(groups);
        processContainment(computers);

        processGPOLinks(domains);
        processGPOLinks(ous);

        // Save to Cache
        saveToStorage();
        updateStats();

        updateStatus("Ready.");
        showLoading(false);

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
        if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);

        if (json.error) throw new Error(json.error);
        if (!Array.isArray(json) || json.length === 0) {
            if (placeholder) placeholder.textContent = "No ACL entries found.";
            return;
        }

        const aces = [];
        json.forEach(entry => {
            const attrs = entry.attributes;
            if (Array.isArray(attrs)) {
                aces.push(...attrs);
            } else if (attrs) {
                aces.push(attrs);
            }
        });
        if (aces.length === 0) {
            if (placeholder) placeholder.textContent = "No ACL entries found.";
            return;
        }

        let aceHtml = `<div class="mt-2 space-y-2 pr-2">`;
        aces.forEach(ace => {
            const type = ace.ACEType || 'Unknown';
            const mask = ace.AccessMask || 'Unknown';
            const principal = ace.SecurityIdentifier || 'Unknown';
            const isInherited = ace.IsInherited === 'True';
            const targetDn = ace.ObjectDN || 'Unknown object';

            aceHtml += `
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800/50 rounded border border-neutral-100 dark:border-neutral-700">
                    <div class="flex justify-between items-start mb-1">
                        <span class="font-bold text-[10px] uppercase px-1.5 py-0.5 rounded ${type.includes('ALLOWED') ? 'bg-green-100 text-green-700 dark:bg-green-900/30' : 'bg-red-100 text-red-700 dark:bg-red-900/30'}">
                            ${escapeHtml(type)}
                        </span>
                        ${isInherited ? '<span class="text-[9px] text-neutral-400">Inherited</span>' : ''}
                    </div>
                    <div class="font-mono text-[10px] text-neutral-800 dark:text-neutral-200 mb-1 break-all">${escapeHtml(principal)}</div>
                    <div class="text-[10px] text-blue-600 dark:text-blue-400 font-medium">${escapeHtml(mask)}</div>
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

export async function fetchOutboundDACL(nodeId) {
    const container = document.getElementById(`dacl-outbound-section-${nodeId.replace(/[^a-z0-9]/gi, '_')}`);
    if (!container) return;

    const placeholder = container.querySelector('.dacl-outbound-placeholder');
    const spinner = container.querySelector('.dacl-outbound-spinner');
    const button = container.querySelector('.dacl-outbound-button');
    if (spinner) spinner.classList.remove('hidden');
    if (button) button.disabled = true;

    try {
        const node = graphData.nodeMap.get(nodeId);
        const sid = node?.data?.raw?.objectSid || (node?.data?.type === 'foreign' ? node?.data?.id : null);
        if (!sid) {
            if (placeholder) placeholder.textContent = "Unavailable (No SID)";
            return;
        }

        const res = await fetch(`/api/get/domainobjectacl?security_identifier=${encodeURIComponent(sid)}`);
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || `HTTP ${res.status}`);

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
            const targetDn = ace.ObjectDN || 'Unknown object';

            aceHtml += `
                <div class="p-2 bg-neutral-50 dark:bg-neutral-800/50 rounded border border-neutral-100 dark:border-neutral-700">
                    <div class="flex justify-between items-start mb-1">
                        <span class="font-bold text-[10px] uppercase px-1.5 py-0.5 rounded ${type.includes('ALLOWED') ? 'bg-green-100 text-green-700 dark:bg-green-900/30' : 'bg-red-100 text-red-700 dark:bg-red-900/30'}">
                            ${escapeHtml(type)}
                        </span>
                        ${isInherited ? '<span class="text-[9px] text-neutral-400">Inherited</span>' : ''}
                    </div>
                    <div class="text-[10px] text-neutral-700 dark:text-neutral-300 mb-1">
                        <span class="font-semibold">Target:</span>
                        <a href="#" class="text-blue-600 dark:text-blue-400 underline break-all dacl-outbound-target" data-target-id="${escapeHtml(getId(targetDn))}">
                            ${escapeHtml(targetDn)}
                        </a>
                    </div>
                    <div class="font-mono text-[10px] text-neutral-800 dark:text-neutral-200 mb-1 break-all">${escapeHtml(principal)}</div>
                    <div class="text-[10px] text-blue-600 dark:text-blue-400 font-medium">${escapeHtml(mask)}</div>
                </div>
            `;
        });
        aceHtml += `</div>`;

        if (placeholder) placeholder.outerHTML = aceHtml;
    } catch (e) {
        console.error("Outbound DACL Dump Failed:", e);
        if (placeholder) placeholder.textContent = "Failed to fetch outbound DACL.";
    } finally {
        if (spinner) spinner.classList.add('hidden');
        if (button) button.disabled = false;
    }
}

export async function fetchInboundACLs(nodeId) {
    try {
        const node = graphData.nodeMap.get(nodeId);
        if (!node) return false;

        // Inbound: Who controls THIS node?
        const dn = (node.data.raw && node.data.raw.distinguishedName) ? node.data.raw.distinguishedName : node.data.id;
        
        console.log(`Requesting Inbound ACLs for DN: ${dn}`);
        const res = await fetch(`/api/get/domainobjectacl?identity=${encodeURIComponent(dn)}`);
        const json = await res.json();
        if (!res.ok) {
            console.warn("ACL Fetch Error:", json.error || res.status);
            return false;
        }

        if (json.error) {
            console.warn("ACL Fetch Error:", json.error);
            return false;
        }
        if (!Array.isArray(json) || json.length === 0) {
            console.log("No ACLs returned.");
            return false;
        }

        return processACLResults(json, nodeId, true);
    } catch (e) {
        console.error("Failed to fetch inbound ACLs", e);
        return false;
    }
}

export async function fetchOutboundACLs(nodeId) {
    try {
        const node = graphData.nodeMap.get(nodeId);
        if (!node) return false;

        // Outbound: Who does THIS node control?
        // We need the SID of the current node
        const sid = (node.data.raw && node.data.raw.objectSid) ? node.data.raw.objectSid : (node.data.type === 'foreign' ? node.data.id : null);
        
        if (!sid) {
            console.warn("Outbound ACL fetch requires a SID.");
            return false;
        }

        console.log(`Requesting Outbound ACLs for Principal SID: ${sid}`);
        const res = await fetch(`/api/get/domainobjectacl?security_identifier=${encodeURIComponent(sid)}`);
        const json = await res.json();
        if (!res.ok) {
            console.warn("ACL Fetch Error:", json.error || res.status);
            return false;
        }

        if (json.error) {
            console.warn("ACL Fetch Error:", json.error);
            return false;
        }
        if (!Array.isArray(json) || json.length === 0) {
            console.log("No ACLs returned.");
            return false;
        }

        return processACLResults(json, nodeId, false);
    } catch (e) {
        console.error("Failed to fetch outbound ACLs", e);
        return false;
    }
}

function processACLResults(json, nodeId, isInbound) {
    let newEdges = false;
    
    // Each element in json is a dict: { attributes: [list of ACEs] }
    json.forEach(entry => {
        const aces = entry.attributes;
        if (!Array.isArray(aces)) return;

        aces.forEach(ace => {
            const mask = ace.AccessMask;
            const interesting = ['GenericAll', 'WriteDacl', 'WriteOwner', 'GenericWrite', 'FullControl'];
            if (!interesting.includes(mask) && !interesting.some(i => mask.includes(i))) return;
            if (!ace.ACEType || !ace.ACEType.includes("ALLOWED")) return;

            let sourceId, targetId;

            if (isInbound) {
                // Inbound: Who controls THIS node?
                targetId = nodeId;
                const sourceSid = ace.SecurityIdentifier;
                sourceId = sourceSid;
                if (sourceSid && sourceSid.startsWith("S-1-")) {
                    const mapped = graphData.sidMap.get(sourceSid);
                    if (mapped) sourceId = mapped;
                }

                // Create foreign node if missing
                if (!graphData.nodeMap.has(sourceId)) {
                    addForeignNode(sourceId, ace.SecurityIdentifier);
                }
            } else {
                // Outbound: Who does THIS node control?
                sourceId = nodeId;
                const targetDn = ace.ObjectDN;
                if (!targetDn) return;
                targetId = getId(targetDn);

                // If target node doesn't exist in memory, it might be in our full fetch
                // If not, we could add it as an inferred node
                if (!graphData.nodeMap.has(targetId)) {
                    addNode({
                        attributes: { distinguishedName: targetDn, objectSid: ace.ObjectSID }
                    }, 'unknown');
                }
            }

            const edge = addEdge(sourceId, targetId, mask, true);
            if (edge) {
                newEdges = true;
            }
        });
    });

    if (newEdges) {
        saveToStorage();
        // Refresh panel if showing this node
        const openId = document.getElementById('panel-content')?.querySelector('.font-mono')?.innerText;
        if (openId === nodeId) {
            // If we just got inbound results, update the detailed DACL view in the side panel
            if (isInbound) {
                fetchFullDACL(nodeId);
            }
        }
    }
    return newEdges;
}

export async function fetchACLs(nodeId) {
    // Legacy support, default to inbound
    return fetchInboundACLs(nodeId);
}

