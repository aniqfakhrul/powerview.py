export const graphData = {
    nodes: [],
    edges: [],
    nodeMap: new Map(), // id -> node
    edgeMap: new Map(), // id -> edge
    neighbors: new Map(), // nodeId -> Set(edgeId)
    sidMap: new Map() // sid -> nodeId
};

let STORAGE_KEY = 'powerview_graph_data';

export function setStorageKey(key) {
    STORAGE_KEY = key;
}

export function getStorageKey() {
    return STORAGE_KEY;
}

export function getId(dn) {
    return dn ? dn.toLowerCase() : null;
}

export function getLabel(attrs) {
    if (!attrs) return 'Unknown';
    return attrs.sAMAccountName || attrs.name || attrs.cn || (attrs.distinguishedName ? attrs.distinguishedName.split(',')[0].split('=')[1] : 'Unknown');
}

export function saveToStorage() {
    try {
        const payload = {
            nodes: graphData.nodes,
            edges: graphData.edges,
            timestamp: Date.now()
        };
        localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
        console.log("Graph data saved to localStorage using key:", STORAGE_KEY);
    } catch (e) {
        console.error("Failed to save to localStorage", e);
    }
}

export function loadFromStorage() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return false;

        const payload = JSON.parse(raw);
        if (!payload.nodes || !payload.edges) return false;

        console.log("Loading graph from localStorage using key:", STORAGE_KEY);

        graphData.nodes = payload.nodes;
        graphData.edges = payload.edges;

        rebuildMaps();
        return true;

    } catch (e) {
        console.error("Failed to load from localStorage", e);
        return false;
    }
}

export function rebuildMaps() {
    graphData.nodeMap.clear();
    graphData.edgeMap.clear();
    graphData.neighbors.clear();
    graphData.sidMap.clear();

    graphData.nodes.forEach(n => {
        graphData.nodeMap.set(n.data.id, n);
        if (n.data.raw && n.data.raw.objectSid) {
            graphData.sidMap.set(n.data.raw.objectSid, n.data.id);
        }
    });

    graphData.edges.forEach(e => {
        graphData.edgeMap.set(e.data.id, e);

        const s = e.data.source;
        const t = e.data.target;

        if (!graphData.neighbors.has(s)) graphData.neighbors.set(s, new Set());
        if (!graphData.neighbors.has(t)) graphData.neighbors.set(t, new Set());

        graphData.neighbors.get(s).add(e.data.id);
        graphData.neighbors.get(t).add(e.data.id);
    });
}

export function clearData() {
    graphData.nodes = [];
    graphData.edges = [];
    graphData.nodeMap.clear();
    graphData.edgeMap.clear();
    graphData.neighbors.clear();
    graphData.sidMap.clear();
}

export function addNode(item, type) {
    const attrs = item.attributes;
    const dn = attrs.distinguishedName;
    if (!dn) return;

    const id = getId(dn);
    if (graphData.nodeMap.has(id)) return;

    // Map SID to ID
    if (attrs.objectSid) {
        graphData.sidMap.set(attrs.objectSid, id);
    }

    const label = getLabel(attrs);
    const node = {
        data: {
            id: id,
            label: label,
            type: type,
            raw: attrs
        }
    };

    graphData.nodes.push(node);
    graphData.nodeMap.set(id, node);
    return node;
}

export function addEdge(sourceId, targetId, label, isAcl = false, direction = null) {
    // Check if target exists; if not, create inferred
    if (!graphData.nodeMap.has(targetId)) {
        // Try to infer label from DN
        // This is imperfect but needed for cross-domain or partial data
        const nodeFn = targetId.split(',')[0].split('=')[1] || targetId;
        const node = {
            data: {
                id: targetId,
                label: nodeFn,
                type: 'group', // Assume group for memberOf usually
                inferred: true
            },
            style: { 'background-color': '#9ca3af' }
        };
        graphData.nodes.push(node);
        graphData.nodeMap.set(targetId, node);
    }

    const edgeId = `${sourceId}-${label}-${targetId}`;
    // Avoid dupes
    if (graphData.edgeMap.has(edgeId)) return;

    const edge = {
        data: {
            id: edgeId,
            source: sourceId,
            target: targetId,
            label: label,
            acl: isAcl,
            aclDirection: direction
        }
    };

    graphData.edges.push(edge);
    graphData.edgeMap.set(edgeId, edge);

    // Update neighbor index
    if (!graphData.neighbors.has(sourceId)) graphData.neighbors.set(sourceId, new Set());
    if (!graphData.neighbors.has(targetId)) graphData.neighbors.set(targetId, new Set());

    graphData.neighbors.get(sourceId).add(edgeId);
    graphData.neighbors.get(targetId).add(edgeId);

    return edge;
}

export function addForeignNode(sourceId, sourceSid) {
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
        return foreignNode;
    }
    return null;
}
