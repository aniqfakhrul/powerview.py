import { graphData } from './state.js';
import { fetchACLs } from './network.js';
import { showNodeDetails } from './ui.js';

export let cy = null;

export function initializeCytoscape(container) {
    console.log("Graph Page: Initializing Cytoscape...");
    
    // Function to get theme color from Tailwind class on container
    const getThemeColor = () => getComputedStyle(container).color || '#333';

    try {
        cy = cytoscape({
            container: container,
            style: [
                {
                    selector: 'node',
                    style: {
                        'label': 'data(label)',
                        'color': getThemeColor,
                        'text-valign': 'bottom',
                        'text-halign': 'center',
                        'text-margin-y': 6,
                        'font-size': '10px',
                        'background-color': '#999',
                        'width': 30,
                        'height': 30,
                        'border-width': 2,
                        'border-color': '#fff'
                    }
                },
                {
                    selector: 'node[type="user"]',
                    style: {
                        'background-color': '#10b981',
                        'shape': 'ellipse',
                        'width': 30,
                        'height': 30
                    }
                },
                {
                    selector: 'node[type="group"]',
                    style: {
                        'background-color': '#f59e0b',
                        'shape': 'diamond',
                        'width': 35,
                        'height': 35
                    }
                },
                {
                    selector: 'node[type="computer"]',
                    style: {
                        'background-color': '#3b82f6',
                        'shape': 'round-rectangle',
                        'width': 35,
                        'height': 35
                    }
                },
                {
                    selector: 'node[type="foreign"]',
                    style: {
                        'background-color': '#64748b',
                        'shape': 'octagon',
                        'width': 30,
                        'height': 30
                    }
                },
                {
                    selector: 'node[type="domain"]',
                    style: {
                        'background-color': '#8b5cf6', // violet-500
                        'shape': 'star',
                        'width': 35,
                        'height': 35
                    }
                },
                {
                    selector: 'node[type="ou"]',
                    style: {
                        'background-color': '#ec4899', // pink-500
                        'shape': 'round-rectangle',
                        'width': 35,
                        'height': 35
                    }
                },
                {
                    selector: 'node[type="gpo"]',
                    style: {
                        'background-color': '#06b6d4', // cyan-500
                        'shape': 'hexagon',
                        'width': 35,
                        'height': 30
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 1.5,
                        'line-color': '#cbd5e1',
                        'target-arrow-color': '#cbd5e1',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'opacity': 0.8,
                        'label': 'data(label)',
                        'font-size': '8px',
                        'text-rotation': 'autorotate',
                        'text-margin-y': -10,
                        'color': '#000',
                        'text-background-opacity': 1,
                        'text-background-color': '#ffffff',
                        'text-background-padding': '2px',
                        'text-background-shape': 'roundrectangle'
                    }
                },
                {
                    selector: 'edge:selected',
                    style: {
                        'line-color': '#2563eb',
                        'width': 3
                    }
                },
                {
                    selector: 'node:selected',
                    style: {
                        'border-color': '#2563eb',
                        'border-width': 4
                    }
                }
            ],
            layout: {
                name: 'cose',
                animate: false
            }
        });

        // Watch for theme changes to update graph colors automatically
        const observer = new MutationObserver(() => {
            cy.style().update();
        });
        observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });

        // Hook up click event on Cytoscape
        cy.on('tap', 'node', function (evt) {
            const node = evt.target;
            addToGraph(node.id());
        });

        console.log("Graph Page: Cytoscape initialized successfully.");
        return cy;
    } catch (err) {
        console.error("Graph Page: Failed to initialize Cytoscape library", err);
        return null;
    }
}

export function clearGraph() {
    if (cy) {
        cy.elements().remove();
        const detailsPanel = document.getElementById('details-panel');
        if (detailsPanel) detailsPanel.classList.add('translate-x-full');
    }
}

export function centerGraph() {
    if (cy && cy.elements().length > 0) {
        cy.fit();
        cy.center();
    }
}

export function runLayout(fit = true) {
    if (!cy) return;
    const layout = cy.layout({
        name: 'cose',
        animate: true,
        nodeDimensionsIncludeLabels: true,
        randomize: false,
        componentSpacing: 100,
        nodeRepulsion: function (node) { return 8092; },
        idealEdgeLength: function (edge) { return 100; },
        edgeElasticity: function (edge) { return 100; },
        nestingFactor: 5,
        fit: fit,
        padding: 50
    });
    layout.run();
    return layout;
}

export function expandNode(nodeId) {
    let changed = false;
    const neighborEdges = graphData.neighbors.get(nodeId);
    if (neighborEdges) {
        neighborEdges.forEach(edgeId => {
            // Check if edge is already in CY
            if (cy && cy.getElementById(edgeId).length === 0) {
                const edge = graphData.edgeMap.get(edgeId);
                if (!edge) return;

                // Ensure Source Node is in CY
                const sourceId = edge.data.source;
                if (cy.getElementById(sourceId).length === 0) {
                    const sNode = graphData.nodeMap.get(sourceId);
                    if (sNode) {
                        // Position near the target (which is likely nodeId or connected to it)
                        const targetNode = cy.getElementById(edge.data.target);
                        let pos = null;
                        if (targetNode.length > 0) {
                            const tPos = targetNode.position();
                            pos = { x: tPos.x + (Math.random() - 0.5) * 100, y: tPos.y + (Math.random() - 0.5) * 100 };
                        } else {
                            const extent = cy.extent();
                            pos = { x: extent.x1 + extent.w / 2, y: extent.y1 + extent.h / 2 };
                        }
                        cy.add({ ...sNode, position: pos });
                        changed = true;
                    }
                }

                // Ensure Target Node is in CY
                const targetId = edge.data.target;
                if (cy.getElementById(targetId).length === 0) {
                    const tNode = graphData.nodeMap.get(targetId);
                    if (tNode) {
                        const sourceNode = cy.getElementById(sourceId);
                        let pos = null;
                        if (sourceNode.length > 0) {
                            const sPos = sourceNode.position();
                            pos = { x: sPos.x + (Math.random() - 0.5) * 100, y: sPos.y + (Math.random() - 0.5) * 100 };
                        } else {
                            const extent = cy.extent();
                            pos = { x: extent.x1 + extent.w / 2, y: extent.y1 + extent.h / 2 };
                        }
                        cy.add({ ...tNode, position: pos });
                        changed = true;
                    }
                }

                // Add Edge
                cy.add(edge);
                changed = true;
            }
        });
    }
    return changed;
}

export async function addToGraph(nodeId) {
    let needsLayout = false;

    // Add node if not present in CY
    if (cy && cy.getElementById(nodeId).length === 0) {
        const node = graphData.nodeMap.get(nodeId);
        if (node) {
            // Calculate viewport center
            const extent = cy.extent();
            const centerPos = {
                x: extent.x1 + extent.w / 2,
                y: extent.y1 + extent.h / 2
            };

            // Set initial position to center of viewport
            cy.add({
                ...node,
                position: centerPos
            });
            needsLayout = true;
        } else {
            console.warn(`Node ${nodeId} not found in graphData.`);
            return;
        }
    }

    // Show details immediately
    showNodeDetails(nodeId);

    // Fetch ACLs dynamically
    console.log(`Fetching ACLs for ${nodeId}...`);
    const newAcls = await fetchACLs(nodeId);
    
    // Expand neighbors (including newly fetched ACLs)
    console.log(`Expanding node ${nodeId}...`);
    if (expandNode(nodeId) || newAcls || needsLayout) {
        console.log("Graph updated, running layout...");
        const layout = runLayout(false); 
        layout.one('layoutstop', () => {
            const ele = cy.getElementById(nodeId);
            if (ele.length > 0) {
                cy.animate({
                    center: { eles: ele },
                    zoom: 1.2,
                    duration: 500
                });
            }
        });
    } else {
        // Already there, just center
        const ele = cy.getElementById(nodeId);
        if (ele.length > 0) {
            cy.animate({
                center: { eles: ele },
                zoom: 1.2,
                duration: 500
            });
        }
    }
}
