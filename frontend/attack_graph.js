/* ═══════════════════════════════════════════════════════════════
   Attack Graph — D3.js Force-Directed Graph (Palantir Gotham Style)
   ═══════════════════════════════════════════════════════════════ */

const AttackGraph = (() => {
    // ── Config ────────────────────────────────────────────────
    const NODE_RADIUS = 20;
    const LABEL_OFFSET = 28;
    const ARROW_SIZE = 8;
    const LINK_OPACITY = 0.45;

    // ── State ─────────────────────────────────────────────────
    let svg, g, simulation;
    let width, height;
    let nodesData = [];
    let linksData = [];
    let nodeMap = new Map();
    let edgeSet = new Set();

    let nodeGroup, linkGroup, labelGroup, linkLabelGroup;

    // ── Initialize ────────────────────────────────────────────
    function init(selector) {
        const container = document.querySelector(selector);
        if (!container) return;

        svg = d3.select(selector);
        const rect = container.getBoundingClientRect();
        width = Math.max(640, Math.floor(rect.width || container.clientWidth || 0));
        height = Math.max(420, Math.floor(rect.height || container.clientHeight || 0));

        svg.attr('viewBox', [0, 0, width, height]);

        const defs = svg.append('defs');

        // Glow filter
        const filter = defs.append('filter').attr('id', 'glow');
        filter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
        const fm = filter.append('feMerge');
        fm.append('feMergeNode').attr('in', 'coloredBlur');
        fm.append('feMergeNode').attr('in', 'SourceGraphic');

        // Arrow marker
        defs.append('marker')
            .attr('id', 'arrowhead')
            .attr('viewBox', '-0 -5 10 10')
            .attr('refX', NODE_RADIUS + ARROW_SIZE)
            .attr('refY', 0)
            .attr('markerWidth', ARROW_SIZE)
            .attr('markerHeight', ARROW_SIZE)
            .attr('orient', 'auto')
            .append('path')
            .attr('d', 'M 0,-4 L 8,0 L 0,4')
            .attr('fill', 'rgba(255,255,255,0.35)');

        // Main group (zoom/pan)
        g = svg.append('g').attr('class', 'graph-layer');

        linkGroup = g.append('g').attr('class', 'links');
        linkLabelGroup = g.append('g').attr('class', 'link-labels');
        nodeGroup = g.append('g').attr('class', 'nodes');
        labelGroup = g.append('g').attr('class', 'labels');

        // Zoom
        const zoom = d3.zoom()
            .scaleExtent([0.2, 5])
            .on('zoom', (event) => g.attr('transform', event.transform));
        svg.call(zoom);

        // Force simulation
        simulation = d3.forceSimulation()
            .force('link', d3.forceLink().id(d => d.id).distance(60).iterations(3))
            .force('charge', d3.forceManyBody().strength(-1000).distanceMax(600).distanceMin(NODE_RADIUS))
            .force('center', d3.forceCenter(width / 2, height / 2))
            .force('collision', d3.forceCollide().radius(NODE_RADIUS * 1.5).iterations(2))
            .force('x', d3.forceX(width / 2).strength(0.015))
            .force('y', d3.forceY(height / 2).strength(0.015))
            .on('tick', ticked);

        updateStats();
    }

    // ── Add Data ──────────────────────────────────────────────
    function addData(data) {
        if (!simulation) return;
        let changed = false;

        console.log('[Graph] Received data:', data.nodes?.length, 'nodes,', data.edges?.length, 'edges');
        console.log('[Graph] Current nodeMap size:', nodeMap.size);

        // First pass: add all nodes first (to handle edges that reference nodes arriving in different orders)
        if (data.nodes) {
            for (const n of data.nodes) {
                if (!nodeMap.has(n.id)) {
                    const node = {
                        ...n,
                        x: width / 2 + (Math.random() - 0.5) * 400,
                        y: height / 2 + (Math.random() - 0.5) * 400,
                        _pinned: false,
                    };
                    nodesData.push(node);
                    nodeMap.set(n.id, node);
                    changed = true;
                    console.log('[Graph] Added node:', n.id, n.type);
                }
            }
        }

        // Second pass: add edges (nodes should now exist)
        if (data.edges) {
            for (const e of data.edges) {
                const sourceId = e.source.id || e.source;
                const targetId = e.target.id || e.target;
                const key = `${sourceId}|${targetId}|${e.type}`;
                
                const sourceExists = nodeMap.has(sourceId);
                const targetExists = nodeMap.has(targetId);
                
                if (!edgeSet.has(key)) {
                    if (sourceExists && targetExists) {
                        edgeSet.add(key);
                        linksData.push({ ...e });
                        changed = true;
                        console.log('[Graph] Added edge:', sourceId, '->', targetId);
                    } else {
                        console.log('[Graph] Skipped edge - source exists:', sourceExists, 'target exists:', targetExists, 'source:', sourceId, 'target:', targetId);
                    }
                }
            }
        }

        console.log('[Graph] After processing - nodesData:', nodesData.length, 'linksData:', linksData.length);

        if (changed) {
            console.log('[Graph] Calling render(), simulation exists:', !!simulation);
            render();
            simulation.alpha(0.6).restart();
            updateStats();
            console.log('[Graph] Render complete, nodes in DOM:', nodeGroup?.selectAll('g.node').size());
        }
    }

    // ── Render ─────────────────────────────────────────────────
    function render() {
        // ── Links ──
        const links = linkGroup.selectAll('line')
            .data(linksData, d => `${d.source.id || d.source}|${d.target.id || d.target}|${d.type}`);
        links.exit().remove();

        const linksEnter = links.enter().append('line')
            .attr('stroke', 'rgba(255,255,255,0.2)')
            .attr('stroke-width', 1.5)
            .attr('marker-end', 'url(#arrowhead)')
            .style('cursor', 'default')
            .style('opacity', 0);

        linksEnter
            .on('mouseenter', function (event, d) {
                d3.select(this).attr('stroke', '#ffab00').attr('stroke-width', 3);
                showTooltipEdge(event, d);
            })
            .on('mousemove', function (event) {
                moveTooltip(event);
            })
            .on('mouseleave', function () {
                d3.select(this).attr('stroke', 'rgba(255,255,255,0.2)').attr('stroke-width', 1.5);
                hideTooltip();
            });

        linksEnter.transition().duration(600).style('opacity', LINK_OPACITY);

        // ── Link Labels ──
        const linkLabels = linkLabelGroup.selectAll('text')
            .data(linksData, d => `${d.source.id || d.source}|${d.target.id || d.target}|${d.type}`);
        linkLabels.exit().remove();

        linkLabels.enter().append('text')
            .attr('class', 'link-label')
            .attr('text-anchor', 'middle')
            .attr('dy', -4)
            .text(d => d.type)
            .style('opacity', 0)
            .transition().duration(600).style('opacity', 0.5);

        // ── Nodes ──
        const nodes = nodeGroup.selectAll('g.node')
            .data(nodesData, d => d.id);
        nodes.exit().remove();

        const nodesEnter = nodes.enter().append('g')
            .attr('class', 'node')
            .call(drag(simulation));

        // Circle
        nodesEnter.append('circle')
            .attr('r', 0)
            .attr('fill', d => d.color || '#90a4ae')
            .attr('fill-opacity', 0.15)
            .attr('stroke', d => d.color || '#90a4ae')
            .attr('stroke-width', 2)
            .attr('filter', 'url(#glow)')
            .transition().duration(500)
            .attr('r', NODE_RADIUS);

        // Pulse animation
        nodesEnter.append('circle')
            .attr('class', 'pulse-ring')
            .attr('r', NODE_RADIUS)
            .attr('fill', 'none')
            .attr('stroke', d => d.color || '#90a4ae')
            .attr('stroke-width', 2)
            .attr('opacity', 0.8)
            .transition().duration(1200)
            .attr('r', NODE_RADIUS + 15)
            .attr('opacity', 0)
            .remove();

        // Icon
        nodesEnter.append('text')
            .attr('class', 'node-icon')
            .attr('text-anchor', 'middle')
            .attr('dy', 5)
            .style('font-size', '14px')
            .text(d => d.icon || '●');

        // Pin indicator
        nodesEnter.append('circle')
            .attr('class', 'pin-indicator')
            .attr('cx', NODE_RADIUS - 4)
            .attr('cy', -(NODE_RADIUS - 4))
            .attr('r', 4)
            .attr('fill', '#ff1744')
            .attr('stroke', '#0a0c10')
            .attr('stroke-width', 1)
            .style('display', 'none');

        // Hover tooltip for nodes
        nodesEnter
            .on('mouseenter', function (event, d) {
                // Highlight this node
                d3.select(this).select('circle:first-child')
                    .attr('stroke-width', 3).attr('fill-opacity', 0.3);
                showTooltipNode(event, d);
            })
            .on('mousemove', function (event) {
                moveTooltip(event);
            })
            .on('mouseleave', function (event, d) {
                d3.select(this).select('circle:first-child')
                    .attr('stroke-width', 2).attr('fill-opacity', 0.15);
                hideTooltip();
            });

        // Single-click to toggle pin status
        nodesEnter.on('click', function (event, d) {
            event.stopPropagation();
            if (d._pinned) {
                d._pinned = false;
                d.fx = null; d.fy = null;
                d3.select(this).select('.pin-indicator').style('display', 'none');
            } else {
                d._pinned = true;
                d.fx = d.x; d.fy = d.y;
                d3.select(this).select('.pin-indicator').style('display', 'block');
            }

            // Re-render tooltip to immediately reflect pin badge change
            const tt = document.getElementById('graph-tooltip');
            if (tt && tt.style.display !== 'none') {
                showTooltipNode(event, d);
            }

            simulation.alpha(0.3).restart();
        });

        // ── Labels ──
        const labels = labelGroup.selectAll('text.node-label')
            .data(nodesData, d => d.id);
        labels.exit().remove();

        labels.enter().append('text')
            .attr('class', 'node-label')
            .attr('text-anchor', 'middle')
            .attr('dy', LABEL_OFFSET)
            .text(d => d.label)
            .style('opacity', 0)
            .transition().duration(500).style('opacity', 0.8);

        // Update simulation
        simulation.nodes(nodesData);
        simulation.force('link').links(linksData);
    }

    // ── Tooltip (floating near cursor) ────────────────────────

    function getOrCreateTooltip() {
        let tt = document.getElementById('graph-tooltip');
        if (!tt) {
            tt = document.createElement('div');
            tt.id = 'graph-tooltip';
            document.body.appendChild(tt);
        }
        return tt;
    }

    function showTooltipNode(event, d) {
        const tt = getOrCreateTooltip();
        const props = d.properties || {};
        const propsHtml = Object.entries(props)
            .filter(([k]) => !k.startsWith('_'))
            .slice(0, 8)
            .map(([k, v]) => `<div class="tt-row"><span class="tt-key">${k}</span><span class="tt-val">${v}</span></div>`)
            .join('');

        const pinnedTag = d._pinned ? ' <span style="color:#ff1744;font-size:.6rem">📌 已固定</span>' : '';

        tt.innerHTML = `
            <div class="tt-header" style="color:${d.color}">${d.icon} ${d.type}${pinnedTag}</div>
            <div class="tt-title">${d.label}</div>
            ${propsHtml}
        `;
        tt.style.display = 'block';
        positionTooltip(tt, event);
    }

    function showTooltipEdge(event, d) {
        const tt = getOrCreateTooltip();
        const srcLabel = d.source.label || d.source;
        const tgtLabel = d.target.label || d.target;

        tt.innerHTML = `
            <div class="tt-header" style="color:#ffab00">➤ ${d.type}</div>
            <div class="tt-row"><span class="tt-key">源节点</span><span class="tt-val">${srcLabel}</span></div>
            <div class="tt-row"><span class="tt-key">目标节点</span><span class="tt-val">${tgtLabel}</span></div>
        `;
        tt.style.display = 'block';
        positionTooltip(tt, event);
    }

    function positionTooltip(tt, event) {
        const pad = 14;
        let x = event.pageX + pad;
        let y = event.pageY - pad;
        // Keep on screen
        const rect = tt.getBoundingClientRect();
        if (x + rect.width > window.innerWidth - 10) x = event.pageX - rect.width - pad;
        if (y + rect.height > window.innerHeight - 10) y = event.pageY - rect.height - pad;
        if (y < 10) y = 10;
        tt.style.left = x + 'px';
        tt.style.top = y + 'px';
    }

    function moveTooltip(event) {
        const tt = document.getElementById('graph-tooltip');
        if (tt && tt.style.display !== 'none') positionTooltip(tt, event);
    }

    function hideTooltip() {
        const tt = document.getElementById('graph-tooltip');
        if (tt) tt.style.display = 'none';
    }

    // ── Tick ───────────────────────────────────────────────────
    function ticked() {
        linkGroup.selectAll('line')
            .attr('x1', d => d.source.x).attr('y1', d => d.source.y)
            .attr('x2', d => d.target.x).attr('y2', d => d.target.y);

        linkLabelGroup.selectAll('text')
            .attr('x', d => (d.source.x + d.target.x) / 2)
            .attr('y', d => (d.source.y + d.target.y) / 2);

        nodeGroup.selectAll('g.node')
            .attr('transform', d => `translate(${d.x},${d.y})`);

        labelGroup.selectAll('text.node-label')
            .attr('x', d => d.x).attr('y', d => d.y);
    }

    // ── Drag (pins node on drop) ──────────────────────────────
    function drag(sim) {
        return d3.drag()
            .on('start', (event, d) => {
                if (!event.active) sim.alphaTarget(0.3).restart();
                d.fx = d.x; d.fy = d.y;
                hideTooltip(); // hide tooltip while dragging
            })
            .on('drag', (event, d) => {
                d.fx = event.x; d.fy = event.y;
            })
            .on('end', (event, d) => {
                if (!event.active) sim.alphaTarget(0);
                // PIN the node after drag
                d._pinned = true;
                nodeGroup.selectAll('g.node').each(function (nd) {
                    if (nd.id === d.id) {
                        d3.select(this).select('.pin-indicator').style('display', 'block');
                    }
                });
            });
    }

    // ── Stats ─────────────────────────────────────────────────
    function updateStats() {
        const el = document.getElementById('graphStats');
        if (el) el.textContent = `${nodesData.length} nodes · ${linksData.length} edges`;
    }

    // ── Reset ─────────────────────────────────────────────────
    function reset() {
        nodesData = []; linksData = [];
        nodeMap.clear(); edgeSet.clear();
        if (g) {
            linkGroup.selectAll('*').remove();
            linkLabelGroup.selectAll('*').remove();
            nodeGroup.selectAll('*').remove();
            labelGroup.selectAll('*').remove();
        }
        if (simulation) {
            simulation.nodes([]);
            simulation.force('link').links([]);
            simulation.alpha(0).stop();
        }
        hideTooltip();
        updateStats();
    }

    // ── Resize ────────────────────────────────────────────────
    function resize() {
        const container = document.querySelector('.graph-svg');
        if (!container || !simulation) return;
        width = container.clientWidth;
        height = container.clientHeight;
        svg.attr('viewBox', [0, 0, width, height]);
        simulation.force('center', d3.forceCenter(width / 2, height / 2));
        simulation.force('x', d3.forceX(width / 2).strength(0.015));
        simulation.force('y', d3.forceY(height / 2).strength(0.015));
        simulation.alpha(0.3).restart();
    }

    return { init, addData, reset, resize };
})();

window.addEventListener('resize', () => AttackGraph.resize());
