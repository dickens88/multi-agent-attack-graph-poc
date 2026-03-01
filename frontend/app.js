/* ═══════════════════════════════════════════════════════════════
   Security Investigation Dashboard — Frontend Logic
   ═══════════════════════════════════════════════════════════════ */

// ── DOM Elements ──────────────────────────────────────────────
const questionInput = document.getElementById('questionInput');
const submitBtn = document.getElementById('submitBtn');
const statusIndicator = document.getElementById('statusIndicator');
const pipeline = document.getElementById('pipeline');
const iterationBadge = document.getElementById('iterationBadge');
const timelineContainer = document.getElementById('timelineContainer');
const timeline = document.getElementById('timeline');
const reportContainer = document.getElementById('reportContainer');
const reportContent = document.getElementById('reportContent');
const waitingIndicator = document.getElementById('waitingIndicator');
const waitingText = document.getElementById('waitingText');
const waitingTimer = document.getElementById('waitingTimer');
const deepThinkingCb = document.getElementById('deepThinkingCheckbox');

// ── State ─────────────────────────────────────────────────────
let eventSource = null;
let currentIteration = 0;
let waitingTimerInterval = null;
let waitingStartTime = null;
let lastAgent = '';
let isInvestigating = false;

// ── Agent labels for waiting messages ─────────────────────────
const AGENT_LABELS = {
    Coordinator: '🎯 协调器正在分析问题意图',
    Planner: '🧠 规划器正在制定查询策略',
    Retriever: '🔍 检索器正在查询知识图谱',
    Analyzer: '📊 分析器正在分析查询结果',
    Reporter: '📝 报告器正在生成调查报告',
};

// ── Init Attack Graph on page load ────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    AttackGraph.init('.graph-svg');
});

// ── Waiting Timer ─────────────────────────────────────────────

function startWaitingTimer(agentName) {
    waitingStartTime = Date.now();
    const label = AGENT_LABELS[agentName] || `等待 ${agentName} 响应`;
    waitingText.textContent = label + '...';
    waitingTimer.textContent = '0s';
    waitingIndicator.style.display = 'block';
    waitingIndicator.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

    clearInterval(waitingTimerInterval);
    waitingTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - waitingStartTime) / 1000);
        waitingTimer.textContent = `${elapsed}s`;
    }, 1000);
}

function stopWaitingTimer() {
    clearInterval(waitingTimerInterval);
    waitingTimerInterval = null;
    waitingIndicator.style.display = 'none';
}

// ── Button State Management ───────────────────────────────────

function setButtonInvestigating(active) {
    isInvestigating = active;
    if (active) {
        submitBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="currentColor" stroke="none" width="18" height="18">
                <rect x="6" y="6" width="12" height="12" rx="2"/>
            </svg>
            <span>停止调查</span>`;
        submitBtn.classList.add('stop-mode');
        submitBtn.disabled = false;
        submitBtn.onclick = stopInvestigation;
    } else {
        submitBtn.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M22 2L11 13M22 2l-7 20-4-9-9-4 20-7z"/>
            </svg>
            <span>开始调查</span>`;
        submitBtn.classList.remove('stop-mode');
        submitBtn.disabled = false;
        submitBtn.onclick = startInvestigation;
    }
}

function stopInvestigation() {
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }
    stopWaitingTimer();
    setStatus('done', 'STOPPED');
    setButtonInvestigating(false);
    addTimelineItem('System', 'Stopped', '⏹ 调查已被用户手动停止', currentIteration);
}


// ── Main Entry Point ──────────────────────────────────────────

function startInvestigation() {
    const question = questionInput.value.trim();
    if (!question) return;

    // Reset UI
    timeline.innerHTML = '';
    reportContent.innerHTML = '';
    reportContainer.style.display = 'none';
    currentIteration = 0;
    iterationBadge.textContent = 'Iteration: 0';
    lastAgent = '';

    // Reset attack graph
    AttackGraph.reset();

    // Show pipeline
    pipeline.style.display = 'block';
    timelineContainer.style.display = 'block';
    setStatus('active', 'INVESTIGATING');
    resetPipeline();
    setButtonInvestigating(true);

    // Determine deep thinking mode
    const deepThinking = deepThinkingCb.checked;

    // Start waiting timer for Coordinator
    startWaitingTimer('Coordinator');

    // Build URL with deep_thinking param
    const params = new URLSearchParams({
        question: question,
        deep_thinking: deepThinking.toString(),
    });

    // Close any existing connection
    if (eventSource) {
        eventSource.close();
        eventSource = null;
    }

    eventSource = new EventSource(`/api/investigate?${params.toString()}`);

    eventSource.addEventListener('start', (e) => {
        const data = JSON.parse(e.data);
        console.log('Investigation started:', data.investigation_id);
        if (data.deep_thinking) {
            addTimelineItem('System', '🧠 Mode', '深度思考模式已启用', 0);
        }
    });

    eventSource.addEventListener('agent_message', (e) => {
        const msg = JSON.parse(e.data);
        handleAgentMessage(msg);
    });

    eventSource.addEventListener('graph_update', (e) => {
        const data = JSON.parse(e.data);
        console.log('Graph update:', data.nodes?.length, 'nodes,', data.edges?.length, 'edges');
        AttackGraph.addData(data);
    });

    eventSource.addEventListener('report', (e) => {
        const data = JSON.parse(e.data);
        stopWaitingTimer();
        displayReport(data.report);
    });

    eventSource.addEventListener('error', (e) => {
        if (e.data) {
            const data = JSON.parse(e.data);
            stopWaitingTimer();
            addTimelineItem('System', 'Error', `**Error**: ${data.error}`, 0);
        }
    });

    eventSource.addEventListener('done', () => {
        stopWaitingTimer();
        setStatus('done', 'COMPLETE');
        setButtonInvestigating(false);
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    });

    eventSource.onerror = () => {
        stopWaitingTimer();
        setStatus('done', 'ERROR');
        setButtonInvestigating(false);
        if (eventSource) {
            eventSource.close();
            eventSource = null;
        }
    };
}


// ── Handle Agent Messages ─────────────────────────────────────

function handleAgentMessage(msg) {
    const agent = msg.agent || 'Unknown';
    const action = msg.action || '';
    const content = msg.content || '';
    const iteration = msg.iteration || 0;

    // Stop current waiting timer
    stopWaitingTimer();

    // Update iteration
    if (iteration > currentIteration) {
        currentIteration = iteration;
        iterationBadge.textContent = `Iteration: ${currentIteration}`;
    }

    // Highlight pipeline node
    highlightPipelineNode(agent);

    // Add to timeline
    addTimelineItem(agent, action, content, iteration);

    // Track last agent and start waiting for next
    lastAgent = agent;
    const nextAgent = predictNextAgent(agent, action);
    if (nextAgent) {
        startWaitingTimer(nextAgent);
    }
}


function predictNextAgent(currentAgent, action) {
    if (action && action.includes('Skipped')) return 'Reporter';
    switch (currentAgent) {
        case 'Coordinator': return 'Planner';
        case 'Planner':
            if (action && action.includes('done')) return 'Reporter';
            return 'Retriever';
        case 'Retriever':
            if (action && action.includes('Parallel Execution')) return null;
            return 'Analyzer';
        case 'Analyzer': return 'Planner';
        case 'Reporter': return null;
        default: return null;
    }
}


// ── Timeline ──────────────────────────────────────────────────

function addTimelineItem(agent, action, content, iteration) {
    const item = document.createElement('div');
    item.className = 'timeline-item';
    item.setAttribute('data-agent', agent);

    let rendered = content
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/\n/g, '<br>');

    item.innerHTML = `
        <div class="timeline-header">
            <span class="agent-badge" data-agent="${agent}">${agent}</span>
            <span class="action-label">${action}</span>
            <span class="iteration-label">iter ${iteration}</span>
        </div>
        <div class="timeline-body">${rendered}</div>
    `;

    timeline.appendChild(item);
    item.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


// ── Pipeline ──────────────────────────────────────────────────

function resetPipeline() {
    document.querySelectorAll('.pipeline-node').forEach(n => {
        n.classList.remove('active', 'completed');
    });
}

function highlightPipelineNode(agent) {
    const nodes = ['Coordinator', 'Planner', 'Retriever', 'Analyzer', 'Reporter'];
    const index = nodes.indexOf(agent);

    document.querySelectorAll('.pipeline-node').forEach(n => {
        n.classList.remove('active');
    });

    if (index >= 0) {
        const pipeNode = document.getElementById(`pipe${agent}`);
        if (pipeNode) {
            pipeNode.classList.add('active');
            pipeNode.classList.remove('completed');
        }
        for (let i = 0; i < index; i++) {
            const prev = document.getElementById(`pipe${nodes[i]}`);
            if (prev) prev.classList.add('completed');
        }
    }
}


// ── Status ────────────────────────────────────────────────────

function setStatus(cls, text) {
    statusIndicator.className = `status-indicator ${cls}`;
    statusIndicator.querySelector('.status-text').textContent = text;
}


// ── Report Display ────────────────────────────────────────────

function displayReport(markdown) {
    reportContainer.style.display = 'block';

    let html = markdown
        .replace(/^### (.*)$/gm, '<h3>$1</h3>')
        .replace(/^## (.*)$/gm, '<h2>$1</h2>')
        .replace(/^# (.*)$/gm, '<h1>$1</h1>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`([^`]+)`/g, '<code>$1</code>')
        .replace(/^\- (.*)$/gm, '<li>$1</li>')
        .replace(/^\d+\. (.*)$/gm, '<li>$1</li>')
        .replace(/\n{2,}/g, '</p><p>')
        .replace(/\n/g, '<br>');

    html = html.replace(/(<li>.*?<\/li>(\s*<br>)*)+/g, (match) => {
        return '<ul>' + match.replace(/<br>/g, '') + '</ul>';
    });

    reportContent.innerHTML = `<p>${html}</p>`;
    reportContainer.scrollIntoView({ behavior: 'smooth', block: 'start' });
}
