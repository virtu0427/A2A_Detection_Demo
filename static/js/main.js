const severityMap = {
  '높음': 'high',
  '중간': 'medium',
  '낮음': 'low'
};

const statusColorMap = {
  '정상': 'status-normal',
  '주의': 'status-warning',
  '격리': 'status-critical'
};

let liveEvents = [];
let showOnlyCritical = false;

function formatTimestamp(value) {
  if (!value) return '-';
  return value.replace('T', ' ');
}

function createToast(event) {
  const container = document.querySelector('.toast-container');
  if (!container) return;
  const toast = document.createElement('div');
  toast.className = `toast severity-${severityMap[event.severity] || 'medium'}`;
  toast.innerHTML = `
    <strong>${event.threat_type || '실시간 경보'} · ${event.severity}</strong>
    <p>${formatTimestamp(event.timestamp)}<br />
    ${event.source_agent} → ${event.target_agent}<br />
    ${event.description}</p>
  `;
  container.appendChild(toast);
  setTimeout(() => toast.remove(), 8000);
}

function renderLiveFeed() {
  const container = document.getElementById('live-feed');
  if (!container) return;
  container.innerHTML = '';

  const filtered = showOnlyCritical
    ? liveEvents.filter((event) => event.severity === '높음')
    : liveEvents;

  if (filtered.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.textContent = showOnlyCritical
      ? '고위험 이벤트가 아직 도착하지 않았습니다.'
      : '수집된 실시간 이벤트가 없습니다. 잠시 후 다시 확인하세요.';
    container.appendChild(empty);
    return;
  }

  filtered.forEach((event) => {
    const card = document.createElement('article');
    card.className = 'live-card';
    card.innerHTML = `
      <header>
        <span class="badge ${severityMap[event.severity] || 'medium'}">${event.severity}</span>
        <time>${formatTimestamp(event.timestamp)}</time>
      </header>
      <h4>${event.threat_type}</h4>
      <p class="meta">${event.source_agent} → ${event.target_agent} · ${event.protocol_layer || 'Layer ?'}</p>
      <p>${event.description}</p>
    `;
    container.appendChild(card);
  });
}

async function loadOverviewMetrics() {
  const res = await fetch('/api/overview');
  if (!res.ok) return;
  const data = await res.json();

  const agentCount = document.getElementById('metric-agent-count');
  if (agentCount) {
    agentCount.textContent = data.agent_count ?? '-';
  }

  const highThreats = document.getElementById('metric-high-threats');
  if (highThreats) {
    highThreats.textContent = data.high_threats ?? '-';
  }

  const activeLinks = document.getElementById('metric-active-links');
  if (activeLinks) {
    activeLinks.textContent = data.communication_count ?? '-';
  }

  const lastUpdate = document.getElementById('metric-last-update');
  if (lastUpdate) {
    lastUpdate.textContent = data.last_update ? formatTimestamp(data.last_update) : '-';
  }

  const totalPackets = document.getElementById('metric-total-packets');
  if (totalPackets) {
    totalPackets.textContent = data.total_packets ?? '-';
  }

  const severityCounts = data.severity_counts || {};
  const highMetric = document.getElementById('metric-severity-high');
  if (highMetric) highMetric.textContent = severityCounts['높음'] ?? '0';
  const mediumMetric = document.getElementById('metric-severity-medium');
  if (mediumMetric) mediumMetric.textContent = severityCounts['중간'] ?? '0';
  const lowMetric = document.getElementById('metric-severity-low');
  if (lowMetric) lowMetric.textContent = severityCounts['낮음'] ?? '0';
}

async function loadTimeline() {
  const res = await fetch('/api/packets/recent');
  if (!res.ok) return;
  const data = await res.json();
  const timeline = document.getElementById('timeline-list');
  if (!timeline) return;

  timeline.innerHTML = '';
  data.packets.forEach((packet) => {
    const item = document.createElement('li');
    item.className = `timeline-item severity-${severityMap[packet.severity] || 'medium'}`;
    item.innerHTML = `
      <div class="timeline-marker"></div>
      <div class="timeline-content">
        <div class="timeline-header">
          <strong>${packet.threat_type}</strong>
          <span class="badge ${severityMap[packet.severity] || 'medium'}">${packet.severity}</span>
        </div>
        <p class="meta">${formatTimestamp(packet.timestamp)} · ${packet.protocol_layer}</p>
        <p class="meta">${packet.source_agent} → ${packet.target_agent}</p>
        <p>${packet.description}</p>
      </div>
    `;
    timeline.appendChild(item);
  });

  // 초기 실시간 카드 데이터가 없다면 타임라인으로 초기화
  if (liveEvents.length === 0) {
    liveEvents = data.packets.slice(0, 6);
    renderLiveFeed();
  }
}

function appendLiveEvent(event) {
  liveEvents.unshift(event);
  if (liveEvents.length > 30) {
    liveEvents = liveEvents.slice(0, 30);
  }
  renderLiveFeed();
}

function startEventStream() {
  const source = new EventSource('/stream');
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    appendLiveEvent(payload);
    createToast(payload);
    loadOverviewMetrics();
  };
}

async function loadAgentGraph() {
  const res = await fetch('/api/agents');
  if (!res.ok) return;
  const data = await res.json();
  const container = document.getElementById('graph-container');
  if (!container) return;

  const nodes = new vis.DataSet(
    data.nodes.map((node) => ({
      ...node,
      color: {
        background: 'rgba(15, 23, 42, 0.95)',
        border: '#38bdf8',
        highlight: {
          background: '#0f172a',
          border: '#0ea5e9'
        }
      },
      font: {
        color: '#f8fafc'
      }
    }))
  );

  const edges = new vis.DataSet(
    data.edges.map((edge) => ({
      ...edge,
      color: {
        color: 'rgba(56, 189, 248, 0.45)',
        highlight: '#38bdf8'
      },
      font: {
        color: '#94a3b8',
        align: 'middle'
      },
      arrows: 'to'
    }))
  );

  const network = new vis.Network(
    container,
    { nodes, edges },
    {
      physics: {
        enabled: true,
        stabilization: { iterations: 200 },
        solver: 'forceAtlas2Based'
      },
      interaction: {
        hover: true,
        tooltipDelay: 120,
        zoomView: true
      },
      edges: {
        smooth: true
      },
      nodes: {
        shape: 'dot',
        size: 22
      }
    }
  );

  const detailPanel = document.getElementById('agent-detail');

  network.on('click', (params) => {
    if (!detailPanel) return;
    if (params.nodes.length > 0) {
      const agentId = params.nodes[0];
      const agent = data.agents.find((item) => item.id === agentId);
      if (!agent) return;
      const statusClass = statusColorMap[agent.status] || 'status-normal';
      detailPanel.innerHTML = `
        <h4>${agent.name}</h4>
        <p class="meta">역할: ${agent.role}</p>
        <p class="meta">상태: <span class="status-indicator"><span class="status-dot ${statusClass}"></span>${agent.status}</span></p>
        <p class="meta">위험 점수: ${(agent.risk_score * 100).toFixed(1)}%</p>
        <p class="meta">최근 활동: ${formatTimestamp(agent.last_seen)}</p>
      `;
    }
  });

  network.on('selectEdge', (params) => {
    if (!detailPanel) return;
    if (params.edges.length > 0) {
      const edgeId = params.edges[0];
      const edge = edges.get(edgeId);
      const fromLabel = nodes.get(edge.from).label;
      const toLabel = nodes.get(edge.to).label;
      detailPanel.innerHTML = `
        <h4>통신 세부 정보</h4>
        <p class="meta">연결: ${fromLabel} → ${toLabel}</p>
        <p class="meta">메시지: ${edge.label}</p>
      `;
    }
  });

  renderCommunicationList(data.communications);
}

function renderCommunicationList(communications = []) {
  const list = document.getElementById('communication-list');
  if (!list) return;
  list.innerHTML = '';

  if (communications.length === 0) {
    const li = document.createElement('li');
    li.className = 'empty-state';
    li.textContent = '표시할 통신 로그가 없습니다.';
    list.appendChild(li);
    return;
  }

  communications.forEach((comm) => {
    const li = document.createElement('li');
    li.innerHTML = `
      <div class="comm-header">
        <strong>${comm.source}</strong>
        <span class="icon-arrow">→</span>
        <strong>${comm.target}</strong>
      </div>
      <p class="meta">${formatTimestamp(comm.last_activity)}</p>
      <p>${comm.threat_summary}</p>
    `;
    list.appendChild(li);
  });
}

async function refreshCommunications() {
  const res = await fetch('/api/agents');
  if (!res.ok) return;
  const data = await res.json();
  renderCommunicationList(data.communications);
}

async function searchPackets(event) {
  if (event) event.preventDefault();
  const form = document.getElementById('packet-filter');
  if (!form) return;

  const formData = new FormData(form);
  const params = new URLSearchParams();
  for (const [key, value] of formData.entries()) {
    if (value) {
      params.append(key, value);
    }
  }

  const res = await fetch(`/api/packets?${params.toString()}`);
  if (!res.ok) return;
  const data = await res.json();
  const tbody = document.querySelector('#packet-table tbody');
  if (!tbody) return;

  tbody.innerHTML = '';
  if (data.packets.length === 0) {
    const row = document.createElement('tr');
    row.innerHTML = '<td colspan="7" class="empty">조건에 맞는 패킷이 없습니다.</td>';
    tbody.appendChild(row);
    return;
  }

  data.packets.forEach((packet) => {
    const row = document.createElement('tr');
    const severityClass = severityMap[packet.severity] || 'medium';
    row.innerHTML = `
      <td>${formatTimestamp(packet.timestamp)}</td>
      <td>${packet.source_agent}</td>
      <td>${packet.target_agent}</td>
      <td>${packet.protocol_layer}</td>
      <td>${packet.threat_type}</td>
      <td><span class="badge ${severityClass}">${packet.severity}</span></td>
      <td>${packet.description}<br/><span class="meta">대응: ${packet.resolution}</span></td>
    `;
    tbody.appendChild(row);
  });
}

function bindQuickFilters() {
  const chips = document.querySelectorAll('.quick-filters .chip');
  const form = document.getElementById('packet-filter');
  if (!chips.length || !form) return;

  chips.forEach((chip) => {
    chip.addEventListener('click', () => {
      const severitySelect = form.querySelector('select[name="severity"]');
      if (chip.dataset.reset !== undefined) {
        form.reset();
      } else if (chip.dataset.severity) {
        severitySelect.value = chip.dataset.severity;
      }
      searchPackets();
    });
  });
}

function initDashboard() {
  loadOverviewMetrics();
  loadTimeline();
  startEventStream();

  const toggle = document.getElementById('toggle-critical');
  if (toggle) {
    toggle.addEventListener('change', (event) => {
      showOnlyCritical = event.target.checked;
      renderLiveFeed();
    });
  }

  const refresh = document.getElementById('btn-refresh-overview');
  if (refresh) {
    refresh.addEventListener('click', () => {
      loadOverviewMetrics();
      loadTimeline();
    });
  }
}

function initGraph() {
  loadAgentGraph();
  const refreshButton = document.getElementById('btn-refresh-communications');
  if (refreshButton) {
    refreshButton.addEventListener('click', refreshCommunications);
  }
}

function initPackets() {
  loadOverviewMetrics();
  bindQuickFilters();
  const form = document.getElementById('packet-filter');
  if (form) {
    form.addEventListener('submit', searchPackets);
    searchPackets();
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const page = document.body.dataset.page;
  if (page === 'dashboard') {
    initDashboard();
  }
  if (page === 'graph') {
    initGraph();
  }
  if (page === 'packets') {
    initPackets();
  }
});
