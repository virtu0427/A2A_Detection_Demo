const severityMap = {
  '높음': 'high',
  '중간': 'medium',
  '낮음': 'low'
};

let liveEvents = [];
let showOnlyCritical = false;
let severityChart;
let layerChart;
let trendChart;
let alertHistory = [];
let alertStreamStarted = false;
let alertsInitialized = false;
let mainAgentNetwork;
let agentDetailNetwork;

function formatTimestamp(value) {
  if (!value) return '-';
  return value.replace('T', ' ');
}

function setupNavigation() {
  const nav = document.querySelector('.side-nav');
  const toggle = document.querySelector('.nav-toggle');
  const close = document.querySelector('.side-nav-close');

  if (!nav || !toggle) return;

  const setState = (state) => {
    nav.dataset.state = state;
    document.body.dataset.navState = state;
  };

  const expand = () => {
    setState('expanded');
  };

  const collapse = () => {
    setState('collapsed');
  };

  toggle.addEventListener('click', () => {
    if (nav.dataset.state === 'expanded') {
      collapse();
    } else {
      expand();
    }
  });

  if (close) {
    close.addEventListener('click', collapse);
  }

  document.addEventListener('click', (event) => {
    if (window.innerWidth >= 1180) return;
    if (nav.dataset.state !== 'expanded') return;
    if (nav.contains(event.target) || toggle.contains(event.target)) return;
    collapse();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      collapse();
    }
  });

  const handleResize = () => {
    if (window.innerWidth >= 1180) {
      expand();
    } else if (window.innerWidth < 1024) {
      collapse();
    }
  };

  window.addEventListener('resize', handleResize);
  handleResize();
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
    const card = document.createElement('a');
    card.className = 'live-card';
    card.href = `/alerts/${event.id}`;
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

function renderAlertBar() {
  const bar = document.querySelector('.alert-bar');
  const track = document.querySelector('.alert-track');
  if (!bar || !track) return;

  track.innerHTML = '';
  if (!alertHistory.length) {
    const empty = document.createElement('div');
    empty.className = 'alert-empty';
    empty.textContent = '최근 경보가 없습니다.';
    track.appendChild(empty);
    bar.classList.add('is-visible');
    return;
  }
  alertHistory.forEach((item) => {
    const link = document.createElement('a');
    link.className = `alert-item`;
    link.href = `/alerts/${item.id}`;
    link.title = `${item.threat_type} · ${item.source_agent} → ${item.target_agent}`;
    link.innerHTML = `
      <span class="badge ${severityMap[item.severity] || 'medium'}">${item.severity}</span>
      <span>${item.threat_type} · ${item.source_agent} → ${item.target_agent}</span>
    `;
    track.appendChild(link);
  });

  bar.classList.add('is-visible');
}

function updateAlertBar(event) {
  alertHistory = alertHistory.filter((item) => item.id !== event.id);
  alertHistory.unshift(event);
  if (alertHistory.length > 3) {
    alertHistory = alertHistory.slice(0, 3);
  }
  renderAlertBar();
}

function bindAlertBarClose() {
  const bar = document.querySelector('.alert-bar');
  const close = document.querySelector('.alert-close');
  if (!bar || !close) return;
  close.addEventListener('click', () => {
    bar.classList.remove('is-visible');
  });
}

async function loadOverviewMetrics() {
  const res = await fetch('/api/overview');
  if (!res.ok) return;
  const data = await res.json();

  const agentCount = document.getElementById('metric-agent-count');
  if (agentCount) agentCount.textContent = data.agent_count ?? '-';

  const highThreats = document.getElementById('metric-high-threats');
  if (highThreats) highThreats.textContent = data.high_threats ?? '-';

  const activeLinks = document.getElementById('metric-active-links');
  if (activeLinks) activeLinks.textContent = data.communication_count ?? '-';

  const lastUpdate = document.getElementById('metric-last-update');
  if (lastUpdate) lastUpdate.textContent = data.last_update ? formatTimestamp(data.last_update) : '-';

  const totalPackets = document.getElementById('metric-total-packets');
  if (totalPackets) totalPackets.textContent = data.total_packets ?? '-';

  const severityCounts = data.severity_counts || {};
  const highMetric = document.getElementById('metric-severity-high');
  if (highMetric) highMetric.textContent = severityCounts['높음'] ?? '0';
  const mediumMetric = document.getElementById('metric-severity-medium');
  if (mediumMetric) mediumMetric.textContent = severityCounts['중간'] ?? '0';
  const lowMetric = document.getElementById('metric-severity-low');
  if (lowMetric) lowMetric.textContent = severityCounts['낮음'] ?? '0';

  renderSeverityChart(severityCounts);
  renderLayerChart(data.layer_counts || {});
  renderPersistentList(data.persistent_agents || []);
  renderTrendChart(data.threat_trend || []);
}

function renderSeverityChart(severityCounts) {
  const ctx = document.getElementById('severity-chart');
  if (!ctx) return;
  const labels = ['높음', '중간', '낮음'];
  const values = labels.map((label) => severityCounts[label] || 0);

  if (severityChart) {
    severityChart.data.datasets[0].data = values;
    severityChart.update();
    return;
  }

  severityChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: ['rgba(239,68,68,0.6)', 'rgba(249,115,22,0.6)', 'rgba(34,197,94,0.6)'],
          borderWidth: 1,
          borderColor: 'rgba(15,23,42,0.6)'
        }
      ]
    },
    options: {
      plugins: {
        legend: { position: 'bottom', labels: { color: '#cbd5f5' } }
      }
    }
  });
}

function renderLayerChart(layerCounts) {
  const ctx = document.getElementById('layer-chart');
  if (!ctx) return;
  const labels = Object.keys(layerCounts);
  const values = labels.map((key) => layerCounts[key]);

  if (layerChart) {
    layerChart.data.labels = labels;
    layerChart.data.datasets[0].data = values;
    layerChart.update();
    return;
  }

  layerChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: '탐지량',
          data: values,
          backgroundColor: 'rgba(56, 189, 248, 0.5)',
          borderColor: '#38bdf8',
          borderWidth: 1,
        }
      ]
    },
    options: {
      scales: {
        x: {
          ticks: { color: '#cbd5f5' },
          grid: { color: 'rgba(148, 163, 184, 0.12)' }
        },
        y: {
          ticks: { color: '#cbd5f5' },
          grid: { color: 'rgba(148, 163, 184, 0.12)' },
          beginAtZero: true,
        }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });
}

function renderTrendChart(trend = []) {
  const ctx = document.getElementById('trend-chart');
  if (!ctx) return;

  const wrapper = ctx.closest('.trend-chart-wrapper');
  let emptyState = wrapper ? wrapper.querySelector('.chart-empty') : null;

  if (!trend.length) {
    if (!emptyState && wrapper) {
      emptyState = document.createElement('p');
      emptyState.className = 'chart-empty';
      emptyState.textContent = '표시할 데이터가 없습니다.';
      wrapper.appendChild(emptyState);
    }
    if (trendChart) {
      trendChart.destroy();
      trendChart = null;
    }
    ctx.style.opacity = '0';
    return;
  }

  if (emptyState) {
    emptyState.remove();
  }

  ctx.style.opacity = '1';

  const labels = trend.map((item) => item.window_label || item.window);
  const values = trend.map((item) => item.count || 0);

  if (trendChart) {
    trendChart.data.labels = labels;
    trendChart.data.datasets[0].data = values;
    trendChart.update();
    return;
  }

  const context = ctx.getContext('2d');
  const gradient = context.createLinearGradient(0, 0, 0, ctx.height || ctx.clientHeight || 220);
  gradient.addColorStop(0, 'rgba(56, 189, 248, 0.35)');
  gradient.addColorStop(1, 'rgba(56, 189, 248, 0.02)');

  trendChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: '탐지 건수',
          data: values,
          borderColor: '#38bdf8',
          backgroundColor: gradient,
          pointBackgroundColor: '#38bdf8',
          pointBorderColor: '#0f172a',
          pointRadius: 4,
          fill: true,
          tension: 0.35,
        }
      ]
    },
    options: {
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: '#cbd5f5', maxRotation: 0, minRotation: 0 },
          grid: { display: false }
        },
        y: {
          beginAtZero: true,
          ticks: { color: '#cbd5f5' },
          grid: { color: 'rgba(148, 163, 184, 0.12)' }
        }
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: {
            label: (context) => `${context.parsed.y}건 탐지`
          }
        }
      }
    }
  });
}

function renderPersistentList(items) {
  const list = document.getElementById('persistent-list');
  if (!list) return;
  list.innerHTML = '';

  if (!items.length) {
    const li = document.createElement('li');
    li.className = 'empty-state';
    li.textContent = '지속 경보가 기록된 에이전트가 없습니다.';
    list.appendChild(li);
    return;
  }

  items.forEach((item) => {
    const li = document.createElement('li');
    li.className = 'persistent-item';
    li.innerHTML = `
      <div class="persistent-head">
        <strong>${item.agent_name}</strong>
        <span class="meta">최근 감지 ${formatTimestamp(item.last_detected)}</span>
      </div>
      <div class="persistent-body">
        <span class="meta">반복 ${item.repeat_count}회</span>
        <span class="meta">주요 위협 ${item.last_threat}</span>
      </div>
      <span class="persistent-link">상세 보기</span>
    `;
    if (item.agent_id) {
      const navigate = () => {
        window.location.href = `/agents/${item.agent_id}`;
      };
      li.setAttribute('role', 'link');
      li.tabIndex = 0;
      li.addEventListener('click', navigate);
      li.addEventListener('keypress', (event) => {
        if (event.key === 'Enter') {
          navigate();
        }
      });
    } else {
      li.classList.add('is-static');
    }
    list.appendChild(li);
  });
}

async function loadTimeline() {
  const res = await fetch('/api/packets/recent');
  if (!res.ok) return;
  const data = await res.json();
  const timeline = document.getElementById('timeline-list');
  if (!timeline) return;

  timeline.innerHTML = '';
  if (!data.packets.length) {
    const li = document.createElement('li');
    li.className = 'empty-state';
    li.textContent = '최근 저장된 패킷이 없습니다.';
    timeline.appendChild(li);
    return;
  }

  data.packets.forEach((packet) => {
    const item = document.createElement('li');
    item.className = `timeline-item severity-${severityMap[packet.severity] || 'medium'}`;
    item.innerHTML = `
      <a href="/packets/${packet.id}">
        <div class="timeline-header">
          <strong>${packet.threat_type}</strong>
          <span class="badge ${severityMap[packet.severity] || 'medium'}">${packet.severity}</span>
        </div>
        <p class="meta">${formatTimestamp(packet.timestamp)} · ${packet.protocol_layer}</p>
        <p class="meta">${packet.source_agent} → ${packet.target_agent}</p>
        <p>${packet.description}</p>
      </a>
    `;
    timeline.appendChild(item);
  });
}

async function loadInitialAlerts() {
  if (alertsInitialized) {
    renderAlertBar();
    return;
  }
  try {
    const res = await fetch('/api/alerts/recent');
    if (!res.ok) return;
    const data = await res.json();
    if (!Array.isArray(data.alerts)) return;

    liveEvents = data.alerts.slice(0, 12);
    renderLiveFeed();

    alertHistory = data.alerts.slice(0, 3);
  } finally {
    alertsInitialized = true;
    renderAlertBar();
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
  if (alertStreamStarted || typeof EventSource === 'undefined') return;
  alertStreamStarted = true;
  const source = new EventSource('/stream');
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    appendLiveEvent(payload);
    updateAlertBar(payload);
    loadOverviewMetrics();
  };
  source.onerror = () => {
    source.close();
    alertStreamStarted = false;
    setTimeout(startEventStream, 5000);
  };
}

async function searchPackets(event) {
  if (event) event.preventDefault();
  const form = document.getElementById('packet-filter');
  if (!form) return;

  const formData = new FormData(form);
  const params = new URLSearchParams();
  for (const [key, value] of formData.entries()) {
    if (value) params.append(key, value);
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
    row.dataset.link = `/packets/${packet.id}`;
    row.innerHTML = `
      <td>${formatTimestamp(packet.timestamp)}</td>
      <td>${packet.source_agent}</td>
      <td>${packet.target_agent}</td>
      <td>${packet.protocol_layer}</td>
      <td>${packet.threat_type}</td>
      <td><span class="badge ${severityMap[packet.severity] || 'medium'}">${packet.severity}</span></td>
      <td>${packet.description}<br/><span class="meta">대응: ${packet.resolution}</span></td>
    `;
    row.addEventListener('click', () => {
      window.location.href = row.dataset.link;
    });
    tbody.appendChild(row);
  });
}

function bindQuickFilters() {
  const chips = document.querySelectorAll('.quick-filters .chip');
  const form = document.getElementById('packet-filter');
  if (!chips.length || !form) return;

  chips.forEach((chip) => {
    chip.addEventListener('click', () => {
      if (chip.dataset.reset !== undefined) {
        form.reset();
      } else if (chip.dataset.severity) {
        form.querySelector('select[name="severity"]').value = chip.dataset.severity;
      }
      searchPackets();
    });
  });
}

function initDashboard() {
  loadOverviewMetrics();
  loadTimeline();

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
      borderWidth: 2,
      font: {
        color: '#f8fafc',
        face: 'Noto Sans KR',
        size: 16,
        strokeWidth: 3,
        strokeColor: '#0f172a'
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
        align: 'top',
        size: 12,
        face: 'Noto Sans KR',
        background: 'rgba(15, 23, 42, 0.75)'
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
        solver: 'barnesHut',
        stabilization: { iterations: 250 },
        barnesHut: {
          gravitationalConstant: -3200,
          centralGravity: 0.2,
          springConstant: 0.04,
          springLength: 180,
        }
      },
      interaction: {
        hover: true,
        tooltipDelay: 120,
        zoomView: true,
        minZoom: 0.45,
        maxZoom: 1.6
      },
      edges: {
        smooth: {
          type: 'continuous',
          roundness: 0.18
        }
      },
      nodes: {
        shape: 'dot',
        size: 22
      },
      layout: {
        improvedLayout: true
      }
    }
  );

  mainAgentNetwork = network;

  const resetButton = document.getElementById('btn-reset-graph');
  if (resetButton) {
    resetButton.onclick = () => {
      if (!mainAgentNetwork) return;
      mainAgentNetwork.fit({ animation: { duration: 400, easing: 'easeInOutQuad' } });
    };
  }

  network.once('stabilized', () => {
    network.fit({ animation: false });
  });

  const detailPanel = document.getElementById('agent-detail');
  if (detailPanel) {
    detailPanel.innerHTML = '그래프에서 노드 또는 간선을 선택해 세부 정보를 확인하세요.';
  }

  network.on('click', (params) => {
    if (!detailPanel) return;
    if (params.nodes.length > 0) {
      const agentId = params.nodes[0];
      const agent = data.agents.find((item) => item.id === agentId);
      if (!agent) return;
      const statusClass = {
        '정상': 'status-normal',
        '주의': 'status-warning',
        '격리': 'status-critical'
      }[agent.status] || 'status-normal';
      detailPanel.innerHTML = `
        <h4>${agent.name}</h4>
        <p class="meta">역할: ${agent.role}</p>
        <p class="meta">상태: <span class="status-indicator"><span class="status-dot ${statusClass}"></span>${agent.status}</span></p>
        <p class="meta">위험 점수: ${(agent.risk_score * 100).toFixed(1)}%</p>
        <p class="meta">최근 활동: ${formatTimestamp(agent.last_seen)}</p>
        <p><a href="/agents/${agent.id}">상세 페이지 이동</a></p>
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

function initPackets() {
  loadOverviewMetrics();
  bindQuickFilters();
  const form = document.getElementById('packet-filter');
  if (form) {
    form.addEventListener('submit', searchPackets);
    searchPackets();
  }
}

function initAgentDetail() {
  const payload = window.agentDetailData;
  if (!payload) return;

  const container = document.getElementById('agent-detail-graph');
  if (!container || typeof vis === 'undefined') return;

  const nodes = new vis.DataSet();
  nodes.add({
    id: payload.agentId,
    label: payload.name,
    color: { background: '#0f172a', border: '#38bdf8' },
    font: { color: '#f8fafc' }
  });

  payload.relatedAgents.forEach((agent) => {
    nodes.add({
      id: agent.id,
      label: agent.name,
      color: { background: '#111b31', border: '#4f83d9' },
      font: { color: '#e2e8f0' }
    });
  });

  const edges = new vis.DataSet();
  payload.communications.forEach((comm) => {
    const from = comm.source === payload.name ? payload.agentId : payload.relatedAgents.find((item) => item.name === comm.source)?.id;
    const to = comm.target === payload.name ? payload.agentId : payload.relatedAgents.find((item) => item.name === comm.target)?.id;
    if (from && to) {
      edges.add({
        from,
        to,
        label: comm.summary,
        arrows: 'to',
        color: { color: 'rgba(56, 189, 248, 0.5)', highlight: '#38bdf8' },
        font: { color: '#94a3b8', face: 'Noto Sans KR', size: 11, background: 'rgba(15, 23, 42, 0.72)' }
      });
    }
  });

  agentDetailNetwork = new vis.Network(container, { nodes, edges }, {
    physics: {
      enabled: true,
      solver: 'barnesHut',
      stabilization: { iterations: 200 },
      barnesHut: { gravitationalConstant: -2800, springLength: 160 }
    },
    interaction: { hover: true, tooltipDelay: 100, zoomView: true, minZoom: 0.5, maxZoom: 1.6 },
    nodes: {
      shape: 'dot',
      size: 20,
      font: { color: '#f8fafc', size: 14, face: 'Noto Sans KR', strokeWidth: 2, strokeColor: '#0f172a' },
      borderWidth: 2,
      color: { background: '#0f172a', border: '#38bdf8' }
    },
    edges: { smooth: { type: 'continuous', roundness: 0.2 } }
  });

  agentDetailNetwork.once('stabilized', () => {
    agentDetailNetwork.fit({ animation: false });
  });

  const resetButton = document.getElementById('btn-reset-agent-graph');
  if (resetButton) {
    resetButton.onclick = () => {
      if (!agentDetailNetwork) return;
      agentDetailNetwork.fit({ animation: { duration: 400, easing: 'easeInOutQuad' } });
    };
  }
}

function initPage() {
  setupNavigation();
  bindAlertBarClose();
  loadInitialAlerts();
  startEventStream();

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
  if (page === 'agent-detail') {
    initAgentDetail();
  }
}

document.addEventListener('DOMContentLoaded', initPage);
