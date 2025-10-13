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

const toastContainer = document.querySelector('.toast-container');

function createToast(event) {
  if (!toastContainer) return;
  const toast = document.createElement('div');
  toast.className = 'toast';
  toast.innerHTML = `
    <strong>실시간 경보 · ${event.severity}</strong>
    <p>${event.timestamp.replace('T', ' ')}<br/>
    ${event.source_agent} → ${event.target_agent}<br/>
    ${event.description}</p>
  `;
  toastContainer.appendChild(toast);
  setTimeout(() => toast.remove(), 8000);
}

async function loadRecentPackets() {
  const res = await fetch('/api/packets/recent');
  const data = await res.json();
  const logList = document.querySelector('.log-list');
  logList.innerHTML = '';

  data.packets.forEach((packet) => {
    const card = document.createElement('div');
    card.className = 'log-card';
    const severityClass = severityMap[packet.severity] || 'medium';

    card.innerHTML = `
      <div class="log-header">
        <strong>${packet.threat_type}</strong>
        <span class="tag ${severityClass}">${packet.severity}</span>
      </div>
      <div class="log-meta">${packet.timestamp.replace('T', ' ')} · ${packet.protocol_layer}</div>
      <div class="log-meta">${packet.source_agent} → ${packet.target_agent}</div>
      <p>${packet.description}</p>
      <div class="log-meta">대응: ${packet.resolution}</div>
    `;

    logList.appendChild(card);
  });
}

async function loadAgentGraph() {
  const res = await fetch('/api/agents');
  const data = await res.json();
  const container = document.getElementById('graph-container');

  const nodes = new vis.DataSet(data.nodes.map((node) => ({
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
  })));

  const edges = new vis.DataSet(data.edges.map((edge) => ({
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
  })));

  const network = new vis.Network(container, { nodes, edges }, {
    physics: {
      enabled: true,
      stabilization: { iterations: 200 },
      solver: 'forceAtlas2Based'
    },
    interaction: {
      hover: true,
      tooltipDelay: 100,
      zoomView: true
    },
    edges: {
      smooth: true
    },
    nodes: {
      shape: 'dot',
      size: 22
    }
  });

  network.on('click', (params) => {
    if (params.nodes.length > 0) {
      const agentId = params.nodes[0];
      const agent = data.agents.find((item) => item.id === agentId);
      if (!agent) return;
      const statusClass = statusColorMap[agent.status] || 'status-normal';
      const panel = document.querySelector('#agent-detail');
      panel.innerHTML = `
        <h3>${agent.name}</h3>
        <p class="subtext">역할: ${agent.role}</p>
        <p class="subtext">상태: <span class="status-indicator"><span class="status-dot ${statusClass}"></span>${agent.status}</span></p>
        <p class="subtext">위험 점수: ${(agent.risk_score * 100).toFixed(1)}%</p>
        <p class="subtext">최근 활동: ${agent.last_seen.replace('T', ' ')}</p>
      `;
    }
  });

  network.on('selectEdge', (params) => {
    if (params.edges.length > 0) {
      const edgeId = params.edges[0];
      const edge = edges.get(edgeId);
      const panel = document.querySelector('#agent-detail');
      panel.innerHTML = `
        <h3>통신 세부 정보</h3>
        <p class="subtext">${edge.label}</p>
        <p class="subtext">연결: ${nodes.get(edge.from).label} → ${nodes.get(edge.to).label}</p>
      `;
    }
  });
}

async function searchPackets(event) {
  event.preventDefault();
  const form = event.target;
  const params = new URLSearchParams(new FormData(form));
  const res = await fetch(`/api/packets?${params.toString()}`);
  const data = await res.json();

  const tbody = document.querySelector('#packet-table tbody');
  tbody.innerHTML = '';

  if (data.packets.length === 0) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 7;
    cell.textContent = '조건에 맞는 패킷이 없습니다.';
    cell.style.textAlign = 'center';
    row.appendChild(cell);
    tbody.appendChild(row);
    return;
  }

  data.packets.forEach((packet) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${packet.timestamp.replace('T', ' ')}</td>
      <td>${packet.source_agent}</td>
      <td>${packet.target_agent}</td>
      <td>${packet.protocol_layer}</td>
      <td>${packet.threat_type}</td>
      <td>${packet.severity}</td>
      <td>${packet.description}</td>
    `;
    tbody.appendChild(row);
  });
}

function startEventStream() {
  const source = new EventSource('/stream');
  source.onmessage = (event) => {
    const payload = JSON.parse(event.data);
    createToast(payload);
    loadRecentPackets();
  };
}

document.addEventListener('DOMContentLoaded', () => {
  loadRecentPackets();
  loadAgentGraph();
  startEventStream();

  document.querySelector('.filter-form').addEventListener('submit', searchPackets);
});
