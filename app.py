import json
import os
import queue
import random
import sqlite3
import threading
import time
from datetime import datetime, timedelta

from flask import Flask, Response, jsonify, redirect, render_template, request, url_for

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "a2a_demo.db")

app = Flask(__name__)

event_queue: "queue.Queue[dict]" = queue.Queue(maxsize=100)
event_thread_started = False


@app.context_processor
def inject_branding():
    now = datetime.utcnow()
    return {
        "branding": {
            "team": "BOB14기 Attager Team",
            "solution": "A2A Multi-Agent 위협 탐지 센터",
            "tagline": "Agent-to-Agent 보안 흐름을 지키는 실시간 관제",
            "build_date": now.strftime("%Y.%m.%d"),
            "year": now.year,
        }
    }

def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS agents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            role TEXT NOT NULL,
            status TEXT NOT NULL,
            risk_score REAL NOT NULL,
            last_seen TEXT NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS communications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_agent_id INTEGER NOT NULL,
            target_agent_id INTEGER NOT NULL,
            last_activity TEXT NOT NULL,
            threat_summary TEXT,
            FOREIGN KEY (source_agent_id) REFERENCES agents (id),
            FOREIGN KEY (target_agent_id) REFERENCES agents (id)
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_agent TEXT NOT NULL,
            target_agent TEXT NOT NULL,
            protocol_layer TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            description TEXT NOT NULL,
            resolution TEXT NOT NULL
        )
        """
    )

    conn.commit()

    cur.execute("SELECT COUNT(*) FROM agents")
    if cur.fetchone()[0] == 0:
        seed_database(conn)

    conn.close()

def seed_database(conn: sqlite3.Connection):
    now = datetime.utcnow()
    agents = [
        ("Atlas-Planner", "작업 조율", "정상", 0.24, now - timedelta(minutes=5)),
        ("Hermes-Router", "메시지 라우팅", "주의", 0.61, now - timedelta(minutes=2)),
        ("Cetus-Analyzer", "로그 분석", "정상", 0.18, now - timedelta(minutes=1)),
        ("Nyx-Vault", "비밀 저장", "격리", 0.82, now - timedelta(minutes=8)),
        ("Helios-Executor", "작업 수행", "정상", 0.33, now - timedelta(minutes=3)),
    ]

    agent_ids = []
    for name, role, status, risk, last_seen in agents:
        conn.execute(
            "INSERT INTO agents (name, role, status, risk_score, last_seen) VALUES (?, ?, ?, ?, ?)",
            (name, role, status, risk, last_seen.isoformat()),
        )
        agent_ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    communications = [
        (agent_ids[0], agent_ids[1], now - timedelta(minutes=2), "Task Replay 경보 2회"),
        (agent_ids[1], agent_ids[2], now - timedelta(minutes=1), "Message Schema 위반 탐지"),
        (agent_ids[0], agent_ids[3], now - timedelta(minutes=4), "Cross-Agent 권한 상승 시도"),
        (agent_ids[2], agent_ids[4], now - timedelta(minutes=1), "Artifact 변조 의심"),
    ]

    for source, target, last_activity, summary in communications:
        conn.execute(
            "INSERT INTO communications (source_agent_id, target_agent_id, last_activity, threat_summary) VALUES (?, ?, ?, ?)",
            (source, target, last_activity.isoformat(), summary),
        )

    packets = [
        (
            now - timedelta(minutes=10),
            "Atlas-Planner",
            "Helios-Executor",
            "Layer 3",
            "Task Replay",
            "높음",
            "동일 Task ID 재요청 패턴 확인",
            "재전송 차단 정책 적용",
        ),
        (
            now - timedelta(minutes=8),
            "Hermes-Router",
            "Nyx-Vault",
            "Layer 2",
            "Message Schema Violation",
            "중간",
            "AgentCard 스키마 필드 누락",
            "스키마 검증 강화",
        ),
        (
            now - timedelta(minutes=6),
            "Nyx-Vault",
            "Atlas-Planner",
            "Layer 4",
            "Server Impersonation",
            "높음",
            "TLS 핸드셰이크 중 위조 인증서 수신",
            "세션 차단 및 키 회전",
        ),
        (
            now - timedelta(minutes=5),
            "Cetus-Analyzer",
            "Hermes-Router",
            "Layer 3",
            "Agent Card Spoofing",
            "높음",
            "미등록 도메인에서 AgentCard 수신",
            "도메인 블록리스트 추가",
        ),
        (
            now - timedelta(minutes=3),
            "Helios-Executor",
            "Atlas-Planner",
            "Layer 2",
            "Artifact Tampering",
            "중간",
            "Artifact 해시 불일치",
            "Artifact 재전송 요청",
        ),
        (
            now - timedelta(minutes=1),
            "Hermes-Router",
            "Atlas-Planner",
            "Layer 6",
            "Supply Chain Attack",
            "높음",
            "외부 종속성 업데이트 중 악성 패키지 감지",
            "업데이트 롤백 및 검증",
        ),
    ]

    for packet in packets:
        conn.execute(
            """
            INSERT INTO packets (
                timestamp, source_agent, target_agent, protocol_layer,
                threat_type, severity, description, resolution
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet[0].isoformat(),
                packet[1],
                packet[2],
                packet[3],
                packet[4],
                packet[5],
                packet[6],
                packet[7],
            ),
        )

    conn.commit()

def format_agent(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "risk_score": row["risk_score"],
        "last_seen": row["last_seen"],
    }


def format_packet(row):
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source_agent": row["source_agent"],
        "target_agent": row["target_agent"],
        "protocol_layer": row["protocol_layer"],
        "threat_type": row["threat_type"],
        "severity": row["severity"],
        "description": row["description"],
        "resolution": row["resolution"],
    }


def generate_event():
    conn = get_db_connection()
    cur = conn.cursor()
    agents = [format_agent(row) for row in cur.execute("SELECT * FROM agents").fetchall()]
    conn.close()
    threat_types = [
        "Agent Card Spoofing",
        "Task Replay",
        "Message Schema Violation",
        "Server Impersonation",
        "Cross-Agent Task Escalation",
        "Artifact Tampering",
        "Supply Chain Attack",
        "Authentication Threat",
        "Poisoned AgentCard",
        "Emergent Vulnerability",
    ]
    severities = ["낮음", "중간", "높음"]
    layers = ["Layer 2", "Layer 3", "Layer 4", "Layer 6", "Layer 7"]

    while True:
        source, target = random.sample(agents, 2)
        threat_type = random.choice(threat_types)
        severity = random.choices(severities, weights=[0.3, 0.4, 0.3])[0]
        protocol_layer = random.choice(layers)
        timestamp = datetime.utcnow().isoformat()
        description = f"{source['name']} → {target['name']} 통신 중 '{threat_type}' 시그니처 감지"

        event = {
            "timestamp": timestamp,
            "source_agent": source["name"],
            "target_agent": target["name"],
            "threat_type": threat_type,
            "severity": severity,
            "protocol_layer": protocol_layer,
            "description": description,
        }

        try:
            event_queue.put(event, timeout=1)
        except queue.Full:
            pass

        time.sleep(random.uniform(3, 6))


def event_stream():
    while True:
        event = event_queue.get()
        data = json.dumps(event, ensure_ascii=False)
        yield f"data: {data}\n\n"


def background_event_thread():
    global event_thread_started
    if event_thread_started:
        return
    thread = threading.Thread(target=generate_event, daemon=True)
    thread.start()
    event_thread_started = True


@app.route("/")
def index():
    return redirect(url_for("dashboard"))


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/graph")
def graph():
    return render_template("graph.html", active_page="graph")


@app.route("/packets")
def packets():
    return render_template("packets.html", active_page="packets")


@app.route("/api/agents")
def api_agents():
    conn = get_db_connection()
    agents = [format_agent(row) for row in conn.execute("SELECT * FROM agents").fetchall()]

    graph_nodes = [
        {
            "id": agent["id"],
            "label": agent["name"],
            "title": f"<b>{agent['name']}</b><br/>역할: {agent['role']}<br/>상태: {agent['status']}<br/>위험도: {agent['risk_score']:.2f}",
            "group": agent["status"],
        }
        for agent in agents
    ]

    conn.row_factory = sqlite3.Row
    communications = conn.execute(
        """
        SELECT communications.*, s.name AS source_name, t.name AS target_name
        FROM communications
        JOIN agents AS s ON communications.source_agent_id = s.id
        JOIN agents AS t ON communications.target_agent_id = t.id
        ORDER BY datetime(communications.last_activity) DESC
        """
    ).fetchall()
    graph_edges = []
    for row in communications:
        graph_edges.append(
            {
                "from": row["source_agent_id"],
                "to": row["target_agent_id"],
                "label": row["threat_summary"] or "최근 통신",
                "title": row["threat_summary"] or "최근 통신",
            }
        )

    comm_details = [
        {
            "id": row["id"],
            "source": row["source_name"],
            "target": row["target_name"],
            "last_activity": row["last_activity"],
            "threat_summary": row["threat_summary"] or "최근 통신",
        }
        for row in communications
    ]

    return jsonify(
        {
            "agents": agents,
            "nodes": graph_nodes,
            "edges": graph_edges,
            "communications": comm_details,
        }
    )


@app.route("/api/packets")
def api_packets():
    threat = request.args.get("threat")
    severity = request.args.get("severity")
    source = request.args.get("source")
    target = request.args.get("target")
    layer = request.args.get("layer")

    query = "SELECT * FROM packets WHERE 1=1"
    params = []

    if threat:
        query += " AND threat_type LIKE ?"
        params.append(f"%{threat}%")
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source:
        query += " AND source_agent LIKE ?"
        params.append(f"%{source}%")
    if target:
        query += " AND target_agent LIKE ?"
        params.append(f"%{target}%")
    if layer:
        query += " AND protocol_layer = ?"
        params.append(layer)

    query += " ORDER BY datetime(timestamp) DESC"

    conn = get_db_connection()
    rows = conn.execute(query, params).fetchall()
    packets = [format_packet(row) for row in rows]

    return jsonify({"packets": packets})


@app.route("/api/overview")
def api_overview():
    conn = get_db_connection()
    cur = conn.cursor()

    agent_count = cur.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    comm_count = cur.execute("SELECT COUNT(*) FROM communications").fetchone()[0]
    total_packets = cur.execute("SELECT COUNT(*) FROM packets").fetchone()[0]

    severity_rows = cur.execute(
        """
        SELECT severity, COUNT(*) as cnt
        FROM packets
        GROUP BY severity
        """
    ).fetchall()
    severity_counts = {row["severity"]: row["cnt"] for row in severity_rows}

    last_packet = cur.execute(
        "SELECT timestamp FROM packets ORDER BY datetime(timestamp) DESC LIMIT 1"
    ).fetchone()
    last_update = last_packet[0] if last_packet else None

    return jsonify(
        {
            "agent_count": agent_count,
            "communication_count": comm_count,
            "total_packets": total_packets,
            "severity_counts": severity_counts,
            "high_threats": severity_counts.get("높음", 0),
            "last_update": last_update,
        }
    )


@app.route("/api/packets/recent")
def api_recent_packets():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY datetime(timestamp) DESC LIMIT 20"
    ).fetchall()
    packets = [format_packet(row) for row in rows]
    return jsonify({"packets": packets})


@app.route("/stream")
def stream():
    return Response(event_stream(), mimetype="text/event-stream")


init_db()
background_event_thread()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
