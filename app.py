import json
import os
import queue
import random
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "a2a_demo.db")

app = Flask(__name__)

event_queue: "queue.Queue[dict]" = queue.Queue(maxsize=100)
event_thread_started = False

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
        CREATE TABLE IF NOT EXISTS agent_profiles (
            agent_id INTEGER PRIMARY KEY,
            ip_address TEXT,
            user_name TEXT,
            department TEXT,
            model TEXT,
            location TEXT,
            purpose TEXT,
            FOREIGN KEY (agent_id) REFERENCES agents (id)
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

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_agent TEXT NOT NULL,
            target_agent TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            severity TEXT NOT NULL,
            protocol_layer TEXT NOT NULL,
            description TEXT NOT NULL
        )
        """
    )

    conn.commit()

    cur.execute("SELECT COUNT(*) FROM agents")
    if cur.fetchone()[0] == 0:
        seed_database(conn)

    ensure_profiles(conn)
    ensure_alert_seed(conn)

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

    agent_ids: List[int] = []
    for name, role, status, risk, last_seen in agents:
        conn.execute(
            "INSERT INTO agents (name, role, status, risk_score, last_seen) VALUES (?, ?, ?, ?, ?)",
            (name, role, status, risk, last_seen.isoformat()),
        )
        agent_ids.append(conn.execute("SELECT last_insert_rowid()").fetchone()[0])

    profiles = [
        (agent_ids[0], "10.3.14.21", "최아라", "플레이북", "Atlas-Coordinator v2", "서울", "멀티 에이전트 워크플로 조율"),
        (agent_ids[1], "10.3.14.45", "문지혁", "전송제어", "Hermes-Gateway r5", "판교", "메시지 라우팅 및 인증"),
        (agent_ids[2], "10.3.14.87", "이다연", "로깅", "Cetus-Insight 1.3", "판교", "로그 분석 및 위협 탐지"),
        (agent_ids[3], "10.3.15.10", "박은호", "보안금고", "Nyx-Vault 3.0", "서울", "비밀 데이터 저장"),
        (agent_ids[4], "10.3.14.64", "정태윤", "실행", "Helios-Run 7b", "부산", "실시간 작업 실행"),
    ]

    for profile in profiles:
        conn.execute(
            """
            INSERT INTO agent_profiles (
                agent_id, ip_address, user_name, department, model, location, purpose
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            profile,
        )

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

    packets.extend(
        [
            (
                now - timedelta(minutes=20),
                "Atlas-Planner",
                "Helios-Executor",
                "Layer 3",
                "Task Replay",
                "높음",
                "캐시된 Task ID 재전송 시도가 반복되었습니다.",
                "임시 토큰 폐기 및 세션 리셋",
            ),
            (
                now - timedelta(minutes=30),
                "Cetus-Analyzer",
                "Hermes-Router",
                "Layer 3",
                "Cross-Agent Escalation",
                "높음",
                "여러 에이전트 세션에서 비정상 권한 상승이 감지되었습니다.",
                "세션 전파 중단 및 역할 검증",
            ),
            (
                now - timedelta(minutes=45),
                "Hermes-Router",
                "Nyx-Vault",
                "Layer 2",
                "Message Schema Violation",
                "중간",
                "에이전트 필드 순서 변조 시도가 발견되었습니다.",
                "스키마 강제 정렬 적용",
            ),
            (
                now - timedelta(hours=1, minutes=15),
                "Atlas-Planner",
                "Helios-Executor",
                "Layer 4",
                "Server Impersonation",
                "높음",
                "이전 세션과 유사한 위조 인증서가 재시도되었습니다.",
                "미러링 노드 격리",
            ),
            (
                now - timedelta(hours=2, minutes=5),
                "Nyx-Vault",
                "Cetus-Analyzer",
                "Layer 6",
                "Supply Chain Attack",
                "중간",
                "외부 의존성에서 임시 파일 삽입 징후가 확인되었습니다.",
                "패키지 검증 재실행",
            ),
            (
                now - timedelta(hours=3),
                "Helios-Executor",
                "Atlas-Planner",
                "Layer 2",
                "Artifact Tampering",
                "낮음",
                "과거 버전 아티팩트와 해시가 불일치합니다.",
                "감시 대기열에 재배치",
            ),
        ]
    )

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

    alert_seed = [
        (
            now - timedelta(minutes=2, seconds=30),
            "Atlas-Planner",
            "Nyx-Vault",
            "Cross-Agent Task Escalation",
            "높음",
            "Layer 3",
            "Atlas-Planner가 Nyx-Vault 권한 상승 시도 감지",
        ),
        (
            now - timedelta(minutes=2),
            "Hermes-Router",
            "Atlas-Planner",
            "A2A Message Schema Violation",
            "중간",
            "Layer 2",
            "Hermes 라우터 메시지 스키마 필드 무결성 경고",
        ),
    ]

    for alert in alert_seed:
        conn.execute(
            """
            INSERT INTO alerts (
                timestamp, source_agent, target_agent, threat_type, severity, protocol_layer, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            alert,
        )

    conn.commit()


def ensure_profiles(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM agent_profiles")
    if cur.fetchone()[0] > 0:
        return

    agent_rows = cur.execute("SELECT id, name FROM agents ORDER BY id").fetchall()
    sample_profiles = {
        "Atlas-Planner": (
            "10.3.14.21",
            "최아라",
            "플레이북",
            "Atlas-Coordinator v2",
            "서울",
            "멀티 에이전트 워크플로 조율",
        ),
        "Hermes-Router": (
            "10.3.14.45",
            "문지혁",
            "전송제어",
            "Hermes-Gateway r5",
            "판교",
            "메시지 라우팅 및 인증",
        ),
        "Cetus-Analyzer": (
            "10.3.14.87",
            "이다연",
            "로깅",
            "Cetus-Insight 1.3",
            "판교",
            "로그 분석 및 위협 탐지",
        ),
        "Nyx-Vault": (
            "10.3.15.10",
            "박은호",
            "보안금고",
            "Nyx-Vault 3.0",
            "서울",
            "비밀 데이터 저장",
        ),
        "Helios-Executor": (
            "10.3.14.64",
            "정태윤",
            "실행",
            "Helios-Run 7b",
            "부산",
            "실시간 작업 실행",
        ),
    }

    for row in agent_rows:
        values = sample_profiles.get(
            row["name"],
            ("10.0.0.1", "미지정", "미지정", "Unknown", "서울", "Agent-to-Agent 모니터링"),
        )
        cur.execute(
            """
            INSERT OR REPLACE INTO agent_profiles (
                agent_id, ip_address, user_name, department, model, location, purpose
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (row["id"],) + values,
        )
    conn.commit()


def ensure_alert_seed(conn: sqlite3.Connection):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM alerts")
    if cur.fetchone()[0] > 0:
        return

    now = datetime.utcnow()
    seed = [
        (
            now - timedelta(minutes=4),
            "Atlas-Planner",
            "Nyx-Vault",
            "Cross-Agent Task Escalation",
            "높음",
            "Layer 3",
            "Atlas-Planner가 Nyx-Vault 권한 상승 시도 감지",
        ),
        (
            now - timedelta(minutes=3),
            "Hermes-Router",
            "Atlas-Planner",
            "A2A Message Schema Violation",
            "중간",
            "Layer 2",
            "Hermes 라우터 메시지 스키마 필드 무결성 경고",
        ),
    ]

    for alert in seed:
        cur.execute(
            """
            INSERT INTO alerts (
                timestamp, source_agent, target_agent, threat_type, severity, protocol_layer, description
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (alert[0].isoformat(),) + alert[1:],
        )
    conn.commit()


def format_agent(row: sqlite3.Row) -> Dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "risk_score": row["risk_score"],
        "last_seen": row["last_seen"],
    }


def get_agent_profile(agent_id: int) -> Optional[Dict]:
    conn = get_db_connection()
    row = conn.execute(
        "SELECT agents.*, agent_profiles.* FROM agents JOIN agent_profiles ON agents.id = agent_profiles.agent_id WHERE agents.id = ?",
        (agent_id,),
    ).fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "risk_score": row["risk_score"],
        "last_seen": row["last_seen"],
        "ip_address": row["ip_address"],
        "user_name": row["user_name"],
        "department": row["department"],
        "model": row["model"],
        "location": row["location"],
        "purpose": row["purpose"],
    }


def format_packet(row: sqlite3.Row, agent_map: Dict[str, Dict[str, int]]) -> Dict:
    source_info = agent_map.get(row["source_agent"], {})
    target_info = agent_map.get(row["target_agent"], {})
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
        "source_agent_id": source_info.get("id"),
        "target_agent_id": target_info.get("id"),
    }


def format_alert(row: sqlite3.Row) -> Dict:
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "source_agent": row["source_agent"],
        "target_agent": row["target_agent"],
        "threat_type": row["threat_type"],
        "severity": row["severity"],
        "protocol_layer": row["protocol_layer"],
        "description": row["description"],
    }


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


def save_alert(event: Dict) -> Dict:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO alerts (timestamp, source_agent, target_agent, threat_type, severity, protocol_layer, description)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event["timestamp"],
            event["source_agent"],
            event["target_agent"],
            event["threat_type"],
            event["severity"],
            event.get("protocol_layer", "Layer ?"),
            event["description"],
        ),
    )
    event_id = cur.lastrowid
    conn.commit()
    conn.close()
    event["id"] = event_id
    return event


def generate_event():
    while True:
        conn = get_db_connection()
        agents = [format_agent(row) for row in conn.execute("SELECT * FROM agents").fetchall()]
        conn.close()

        source, target = random.sample(agents, 2)
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

        threat_type = random.choice(threat_types)
        severity = random.choices(severities, weights=[0.3, 0.4, 0.3])[0]
        protocol_layer = random.choice(layers)
        timestamp = datetime.utcnow().isoformat()
        description = f"{source['name']} → {target['name']} 통신 중 '{threat_type}' 시그니처 감지"

        event = {
            "timestamp": timestamp,
            "source_agent": source["name"],
            "target_agent": target["name"],
            "source_agent_id": source["id"],
            "target_agent_id": target["id"],
            "threat_type": threat_type,
            "severity": severity,
            "protocol_layer": protocol_layer,
            "description": description,
        }

        stored_event = save_alert(event.copy())

        try:
            event_queue.put(stored_event, timeout=1)
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


@app.route("/agents/<int:agent_id>")
def agent_detail(agent_id: int):
    profile = get_agent_profile(agent_id)
    if not profile:
        abort(404)

    conn = get_db_connection()
    communications = conn.execute(
        """
        SELECT c.*, s.name AS source_name, t.name AS target_name
        FROM communications c
        JOIN agents AS s ON c.source_agent_id = s.id
        JOIN agents AS t ON c.target_agent_id = t.id
        WHERE c.source_agent_id = ? OR c.target_agent_id = ?
        ORDER BY datetime(c.last_activity) DESC
        """,
        (agent_id, agent_id),
    ).fetchall()

    related_agents = conn.execute(
        "SELECT id, name, status FROM agents WHERE id != ? ORDER BY name",
        (agent_id,),
    ).fetchall()

    packets = conn.execute(
        """
        SELECT * FROM packets
        WHERE source_agent = (SELECT name FROM agents WHERE id = ?)
           OR target_agent = (SELECT name FROM agents WHERE id = ?)
        ORDER BY datetime(timestamp) DESC
        LIMIT 10
        """,
        (agent_id, agent_id),
    ).fetchall()

    conn.close()

    communication_data = [
        {
            "id": row["id"],
            "source": row["source_name"],
            "target": row["target_name"],
            "last_activity": row["last_activity"],
            "summary": row["threat_summary"] or "최근 통신",
        }
        for row in communications
    ]

    agent_map = {profile["name"]: {"id": agent_id, "name": profile["name"]}}
    for item in related_agents:
        agent_map[item["name"]] = {"id": item["id"], "name": item["name"]}

    packet_rows = [format_packet(row, agent_map) for row in packets]

    return render_template(
        "agent_detail.html",
        agent=profile,
        communications=communication_data,
        related_agents=[dict(row) for row in related_agents],
        packets=packet_rows,
    )


@app.route("/alerts/<int:alert_id>")
def alert_detail(alert_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    agent_rows = conn.execute("SELECT id, name FROM agents").fetchall()
    conn.close()
    if not row:
        abort(404)

    alert = format_alert(row)
    name_to_id = {item["name"]: item["id"] for item in agent_rows}
    return render_template("alert_detail.html", alert=alert, name_to_id=name_to_id)


@app.route("/packets/<int:packet_id>")
def packet_detail(packet_id: int):
    conn = get_db_connection()
    agent_rows = conn.execute("SELECT id, name FROM agents").fetchall()
    agent_map = {row["name"]: {"id": row["id"], "name": row["name"]} for row in agent_rows}
    row = conn.execute("SELECT * FROM packets WHERE id = ?", (packet_id,)).fetchone()
    conn.close()
    if not row:
        abort(404)

    packet = format_packet(row, agent_map)
    return render_template("packet_detail.html", packet=packet)


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

    conn.close()

    return jsonify(
        {
            "agents": agents,
            "nodes": graph_nodes,
            "edges": graph_edges,
            "communications": comm_details,
        }
    )


@app.route("/api/alerts/recent")
def api_recent_alerts():
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY datetime(timestamp) DESC LIMIT 10").fetchall()
    conn.close()
    alerts = [format_alert(row) for row in rows]
    return jsonify({"alerts": alerts})


@app.route("/api/packets")
def api_packets():
    threat = request.args.get("threat")
    severity = request.args.get("severity")
    source = request.args.get("source")
    target = request.args.get("target")
    layer = request.args.get("layer")

    query = "SELECT * FROM packets WHERE 1=1"
    params: List[str] = []

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
    agent_rows = conn.execute("SELECT id, name FROM agents").fetchall()
    conn.close()

    agent_map = {row["name"]: {"id": row["id"], "name": row["name"]} for row in agent_rows}
    packets = [format_packet(row, agent_map) for row in rows]

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

    layer_rows = cur.execute(
        """
        SELECT protocol_layer, COUNT(*) as cnt
        FROM packets
        GROUP BY protocol_layer
        ORDER BY protocol_layer
        """
    ).fetchall()
    layer_counts = {row["protocol_layer"]: row["cnt"] for row in layer_rows}

    persistent_rows = cur.execute(
        """
        SELECT source_agent, COUNT(*) as cnt, MAX(timestamp) as last_ts
        FROM packets
        WHERE severity = '높음'
        GROUP BY source_agent
        HAVING cnt >= 2
        ORDER BY cnt DESC, datetime(last_ts) DESC
        LIMIT 5
        """
    ).fetchall()

    agent_rows = cur.execute("SELECT id, name FROM agents").fetchall()
    agent_map = {row["name"]: row["id"] for row in agent_rows}

    persistent_agents = []
    for row in persistent_rows:
        last_detail = cur.execute(
            """
            SELECT threat_type
            FROM packets
            WHERE source_agent = ? AND severity = '높음'
            ORDER BY datetime(timestamp) DESC
            LIMIT 1
            """,
            (row["source_agent"],),
        ).fetchone()
        persistent_agents.append(
            {
                "agent_name": row["source_agent"],
                "agent_id": agent_map.get(row["source_agent"]),
                "repeat_count": row["cnt"],
                "last_detected": row["last_ts"],
                "last_threat": last_detail[0] if last_detail else "-",
            }
        )

    trend_rows = cur.execute(
        """
        SELECT strftime('%Y-%m-%d %H:00', timestamp) AS bucket,
               COUNT(*) AS cnt
        FROM packets
        WHERE datetime(timestamp) >= datetime('now', '-12 hours')
        GROUP BY bucket
        ORDER BY datetime(bucket)
        """
    ).fetchall()

    now_utc = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    buckets = [now_utc - timedelta(hours=offset) for offset in range(11, -1, -1)]
    bucket_map = {row["bucket"]: row["cnt"] for row in trend_rows}
    threat_trend = [
        {
            "window": bucket.strftime("%Y-%m-%d %H:00"),
            "window_label": bucket.strftime("%m/%d %H시"),
            "count": bucket_map.get(bucket.strftime("%Y-%m-%d %H:00"), 0),
        }
        for bucket in buckets
    ]

    last_packet = cur.execute(
        "SELECT timestamp FROM packets ORDER BY datetime(timestamp) DESC LIMIT 1"
    ).fetchone()
    last_update = last_packet[0] if last_packet else None

    conn.close()

    return jsonify(
        {
            "agent_count": agent_count,
            "communication_count": comm_count,
            "total_packets": total_packets,
            "severity_counts": severity_counts,
            "layer_counts": layer_counts,
            "high_threats": severity_counts.get("높음", 0),
            "last_update": last_update,
            "persistent_agents": persistent_agents,
            "threat_trend": threat_trend,
        }
    )


@app.route("/api/packets/recent")
def api_recent_packets():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT * FROM packets ORDER BY datetime(timestamp) DESC LIMIT 20"
    ).fetchall()
    agent_rows = conn.execute("SELECT id, name FROM agents").fetchall()
    conn.close()

    agent_map = {row["name"]: {"id": row["id"], "name": row["name"]} for row in agent_rows}
    packets = [format_packet(row, agent_map) for row in rows]
    return jsonify({"packets": packets})


@app.route("/stream")
def stream():
    return Response(event_stream(), mimetype="text/event-stream")


init_db()
background_event_thread()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
