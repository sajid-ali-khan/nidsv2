from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Any
import json
import time  # Import the time module for high-resolution timestamps
from collections import deque, Counter
from datetime import datetime, timezone


# --- In-Memory Data Store (no changes here) ---
class NIDSDataStore:
    def __init__(self, max_events: int = 500):
        self.recent_events: deque = deque(maxlen=max_events)
        self.total_events = 0
        self.attack_events = 0
        self.attack_distribution = Counter()

    def add_event(self, event: Dict[str, Any]):
        event['server_timestamp_utc'] = datetime.now(timezone.utc).isoformat()
        self.recent_events.appendleft(event)
        self.total_events += 1
        if event.get('prediction') != 'Normal Traffic':
            self.attack_events += 1
            self.attack_distribution[event.get('prediction')] += 1

    def get_stats(self, time_window_minutes: int = 0) -> Dict[str, int]:
        return {
            "total_events": self.total_events,
            "attacks_detected": self.attack_events,
            "normal_traffic": self.total_events - self.attack_events,
        }

    def get_attack_distribution(self) -> Dict[str, int]:
        return dict(self.attack_distribution)

    def get_historical_events(self, limit: int, offset: int) -> List[Dict[str, Any]]:
        return list(self.recent_events)[offset: offset + limit]


data_store = NIDSDataStore()
app = FastAPI()


# --- Connection Manager (with broadcast fix) ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"New client connected. Total clients: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            print(f"Client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast(self, message: str):
        for connection in self.active_connections[:]:
            try:
                await connection.send_text(message)
            except RuntimeError:
                print(f"Failed to send to a disconnected client, removing.")
                self.disconnect(connection)


manager = ConnectionManager()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    print("🚀 Backend server started. Waiting for events...")


# --- API Endpoints ---
@app.websocket("/ws/events/stream")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.get("/api/stats")
async def get_stats(time_range: int = Query(0, description="Time range in minutes. 0 for all-time.")):
    return data_store.get_stats(time_window_minutes=time_range)


@app.get("/api/attack-distribution")
async def get_attack_distribution():
    return data_store.get_attack_distribution()


@app.get("/api/events")
async def get_events(limit: int = Query(50, ge=1, le=100), offset: int = Query(0, ge=0)):
    return data_store.get_historical_events(limit=limit, offset=offset)


@app.post("/api/log_event")
async def log_event(request: Request):
    event_data = await request.json()

    # --- FIX IS HERE: Make the flow_id unique before processing ---
    unique_flow_id = f"{event_data.get('flow_id', 'unknown_flow')}-{time.time_ns()}"
    event_data['flow_id'] = unique_flow_id

    data_store.add_event(event_data)
    await manager.broadcast(json.dumps(event_data))
    return {"status": "success"}


@app.get("/")
def read_root():
    return {"status": "NIDS Backend is running"}

