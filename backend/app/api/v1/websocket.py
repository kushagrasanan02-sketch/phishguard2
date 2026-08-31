import json
import asyncio
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

class ThreatAlertConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        dead_connections = []
        payload = json.dumps(message)
        for connection in self.active_connections:
            try:
                await connection.send_text(payload)
            except Exception:
                dead_connections.append(connection)

        for dead in dead_connections:
            self.disconnect(dead)

manager = ThreatAlertConnectionManager()

def broadcast_threat_alert_sync(scan_data: dict):
    """Synchronous wrapper to emit a threat alert to active WebSocket clients."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            asyncio.create_task(manager.broadcast(scan_data))
        else:
            loop.run_until_complete(manager.broadcast(scan_data))
    except Exception:
        pass

@router.websocket("/ws/alerts")
async def websocket_threat_alerts_endpoint(websocket: WebSocket):
    """WebSocket endpoint pushing real-time SOC threat alerts."""
    await manager.connect(websocket)
    try:
        # Send initial connection status
        await websocket.send_json({
            "event": "CONNECTED",
            "message": "Connected to PhishGuard AI Real-Time Telemetry Stream"
        })
        while True:
            # Keep connection alive receiving ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)
