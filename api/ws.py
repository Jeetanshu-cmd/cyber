"""
api/ws.py: WebSocket ConnectionManager tracking active clients and broadcasting JSON events.
"""

from typing import List
from fastapi import WebSocket

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, event: dict):
        """
        Broadcasts a JSON event dictionary to all connected WebSocket clients.
        If a client errors during send, it is safely dropped.
        """
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(event)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)

ws_manager = ConnectionManager()
