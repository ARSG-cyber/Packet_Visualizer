"""
app.py - Main Application Server
FastAPI server that hosts the WebSocket packet stream and serves the static frontend.
Run with: python app.py
"""

import asyncio
import json
import os
import sys
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sniffer import PacketSniffer

# ── Configuration ───────────────────────────────────────────────
HOST = "127.0.0.1"
PORT = 8000
MOCK_MODE = "--mock" in sys.argv or "--demo" in sys.argv

# ── Global State ────────────────────────────────────────────────
sniffer = PacketSniffer(mock_mode=MOCK_MODE)
connected_clients: set = set()


# ── Lifespan ────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(application):
    """Start sniffer and broadcast loop on startup, clean up on shutdown."""
    sniffer.start()
    task = asyncio.create_task(broadcast_loop())
    yield
    sniffer.stop()
    task.cancel()


# ── App Setup ───────────────────────────────────────────────────
app = FastAPI(title="PacketPulse - Real-Time Packet Visualizer", lifespan=lifespan)

# Serve static files from /static directory
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/")
async def serve_index():
    """Serve the main dashboard."""
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    """WebSocket endpoint for real-time packet streaming."""
    await ws.accept()
    connected_clients.add(ws)
    print(f"[+] Client connected. Total: {len(connected_clients)}")

    # Send initial stats
    try:
        await ws.send_json({
            "type": "init",
            "stats": sniffer.get_stats(),
            "interfaces": sniffer.get_interfaces(),
        })
    except Exception:
        pass

    try:
        while True:
            # Listen for control messages from the client
            data = await ws.receive_text()
            msg = json.loads(data)

            if msg.get("action") == "pause":
                sniffer.pause()
            elif msg.get("action") == "resume":
                sniffer.resume()
            elif msg.get("action") == "set_interface":
                iface = msg.get("interface")
                sniffer.stop()
                sniffer.interface = iface
                sniffer.start()

    except WebSocketDisconnect:
        connected_clients.discard(ws)
        print(f"[-] Client disconnected. Total: {len(connected_clients)}")
    except Exception as e:
        connected_clients.discard(ws)
        print(f"[-] Client error: {e}")


async def broadcast_loop():
    """Continuously dequeue packets and broadcast to all connected clients."""
    while True:
        packets_batch = []
        # Drain up to 20 packets per cycle for smooth streaming
        for _ in range(20):
            pkt = sniffer.get_packet()
            if pkt is None:
                break
            packets_batch.append(pkt)

        if packets_batch or connected_clients:
            stats = sniffer.get_stats()
            message = json.dumps({
                "type": "update",
                "packets": packets_batch,
                "stats": stats,
            })

            dead_clients = set()
            for client in connected_clients:
                try:
                    await client.send_text(message)
                except Exception:
                    dead_clients.add(client)

            connected_clients.difference_update(dead_clients)

        await asyncio.sleep(0.1)  # ~10 updates/sec


# ── Entry Point ─────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn

    mode_str = "MOCK (Simulated Traffic)" if MOCK_MODE else "LIVE (Real Network Capture)"
    banner = f"""
============================================================
       PacketPulse - Real-Time Packet Visualizer
============================================================
   Mode:   {mode_str}
   Server: http://{HOST}:{PORT}

   Usage:
     python app.py          Auto-detect mode
     python app.py --mock   Force simulation mode

   Open your browser to the URL above to view the
   dashboard. For live capture, run as Administrator.
============================================================
"""
    print(banner)

    uvicorn.run(app, host=HOST, port=PORT, log_level="warning")
