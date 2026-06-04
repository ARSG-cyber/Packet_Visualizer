# PacketPulse - Real-Time Packet Visualizer

A real-time network packet sniffer and visualizer dashboard built with **FastAPI**, **WebSockets**, and **Scapy**. Monitor live network traffic, analyze protocols, track bandwidth, and visualize active hosts with an interactive web-based dashboard.

## 🎯 Features

- **Real-Time Packet Capture** — Stream live network packets as they flow through your system
- **Protocol Analysis** — Breakdown by TCP, UDP, DNS, HTTP, TLS, ICMP, ARP, and more
- **Live Statistics Dashboard** — Packets per second, bandwidth metrics, active hosts tracking
- **Multiple Network Interfaces** — Switch between network adapters on the fly
- **Pause/Resume Control** — Start and stop packet capture without restarting
- **Demo Mode** — Run with mock data for learning and sharing without capturing real traffic
- **Responsive UI** — Clean, modern dashboard optimized for desktop and tablet viewing
- **WebSocket Streaming** — Efficient real-time data delivery to multiple concurrent clients

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **Windows/macOS/Linux**
- **(Windows only) Npcap** — Download from [npcap.com](https://npcap.com/download/) for real packet sniffing

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/ARSG-cyber/Packet_Visualizer.git
   cd packet-visualizer
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

### Running the Project

**Start in real-time mode** (captures actual network traffic):
```bash
python app.py
```
Then open http://127.0.0.1:8000 in your browser.

**Start in demo/mock mode** (simulated data for learning):
```bash
python app.py --mock
```

**Note:** Real packet sniffing requires:
- **Windows**: Npcap installed

## 📊 What You'll See

Once the dashboard loads, you'll observe:

- **Packet Stream** — Real-time list of captured packets with source/destination IPs, protocols, and sizes
- **Protocol Breakdown** — Pie chart showing distribution of network protocols
- **Network Stats** — Total packets, bandwidth usage, packets per second, active hosts
- **Interface Selection** — Dropdown to switch between network adapters
- **Pause/Resume Controls** — Start/stop packet capture on demand

## 🛠 Project Structure

```
packet-visualizer/
├── app.py                 # FastAPI server & WebSocket handler
├── sniffer.py            # Packet capture engine (real & mock mode)
├── requirements.txt      # Python dependencies
└── static/
    ├── index.html        # Dashboard UI
    ├── app.js           # Frontend logic & WebSocket client
    └── style.css        # Dashboard styling
```
## 🔧 Configuration

Edit `app.py` to customize:

- **Host/Port:** Change `HOST` and `PORT` variables
- **Mock Mode:** Add `--mock` flag or remove Scapy for automatic fallback
- **Queue Size:** Adjust `packet_queue.Queue(maxsize=5000)` in `sniffer.py`

## 🧪 Demo/Mock Mode

The mock mode generates realistic simulated packets perfect for:
- ✅ Learning how network protocols work
- ✅ Testing the dashboard UI and features
- ✅ Creating LinkedIn videos and demos
- ✅ Sharing without exposing real network traffic
- ✅ Running on systems without packet capture permissions

Run in demo mode:
```bash
python app.py --mock
```

Or:
```bash
python app.py --demo
```

## 📋 Requirements

See `requirements.txt`:
- **fastapi** — Modern Python web framework
- **uvicorn** — ASGI server
- **websockets** — WebSocket support
- **scapy** — Packet manipulation library

## ⚙️ Troubleshooting

**"Sniffing is not available" error on Windows?**
- Install Npcap: https://npcap.com/download/
- Select "WinPcap API-compatible mode" during installation


**Dashboard not showing packets?**
- Check browser console (F12) for errors
- Verify WebSocket connection at `/ws`
- Ensure firewall isn't blocking localhost:8000
- Try mock mode: `python app.py --mock`

## 📚 Learn More

- **Scapy Documentation:** https://scapy.readthedocs.io/
- **FastAPI Guide:** https://fastapi.tiangolo.com/
- **WebSocket Basics:** https://developer.mozilla.org/en-US/docs/Web/API/WebSocket
- **Network Protocols:** https://www.ibm.com/topics/networking

## 📄 License

MIT License — See LICENSE file for details.

## 🤝 Contributing

Contributions welcome! Feel free to:
- Report bugs via GitHub Issues
- Submit pull requests with improvements
- Suggest new features or protocols to track
- Share feedback and ideas

## 👤 Author

Created while learning cybersecurity and network engineering.


** Tip: Use this project to understand how network traffic flows in real-time. Perfect for learning cybersecurity, network analysis, and real-time data visualization!

