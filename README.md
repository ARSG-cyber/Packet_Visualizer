# PacketPulse - Real-Time Packet Visualizer

A real-time network packet visualizer built with FastAPI, WebSockets, and Scapy.

This project captures network packets and displays them through a live web dashboard, making it easier to understand network traffic, protocols, and packet flow in real time.

## Features

* Live packet capture and visualization
* Protocol analysis (TCP, UDP, DNS, HTTP, TLS, ICMP, ARP)
* Real-time network statistics
* Active host tracking
* Network interface switching
* Demo mode with simulated traffic
* WebSocket-based real-time updates

## Tech Stack

* Python
* FastAPI
* WebSockets
* Scapy
* HTML, CSS, JavaScript

## Installation

```bash
git clone https://github.com/ARSG-cyber/Packet_Visualizer.git
cd packet-visualizer
pip install -r requirements.txt
```

## Usage

Run with real network traffic:

```bash
python app.py
```

Run in demo mode:

```bash
python app.py --mock
```

Open:

```text
http://127.0.0.1:8000
```

## Project Structure

```text
packet-visualizer/
├── app.py
├── sniffer.py
├── requirements.txt
└── static/
    ├── index.html
    ├── app.js
    └── style.css
```

## Why I Built This

I created this project while learning cybersecurity and networking to better understand how packet capture, protocol analysis, and real-time data streaming work in practice.

## License

MIT License
