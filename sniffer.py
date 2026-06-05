"""
sniffer.py - Packet Capture Engine
Supports both real-time packet sniffing via Scapy and a realistic mock mode.
All packets are parsed into structured JSON and placed on a thread-safe queue.
"""

import threading
import queue
import time
import random
import json
import hashlib
from datetime import datetime

# Try to import scapy - graceful fallback if unavailable
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, DNS, ICMP, ARP, Ether, Raw,
        DNSQR, DNSRR, conf, get_if_list
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available. Install with: pip install scapy")
    print("[*] Mock mode will be used instead.\n")


class PacketSniffer:
    """
    Core packet sniffing engine.
    Captures packets on a background thread and enqueues parsed JSON objects.
    """

    def __init__(self, interface=None, mock_mode=False):
        self.interface = interface
        self.mock_mode = mock_mode or not SCAPY_AVAILABLE
        self.packet_queue = queue.Queue(maxsize=5000)
        self.running = False
        self.paused = False
        self.thread = None
        self.packet_count = 0
        self.total_bytes = 0
        self.start_time = None
        self.protocol_counts = {
            "TCP": 0, "UDP": 0, "DNS": 0, "HTTP": 0,
            "TLS": 0, "ICMP": 0, "ARP": 0, "Other": 0
        }
        self.active_hosts = set()
        self._bandwidth_window = []  # (timestamp, bytes) for bandwidth calc

    # ── Public API ──────────────────────────────────────────────

    def start(self):
        """Start the sniffer on a background thread."""
        self.running = True
        self.paused = False
        self.start_time = time.time()
        target = self._mock_sniffer if self.mock_mode else self._real_sniffer
        self.thread = threading.Thread(target=target, daemon=True)
        self.thread.start()
        mode = "MOCK" if self.mock_mode else f"LIVE ({self.interface or 'auto'})"
        print(f"[✓] Sniffer started in {mode} mode")

    def stop(self):
        """Stop the sniffer."""
        self.running = False
        print("[✗] Sniffer stopped")

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def get_packet(self):
        """Non-blocking dequeue of the next parsed packet."""
        try:
            return self.packet_queue.get_nowait()
        except queue.Empty:
            return None

    def get_stats(self):
        """Return current capture statistics."""
        elapsed = time.time() - self.start_time if self.start_time else 1
        now = time.time()
        # Calculate bandwidth over last 2 seconds
        self._bandwidth_window = [
            (t, b) for t, b in self._bandwidth_window if now - t < 2
        ]
        recent_bytes = sum(b for _, b in self._bandwidth_window)
        return {
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "elapsed": round(elapsed, 1),
            "pps": round(self.packet_count / max(elapsed, 1), 1),
            "bandwidth_bps": round(recent_bytes / 2),
            "protocols": dict(self.protocol_counts),
            "active_hosts": len(self.active_hosts),
            "mode": "mock" if self.mock_mode else "live",
            "is_running": self.running and not self.paused,
        }

    def get_interfaces(self):
        """List available network interfaces."""
        if SCAPY_AVAILABLE:
            try:
                return get_if_list()
            except Exception:
                return []
        return []

    # ── Real Packet Sniffing ────────────────────────────────────

    def _real_sniffer(self):
        """Capture packets from a real network interface using Scapy."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_real_packet,
                store=False,
                stop_filter=lambda _: not self.running,
            )
        except PermissionError:
            print("[!] Permission denied. Run as Administrator for live capture.")
            print("[*] Falling back to mock mode...")
            self.mock_mode = True
            self._mock_sniffer()
        except Exception as e:
            print(f"[!] Sniffing error: {e}")
            print("[*] Falling back to mock mode...")
            self.mock_mode = True
            self._mock_sniffer()

    def _process_real_packet(self, pkt):
        """Parse a real Scapy packet and enqueue it."""
        if self.paused or not self.running:
            return

        parsed = self._parse_scapy_packet(pkt)
        if parsed:
            self.packet_count += 1
            self.total_bytes += parsed["size"]
            self._bandwidth_window.append((time.time(), parsed["size"]))

            proto = parsed["protocol"]
            if proto in self.protocol_counts:
                self.protocol_counts[proto] += 1
            else:
                self.protocol_counts["Other"] += 1

            self.active_hosts.add(parsed["src"])
            self.active_hosts.add(parsed["dst"])

            try:
                self.packet_queue.put_nowait(parsed)
            except queue.Full:
                try:
                    self.packet_queue.get_nowait()
                    self.packet_queue.put_nowait(parsed)
                except queue.Empty:
                    pass

    def _parse_scapy_packet(self, pkt):
        """Convert a Scapy packet to a structured dictionary."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        size = len(pkt)

        # Determine source/dest & protocol
        src = dst = "Unknown"
        protocol = "Other"
        info = ""
        layers = []
        flags = ""
        raw_hex = bytes(pkt).hex()[:200]  # First 100 bytes in hex

        # Layer 2 - Ethernet
        if pkt.haslayer(Ether):
            layers.append({
                "name": "Ethernet",
                "fields": {
                    "src_mac": pkt[Ether].src,
                    "dst_mac": pkt[Ether].dst,
                    "type": hex(pkt[Ether].type),
                }
            })

        # Layer 3 - IP
        if pkt.haslayer(IP):
            src = pkt[IP].src
            dst = pkt[IP].dst
            layers.append({
                "name": "IPv4",
                "fields": {
                    "version": pkt[IP].version,
                    "ihl": pkt[IP].ihl,
                    "tos": pkt[IP].tos,
                    "length": pkt[IP].len,
                    "id": pkt[IP].id,
                    "ttl": pkt[IP].ttl,
                    "protocol": pkt[IP].proto,
                    "src": src,
                    "dst": dst,
                }
            })

        # ARP
        if pkt.haslayer(ARP):
            protocol = "ARP"
            arp = pkt[ARP]
            src = arp.psrc
            dst = arp.pdst
            op = "Request" if arp.op == 1 else "Reply"
            info = f"ARP {op}: Who has {dst}? Tell {src}"
            layers.append({
                "name": "ARP",
                "fields": {
                    "operation": op,
                    "sender_mac": arp.hwsrc,
                    "sender_ip": arp.psrc,
                    "target_mac": arp.hwdst,
                    "target_ip": arp.pdst,
                }
            })

        # Layer 4 - TCP
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            sport = tcp.sport
            dport = tcp.dport
            tcp_flags = tcp.flags
            flags = str(tcp_flags)
            protocol = "TCP"

            # Detect HTTP
            if dport == 80 or sport == 80:
                protocol = "HTTP"
                if pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load).decode("utf-8", errors="ignore")
                    if payload.startswith(("GET", "POST", "PUT", "DELETE", "HEAD")):
                        first_line = payload.split("\r\n")[0]
                        info = first_line
                    elif payload.startswith("HTTP/"):
                        first_line = payload.split("\r\n")[0]
                        info = first_line

            # Detect TLS
            if dport == 443 or sport == 443:
                protocol = "TLS"
                info = f"TLS → {dst}:{dport}"

            if not info:
                info = f"{sport} → {dport} [{flags}] Seq={tcp.seq} Ack={tcp.ack}"

            layers.append({
                "name": "TCP",
                "fields": {
                    "src_port": sport,
                    "dst_port": dport,
                    "seq": tcp.seq,
                    "ack": tcp.ack,
                    "flags": flags,
                    "window": tcp.window,
                }
            })

        # Layer 4 - UDP
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            sport = udp.sport
            dport = udp.dport
            protocol = "UDP"
            info = f"{sport} → {dport} Len={udp.len}"

            layers.append({
                "name": "UDP",
                "fields": {
                    "src_port": sport,
                    "dst_port": dport,
                    "length": udp.len,
                }
            })

        # ICMP
        if pkt.haslayer(ICMP):
            protocol = "ICMP"
            icmp = pkt[ICMP]
            icmp_type = icmp.type
            type_map = {0: "Echo Reply", 3: "Dest Unreachable", 8: "Echo Request", 11: "TTL Exceeded"}
            info = f"ICMP {type_map.get(icmp_type, f'Type {icmp_type}')}"
            layers.append({
                "name": "ICMP",
                "fields": {
                    "type": icmp_type,
                    "code": icmp.code,
                    "description": type_map.get(icmp_type, f"Type {icmp_type}"),
                }
            })

        # DNS
        if pkt.haslayer(DNS):
            protocol = "DNS"
            dns = pkt[DNS]
            if dns.qr == 0 and pkt.haslayer(DNSQR):  # Query
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
                info = f"DNS Query: {qname}"
                layers.append({
                    "name": "DNS",
                    "fields": {
                        "type": "Query",
                        "query_name": qname,
                        "query_type": pkt[DNSQR].qtype,
                    }
                })
            elif dns.qr == 1:  # Response
                answers = []
                if dns.ancount and pkt.haslayer(DNSRR):
                    for i in range(dns.ancount):
                        try:
                            rr = dns.an[i]
                            answers.append(str(rr.rdata))
                        except Exception:
                            break
                qname = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".") if pkt.haslayer(DNSQR) else "?"
                info = f"DNS Response: {qname} → {', '.join(answers[:3])}"
                layers.append({
                    "name": "DNS",
                    "fields": {
                        "type": "Response",
                        "query_name": qname,
                        "answers": answers[:5],
                    }
                })

        # Build the ELI5 explanation
        eli5 = self._generate_eli5(protocol, src, dst, info, layers)

        pkt_id = hashlib.md5(
            f"{self.packet_count}{ts}{src}{dst}".encode()
        ).hexdigest()[:12]

        return {
            "id": pkt_id,
            "number": self.packet_count + 1,
            "timestamp": ts,
            "src": src,
            "dst": dst,
            "protocol": protocol,
            "size": size,
            "info": info,
            "flags": flags,
            "layers": layers,
            "raw_hex": raw_hex,
            "eli5": eli5,
        }

    # ── Mock Packet Generator ──────────────────────────────────

    def _mock_sniffer(self):
        """Generate realistic mock packet data for demonstration."""
        domains = [
            "google.com", "linkedin.com", "github.com", "cloudflare.com",
            "youtube.com", "stackoverflow.com", "amazon.com", "microsoft.com",
            "twitter.com", "reddit.com", "netflix.com", "discord.com",
            "medium.com", "hackerone.com", "tryhackme.com"
        ]

        local_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.105"]
        remote_ips = [
            "142.250.80.46", "13.107.42.14", "104.18.32.7",
            "151.101.1.69", "52.94.236.248", "20.205.243.166",
            "198.41.215.162", "157.240.1.35", "69.171.250.35",
            "34.117.59.81", "172.217.14.110", "31.13.71.36",
        ]

        gateways = ["192.168.1.1", "10.0.0.1"]
        dns_servers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "208.67.222.222"]

        mac_local = "AA:BB:CC:11:22:33"
        mac_gateway = "DD:EE:FF:44:55:66"

        while self.running:
            if self.paused:
                time.sleep(0.1)
                continue

            # Randomly choose packet type with realistic distribution
            roll = random.random()
            pkt = None

            if roll < 0.08:
                # ARP (8%)
                pkt = self._mock_arp(local_ips, gateways, mac_local, mac_gateway)
            elif roll < 0.15:
                # ICMP (7%)
                local = random.choice(local_ips)
                remote = random.choice(remote_ips + gateways)
                pkt = self._mock_icmp(local, remote)
            elif roll < 0.35:
                # DNS (20%)
                local = random.choice(local_ips)
                dns = random.choice(dns_servers)
                domain = random.choice(domains)
                pkt = self._mock_dns(local, dns, domain)
            elif roll < 0.50:
                # HTTP (15%)
                local = random.choice(local_ips)
                remote = random.choice(remote_ips)
                domain = random.choice(domains)
                pkt = self._mock_http(local, remote, domain)
            elif roll < 0.72:
                # TLS (22%)
                local = random.choice(local_ips)
                remote = random.choice(remote_ips)
                pkt = self._mock_tls(local, remote)
            elif roll < 0.88:
                # TCP generic (16%)
                local = random.choice(local_ips)
                remote = random.choice(remote_ips)
                pkt = self._mock_tcp(local, remote)
            else:
                # UDP generic (12%)
                local = random.choice(local_ips)
                remote = random.choice(remote_ips)
                pkt = self._mock_udp(local, remote)

            if pkt:
                self.packet_count += 1
                self.total_bytes += pkt["size"]
                self._bandwidth_window.append((time.time(), pkt["size"]))
                pkt["number"] = self.packet_count

                proto = pkt["protocol"]
                if proto in self.protocol_counts:
                    self.protocol_counts[proto] += 1
                else:
                    self.protocol_counts["Other"] += 1

                self.active_hosts.add(pkt["src"])
                self.active_hosts.add(pkt["dst"])

                try:
                    self.packet_queue.put_nowait(pkt)
                except queue.Full:
                    try:
                        self.packet_queue.get_nowait()
                        self.packet_queue.put_nowait(pkt)
                    except queue.Empty:
                        pass

            # Variable delay for realistic traffic bursts
            delay = random.uniform(0.02, 0.15)
            time.sleep(delay)

    def _make_id(self):
        return hashlib.md5(
            f"{self.packet_count}{time.time()}{random.random()}".encode()
        ).hexdigest()[:12]

    def _mock_arp(self, local_ips, gateways, mac_local, mac_gateway):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        src = random.choice(local_ips + gateways)
        dst = random.choice(local_ips + gateways)
        is_request = random.random() < 0.6
        op = "Request" if is_request else "Reply"
        info = f"ARP {op}: Who has {dst}? Tell {src}" if is_request else f"ARP {op}: {src} is at {mac_local}"
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "ARP",
            "size": 42,
            "info": info,
            "flags": "",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": mac_local, "dst_mac": "FF:FF:FF:FF:FF:FF" if is_request else mac_gateway, "type": "0x0806"}},
                {"name": "ARP", "fields": {"operation": op, "sender_mac": mac_local, "sender_ip": src, "target_mac": "00:00:00:00:00:00" if is_request else mac_gateway, "target_ip": dst}},
            ],
            "raw_hex": "ffffffffffff" + "aabbcc112233" + "0806" + "0001080006040001" + "00" * 20,
            "eli5": self._generate_eli5("ARP", src, dst, info, []),
        }

    def _mock_icmp(self, local, remote):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_request = random.random() < 0.5
        icmp_type = 8 if is_request else 0
        desc = "Echo Request (Ping)" if is_request else "Echo Reply (Pong)"
        src = local if is_request else remote
        dst = remote if is_request else local
        size = random.choice([64, 84, 98])
        seq = random.randint(1, 500)
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "ICMP",
            "size": size,
            "info": f"ICMP {desc} id=0x{random.randint(0,0xffff):04x} seq={seq}",
            "flags": "",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64 if is_request else random.randint(48, 58), "protocol": 1, "src": src, "dst": dst, "length": size}},
                {"name": "ICMP", "fields": {"type": icmp_type, "code": 0, "description": desc}},
            ],
            "raw_hex": "4500" + f"{size:04x}" + "00000000" + f"{'40' if is_request else format(random.randint(48,58), '02x')}" + "01" + "00" * 20,
            "eli5": self._generate_eli5("ICMP", src, dst, desc, []),
        }

    def _mock_dns(self, local, dns_server, domain):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_query = random.random() < 0.5
        if is_query:
            src, dst = local, dns_server
            info = f"DNS Query: {domain} (A)"
            layers_dns = {"name": "DNS", "fields": {"type": "Query", "query_name": domain, "query_type": "A"}}
        else:
            src, dst = dns_server, local
            fake_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            info = f"DNS Response: {domain} → {fake_ip}"
            layers_dns = {"name": "DNS", "fields": {"type": "Response", "query_name": domain, "answers": [fake_ip]}}
        size = random.randint(60, 180)
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "DNS",
            "size": size,
            "info": info,
            "flags": "",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64, "protocol": 17, "src": src, "dst": dst, "length": size}},
                {"name": "UDP", "fields": {"src_port": 53 if not is_query else random.randint(49152, 65535), "dst_port": 53 if is_query else random.randint(49152, 65535), "length": size - 28}},
                layers_dns,
            ],
            "raw_hex": "4500" + f"{size:04x}" + "00" * 40,
            "eli5": self._generate_eli5("DNS", src, dst, info, []),
        }

    def _mock_http(self, local, remote, domain):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_request = random.random() < 0.5
        methods = ["GET", "POST", "PUT", "HEAD"]
        paths = ["/", "/api/v1/users", "/index.html", "/login", "/feed", "/search?q=cybersecurity", "/api/notifications"]
        if is_request:
            src, dst = local, remote
            method = random.choice(methods)
            path = random.choice(paths)
            info = f"{method} {path} HTTP/1.1 (Host: {domain})"
            size = random.randint(120, 600)
        else:
            src, dst = remote, local
            codes = [("200", "OK"), ("301", "Moved"), ("304", "Not Modified"), ("404", "Not Found")]
            code, msg = random.choice(codes)
            info = f"HTTP/1.1 {code} {msg}"
            size = random.randint(200, 4000)
        sport = random.randint(49152, 65535) if is_request else 80
        dport = 80 if is_request else random.randint(49152, 65535)
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "HTTP",
            "size": size,
            "info": info,
            "flags": "PA",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64, "protocol": 6, "src": src, "dst": dst, "length": size}},
                {"name": "TCP", "fields": {"src_port": sport, "dst_port": dport, "seq": random.randint(1000, 99999), "ack": random.randint(1000, 99999), "flags": "PA", "window": 65535}},
                {"name": "HTTP", "fields": {"raw": info}},
            ],
            "raw_hex": "4500" + f"{size:04x}" + "00" * 50,
            "eli5": self._generate_eli5("HTTP", src, dst, info, []),
        }

    def _mock_tls(self, local, remote):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_outgoing = random.random() < 0.5
        src = local if is_outgoing else remote
        dst = remote if is_outgoing else local
        tls_types = [
            ("Client Hello", 1),
            ("Server Hello", 2),
            ("Application Data", 23),
            ("Application Data", 23),
            ("Application Data", 23),
        ]
        tls_type, type_code = random.choice(tls_types)
        sport = random.randint(49152, 65535) if is_outgoing else 443
        dport = 443 if is_outgoing else random.randint(49152, 65535)
        size = random.randint(80, 1460)
        info = f"TLS {tls_type} → {dst}:{dport}"
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "TLS",
            "size": size,
            "info": info,
            "flags": "PA",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64, "protocol": 6, "src": src, "dst": dst, "length": size}},
                {"name": "TCP", "fields": {"src_port": sport, "dst_port": dport, "seq": random.randint(1000, 99999), "ack": random.randint(1000, 99999), "flags": "PA", "window": 65535}},
                {"name": "TLS", "fields": {"content_type": tls_type, "version": "TLS 1.3", "length": size - 54}},
            ],
            "raw_hex": "160303" + f"{size - 54:04x}" + "00" * 40,
            "eli5": self._generate_eli5("TLS", src, dst, info, []),
        }

    def _mock_tcp(self, local, remote):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_outgoing = random.random() < 0.5
        src = local if is_outgoing else remote
        dst = remote if is_outgoing else local
        sport = random.randint(49152, 65535)
        dport = random.choice([22, 3306, 5432, 8080, 8443, 3000, 6379, 27017])
        flag_options = ["S", "SA", "A", "PA", "FA", "R"]
        flag = random.choice(flag_options)
        seq = random.randint(1000, 999999)
        ack = random.randint(1000, 999999)
        size = random.randint(54, 1500)
        info = f"{sport} → {dport} [{flag}] Seq={seq} Ack={ack} Win=65535"
        port_services = {22: "SSH", 3306: "MySQL", 5432: "PostgreSQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 3000: "Dev-Server", 6379: "Redis", 27017: "MongoDB"}
        service = port_services.get(dport, "")
        if service:
            info += f" ({service})"
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "TCP",
            "size": size,
            "info": info,
            "flags": flag,
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64, "protocol": 6, "src": src, "dst": dst, "length": size}},
                {"name": "TCP", "fields": {"src_port": sport, "dst_port": dport, "seq": seq, "ack": ack, "flags": flag, "window": 65535}},
            ],
            "raw_hex": "4500" + f"{size:04x}" + "00" * 30,
            "eli5": self._generate_eli5("TCP", src, dst, info, []),
        }

    def _mock_udp(self, local, remote):
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        is_outgoing = random.random() < 0.5
        src = local if is_outgoing else remote
        dst = remote if is_outgoing else local
        sport = random.randint(49152, 65535)
        dport = random.choice([123, 161, 514, 1900, 5353])
        size = random.randint(60, 500)
        port_services = {123: "NTP", 161: "SNMP", 514: "Syslog", 1900: "SSDP/UPnP", 5353: "mDNS"}
        service = port_services.get(dport, "")
        info = f"{sport} → {dport} Len={size - 28}"
        if service:
            info += f" ({service})"
        return {
            "id": self._make_id(),
            "timestamp": ts,
            "src": src, "dst": dst,
            "protocol": "UDP",
            "size": size,
            "info": info,
            "flags": "",
            "layers": [
                {"name": "Ethernet", "fields": {"src_mac": "AA:BB:CC:11:22:33", "dst_mac": "DD:EE:FF:44:55:66", "type": "0x0800"}},
                {"name": "IPv4", "fields": {"version": 4, "ttl": 64, "protocol": 17, "src": src, "dst": dst, "length": size}},
                {"name": "UDP", "fields": {"src_port": sport, "dst_port": dport, "length": size - 28}},
            ],
            "raw_hex": "4500" + f"{size:04x}" + "00" * 20,
            "eli5": self._generate_eli5("UDP", src, dst, info, []),
        }

    # ── ELI5 Explanation Generator ─────────────────────────────

    def _generate_eli5(self, protocol, src, dst, info, layers):
        """Generate a human-readable 'Explain Like I'm 5' description."""
        local_prefixes = ("192.168.", "10.", "172.16.", "172.17.", "172.18.",
                          "172.19.", "172.20.", "172.21.", "172.22.", "172.23.",
                          "172.24.", "172.25.", "172.26.", "172.27.", "172.28.",
                          "172.29.", "172.30.", "172.31.")

        src_name = "your computer" if any(src.startswith(p) for p in local_prefixes) else f"a remote server ({src})"
        dst_name = "your computer" if any(dst.startswith(p) for p in local_prefixes) else f"a remote server ({dst})"

        # Known server names
        known_dns = {"8.8.8.8": "Google DNS", "1.1.1.1": "Cloudflare DNS", "8.8.4.4": "Google DNS", "208.67.222.222": "OpenDNS"}
        if src in known_dns:
            src_name = f"{known_dns[src]} ({src})"
        if dst in known_dns:
            dst_name = f"{known_dns[dst]} ({dst})"

        if any(src.startswith(p) for p in ("192.168.1.1", "10.0.0.1")):
            src_name = f"your router ({src})"
        if any(dst.startswith(p) for p in ("192.168.1.1", "10.0.0.1")):
            dst_name = f"your router ({dst})"

        if protocol == "DNS":
            if "Query" in info:
                domain = info.split("Query: ")[-1].split(" ")[0] if "Query: " in info else "a website"
                return f"🔍 {src_name.capitalize()} is asking {dst_name} for the IP address of \"{domain}\". This is like looking up a phone number in a contacts list before making a call."
            else:
                return f"📬 {src_name.capitalize()} responded with the IP address for the requested website. Now {dst_name} knows where to connect!"
        elif protocol == "HTTP":
            if any(m in info for m in ["GET", "POST", "PUT", "DELETE", "HEAD"]):
                return f"🌐 {src_name.capitalize()} is requesting a web page from {dst_name} using plain HTTP (unencrypted). Anyone on the network could read this data!"
            else:
                return f"📄 {src_name.capitalize()} is sending back web page content to {dst_name}. This response contains the HTML, images, or data that was requested."
        elif protocol == "TLS":
            if "Client Hello" in info:
                return f"🔒 {src_name.capitalize()} is initiating a secure (encrypted) connection to {dst_name}. This is the first step of the TLS handshake — like a secret handshake before sharing private info."
            elif "Server Hello" in info:
                return f"🤝 {src_name.capitalize()} accepted the secure connection and is sending its digital certificate. This proves the server is who it claims to be."
            else:
                return f"🔐 Encrypted data is flowing between {src_name} and {dst_name}. Thanks to TLS encryption, no one else on the network can read this data."
        elif protocol == "TCP":
            if "S]" in info and "SA" not in info:
                return f"📡 {src_name.capitalize()} wants to start a new connection with {dst_name}. This SYN packet is the first step of the TCP 3-way handshake."
            elif "SA" in info:
                return f"✅ {src_name.capitalize()} agreed to connect! This SYN-ACK is step 2 of the TCP 3-way handshake. One more step to go."
            elif "FA" in info:
                return f"👋 {src_name.capitalize()} is gracefully closing the connection with {dst_name}. The conversation is ending."
            elif "R" in info and "R]" in info:
                return f"🚫 {src_name.capitalize()} forcefully reset the connection with {dst_name}. Something may have gone wrong, or the connection was refused."
            else:
                return f"📦 {src_name.capitalize()} is exchanging data with {dst_name} over TCP. TCP ensures every byte arrives in order and nothing is lost."
        elif protocol == "ARP":
            return f"📢 {src_name.capitalize()} is asking the local network: \"Who has IP {dst}?\" ARP maps IP addresses to physical MAC addresses on your local network."
        elif protocol == "ICMP":
            if "Request" in info or "Ping" in info:
                return f"🏓 {src_name.capitalize()} is pinging {dst_name} — \"Are you there?\" This is the most basic network connectivity test."
            elif "Reply" in info or "Pong" in info:
                return f"🏓 {src_name.capitalize()} replied to the ping — \"Yes, I'm here!\" The connection between the two devices is working."
            else:
                return f"⚠️ {src_name.capitalize()} sent an ICMP control message to {dst_name}. ICMP is used for network diagnostics and error reporting."
        elif protocol == "UDP":
            return f"📨 {src_name.capitalize()} sent a quick UDP datagram to {dst_name}. UDP is fast but unreliable — there's no guarantee the data arrived."
        else:
            return f"📡 Network traffic detected between {src_name} and {dst_name} using the {protocol} protocol."
