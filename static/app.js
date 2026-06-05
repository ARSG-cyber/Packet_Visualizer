/* ═══════════════════════════════════════════════════════════════
   PacketPulse — Frontend Application Logic
   WebSocket client, real-time packet rendering, Chart.js, inspector
   ═══════════════════════════════════════════════════════════════ */

(function () {
    'use strict';

    // ── State ──────────────────────────────────────────────────
    const MAX_TABLE_ROWS = 800;
    let ws = null;
    let isPaused = false;
    let activeFilter = 'all';
    let selectedPacketId = null;
    let allPackets = [];      // master packet list (capped)
    let autoScroll = true;

    // ── DOM References ─────────────────────────────────────────
    const $ = (sel) => document.querySelector(sel);
    const statusBadge = $('#status-badge');
    const statusText = $('#status-text');
    const modeBadge = $('#mode-badge');
    const modeText = $('#mode-text');
    const btnPause = $('#btn-pause');
    const btnResume = $('#btn-resume');
    const btnClear = $('#btn-clear');
    const packetTbody = $('#packet-tbody');
    const tableWrapper = $('#packet-table-wrapper');
    const eli5Text = $('#eli5-text');
    const inspectorContent = $('#inspector-content');

    // Metric values
    const valPackets = $('#val-packets');
    const valPps = $('#val-pps');
    const valBandwidth = $('#val-bandwidth');
    const valBytes = $('#val-bytes');
    const valHosts = $('#val-hosts');

    // ── Charts Setup ───────────────────────────────────────────
    const BANDWIDTH_POINTS = 60;
    const bandwidthData = new Array(BANDWIDTH_POINTS).fill(0);
    const bandwidthLabels = new Array(BANDWIDTH_POINTS).fill('');

    const PROTOCOL_COLORS = {
        TCP:   '#00e5ff',
        UDP:   '#ff7b00',
        DNS:   '#a855f7',
        HTTP:  '#10b981',
        TLS:   '#22d3ee',
        ICMP:  '#f43f5e',
        ARP:   '#fb923c',
        Other: '#6b7280',
    };

    // Bandwidth Line Chart
    const bwCtx = document.getElementById('chart-bandwidth').getContext('2d');
    const bandwidthChart = new Chart(bwCtx, {
        type: 'line',
        data: {
            labels: bandwidthLabels,
            datasets: [{
                data: bandwidthData,
                borderColor: '#00e5ff',
                backgroundColor: 'rgba(0, 229, 255, 0.08)',
                borderWidth: 2,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 3,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 300 },
            plugins: {
                legend: { display: false },
                tooltip: {
                    backgroundColor: '#1a1d27',
                    titleColor: '#e8eaf0',
                    bodyColor: '#8b8fa4',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    padding: 10,
                    displayColors: false,
                    callbacks: {
                        label: (ctx) => formatBytes(ctx.raw) + '/s',
                    },
                },
            },
            scales: {
                x: { display: false },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.04)', drawBorder: false },
                    ticks: {
                        color: '#555970',
                        font: { family: "'JetBrains Mono'", size: 10 },
                        callback: (v) => formatBytes(v),
                        maxTicksLimit: 4,
                    },
                },
            },
        },
    });

    // Protocol Doughnut Chart
    const protoCtx = document.getElementById('chart-protocols').getContext('2d');
    const protocolChart = new Chart(protoCtx, {
        type: 'doughnut',
        data: {
            labels: Object.keys(PROTOCOL_COLORS),
            datasets: [{
                data: new Array(Object.keys(PROTOCOL_COLORS).length).fill(0),
                backgroundColor: Object.values(PROTOCOL_COLORS).map(c => c + '30'),
                borderColor: Object.values(PROTOCOL_COLORS),
                borderWidth: 2,
                hoverBorderWidth: 3,
                hoverOffset: 6,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '65%',
            animation: { duration: 400 },
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#8b8fa4',
                        font: { family: "'JetBrains Mono'", size: 11 },
                        padding: 8,
                        usePointStyle: true,
                        pointStyleWidth: 10,
                    },
                },
                tooltip: {
                    backgroundColor: '#1a1d27',
                    titleColor: '#e8eaf0',
                    bodyColor: '#8b8fa4',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1,
                    padding: 10,
                },
            },
        },
    });

    // ── WebSocket Connection ───────────────────────────────────

    function connect() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = `${protocol}//${window.location.host}/ws`;

        ws = new WebSocket(url);

        ws.onopen = () => {
            setStatus('live', 'Capturing');
            btnPause.disabled = false;
        };

        ws.onclose = () => {
            setStatus('error', 'Disconnected');
            btnPause.disabled = true;
            // Reconnect after delay
            setTimeout(connect, 3000);
        };

        ws.onerror = () => {
            setStatus('error', 'Connection Error');
        };

        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);

            if (msg.type === 'init' || msg.type === 'update') {
                if (msg.stats) updateStats(msg.stats);
                if (msg.packets && msg.packets.length > 0) {
                    addPackets(msg.packets);
                }
            }
        };
    }

    // ── Status Management ──────────────────────────────────────

    function setStatus(state, text) {
        statusBadge.className = `status-badge status-${state}`;
        statusText.textContent = text;
    }

    // ── Stats Update ───────────────────────────────────────────

    function updateStats(stats) {
        animateValue(valPackets, stats.packet_count);
        valPps.textContent = stats.pps;
        valBandwidth.textContent = formatBytes(stats.bandwidth_bps) + '/s';
        valBytes.textContent = formatBytes(stats.total_bytes);
        valHosts.textContent = stats.active_hosts;

        // Update mode badge
        modeText.textContent = stats.mode === 'mock' ? 'SIMULATION' : 'LIVE CAPTURE';

        // Update bandwidth chart
        bandwidthData.push(stats.bandwidth_bps);
        bandwidthData.shift();
        bandwidthLabels.push('');
        bandwidthLabels.shift();
        bandwidthChart.update('none');

        // Update protocol chart
        const protoKeys = Object.keys(PROTOCOL_COLORS);
        const protoValues = protoKeys.map(k => stats.protocols[k] || 0);
        protocolChart.data.datasets[0].data = protoValues;
        protocolChart.update('none');

        // Update paused state display
        if (stats.is_running && isPaused) {
            // Server resumed
        }
    }

    function animateValue(el, newVal) {
        const formatted = typeof newVal === 'number' ? newVal.toLocaleString() : newVal;
        if (el.textContent !== formatted) {
            el.textContent = formatted;
            el.classList.remove('flash');
            void el.offsetWidth; // trigger reflow
            el.classList.add('flash');
        }
    }

    // ── Packet Rendering ───────────────────────────────────────

    function addPackets(packets) {
        const fragment = document.createDocumentFragment();

        for (const pkt of packets) {
            allPackets.push(pkt);

            // Apply filter
            if (activeFilter !== 'all' && pkt.protocol !== activeFilter) {
                continue;
            }

            const row = createPacketRow(pkt);
            fragment.appendChild(row);
        }

        // Trim allPackets
        if (allPackets.length > MAX_TABLE_ROWS * 2) {
            allPackets = allPackets.slice(-MAX_TABLE_ROWS);
        }

        // Trim visible rows
        while (packetTbody.children.length > MAX_TABLE_ROWS) {
            packetTbody.removeChild(packetTbody.firstChild);
        }

        packetTbody.appendChild(fragment);

        // Auto-scroll to bottom
        if (autoScroll) {
            tableWrapper.scrollTop = tableWrapper.scrollHeight;
        }
    }

    function createPacketRow(pkt) {
        const tr = document.createElement('tr');
        tr.className = 'new-row';
        tr.dataset.id = pkt.id;

        tr.innerHTML = `
            <td class="col-no">${pkt.number}</td>
            <td class="col-time">${pkt.timestamp}</td>
            <td class="col-src">${pkt.src}</td>
            <td class="col-dst">${pkt.dst}</td>
            <td class="col-proto"><span class="proto-badge proto-${pkt.protocol}">${pkt.protocol}</span></td>
            <td class="col-size" style="text-align:right">${pkt.size}</td>
            <td class="col-info" title="${escapeHtml(pkt.info)}">${escapeHtml(pkt.info)}</td>
        `;

        tr.addEventListener('click', () => selectPacket(pkt, tr));

        // Remove animation class after it plays
        tr.addEventListener('animationend', () => tr.classList.remove('new-row'));

        return tr;
    }

    // ── Packet Selection & Inspector ───────────────────────────

    function selectPacket(pkt, row) {
        // Deselect previous
        const prev = packetTbody.querySelector('.selected');
        if (prev) prev.classList.remove('selected');

        row.classList.add('selected');
        selectedPacketId = pkt.id;

        // Update ELI5
        eli5Text.textContent = pkt.eli5 || 'No explanation available for this packet.';
        eli5Text.classList.add('active-eli5');

        // Render inspector
        renderInspector(pkt);
    }

    function renderInspector(pkt) {
        let html = '';

        // Summary header
        html += `
            <div style="margin-bottom:10px; padding:8px 12px; background:var(--bg-card); border-radius:var(--radius-sm); border:1px solid var(--border-subtle);">
                <div style="font-size:13px; font-weight:700; color:var(--text-bright); margin-bottom:4px;">
                    Packet #${pkt.number} — <span class="proto-badge proto-${pkt.protocol}" style="font-size:11px">${pkt.protocol}</span>
                </div>
                <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">
                    ${pkt.src} → ${pkt.dst} | ${pkt.size} bytes
                </div>
            </div>
        `;

        // Layers
        if (pkt.layers && pkt.layers.length > 0) {
            for (let i = 0; i < pkt.layers.length; i++) {
                const layer = pkt.layers[i];
                const isOpen = i === pkt.layers.length - 1; // open last layer by default
                html += renderLayer(layer, isOpen);
            }
        }

        // Raw Hex
        if (pkt.raw_hex) {
            const formattedHex = formatHex(pkt.raw_hex);
            html += `
                <div class="inspector-hex">
                    <h4>Raw Hex Dump</h4>
                    <div class="hex-content">${formattedHex}</div>
                </div>
            `;
        }

        inspectorContent.innerHTML = html;

        // Bind layer toggles
        inspectorContent.querySelectorAll('.inspector-layer-header').forEach(header => {
            header.addEventListener('click', () => {
                const arrow = header.querySelector('.arrow');
                const fields = header.nextElementSibling;
                arrow.classList.toggle('open');
                fields.classList.toggle('open');
            });
        });
    }

    function renderLayer(layer, defaultOpen) {
        let fieldsHtml = '';
        if (layer.fields) {
            for (const [key, value] of Object.entries(layer.fields)) {
                const displayVal = Array.isArray(value) ? value.join(', ') : String(value);
                fieldsHtml += `
                    <div class="inspector-field">
                        <span class="inspector-field-key">${key}</span>
                        <span class="inspector-field-value">${escapeHtml(displayVal)}</span>
                    </div>
                `;
            }
        }

        return `
            <div class="inspector-layer">
                <div class="inspector-layer-header">
                    <span class="arrow ${defaultOpen ? 'open' : ''}">▶</span>
                    <span class="inspector-layer-name">${escapeHtml(layer.name)}</span>
                </div>
                <div class="inspector-layer-fields ${defaultOpen ? 'open' : ''}">
                    ${fieldsHtml}
                </div>
            </div>
        `;
    }

    // ── Filters ────────────────────────────────────────────────

    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeFilter = btn.dataset.filter;
            rebuildTable();
        });
    });

    function rebuildTable() {
        packetTbody.innerHTML = '';
        const filtered = activeFilter === 'all'
            ? allPackets
            : allPackets.filter(p => p.protocol === activeFilter);

        const toShow = filtered.slice(-MAX_TABLE_ROWS);
        const fragment = document.createDocumentFragment();
        for (const pkt of toShow) {
            fragment.appendChild(createPacketRow(pkt));
        }
        packetTbody.appendChild(fragment);

        if (autoScroll) {
            tableWrapper.scrollTop = tableWrapper.scrollHeight;
        }
    }

    // ── Controls ───────────────────────────────────────────────

    btnPause.addEventListener('click', () => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: 'pause' }));
            isPaused = true;
            btnPause.classList.add('hidden');
            btnResume.classList.remove('hidden');
            setStatus('paused', 'Paused');
        }
    });

    btnResume.addEventListener('click', () => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: 'resume' }));
            isPaused = false;
            btnResume.classList.add('hidden');
            btnPause.classList.remove('hidden');
            setStatus('live', 'Capturing');
        }
    });

    btnClear.addEventListener('click', () => {
        allPackets = [];
        packetTbody.innerHTML = '';
        selectedPacketId = null;
        inspectorContent.innerHTML = `
            <div class="inspector-empty">
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1" opacity="0.3">
                    <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
                <p>Click on a packet to inspect its layers, headers, and raw hex data.</p>
            </div>
        `;
        eli5Text.textContent = 'Select a packet above to see a plain-English explanation of what it does and why it matters.';
        eli5Text.classList.remove('active-eli5');
    });

    // Detect manual scroll (disable auto-scroll)
    tableWrapper.addEventListener('scroll', () => {
        const atBottom = tableWrapper.scrollTop + tableWrapper.clientHeight >= tableWrapper.scrollHeight - 50;
        autoScroll = atBottom;
    });

    // ── Utility Functions ──────────────────────────────────────

    function formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(Math.max(bytes, 1)) / Math.log(1024));
        const idx = Math.min(i, units.length - 1);
        return (bytes / Math.pow(1024, idx)).toFixed(idx > 0 ? 1 : 0) + ' ' + units[idx];
    }

    function formatHex(hex) {
        // Format as groups of 2 characters with space separation
        let result = '';
        for (let i = 0; i < hex.length; i += 2) {
            result += hex.substr(i, 2) + ' ';
            if ((i + 2) % 32 === 0) result += '\n';
        }
        return result.trim();
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // ── Initialize ─────────────────────────────────────────────
    connect();

})();
