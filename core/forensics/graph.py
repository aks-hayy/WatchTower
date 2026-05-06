# core/forensics/graph.py

import json
import ipaddress
import os
from typing import Dict, List, Set, Tuple, Optional
from core.forensics.models import ForensicReport, EntityProfile

class ForensicGraphGenerator:
    """Forensic Graph Generator using the high-fidelity Watchtower HUD design."""

    @staticmethod
    def generate_cytoscape_html(report: ForensicReport) -> str:
        """Adapts ForensicReport data into the high-fidelity NetworkGraphGenerator template."""
        
        # 1. Collect all unique IPs from entities and streams
        all_ips = set(report.entities.keys())
        if hasattr(report, 'streams') and report.streams:
            for flow_id in report.streams.keys():
                all_ips.add(flow_id[0])
                all_ips.add(flow_id[1])

        # 2. Map IPs to the node format expected by the template
        nodes = []
        high_risk_count = 0
        for ip in all_ips:
            profile = report.entities.get(ip)
            
            # Classification logic
            group = None
            if ForensicGraphGenerator._is_internal(ip):
                group = "Internal Network"
            else:
                group = ForensicGraphGenerator._get_cloud_group(ip) or "External"
            
            risk = profile.risk_score if profile else 0
            if risk > 500: high_risk_count += 1

            nodes.append({
                "id": ip,
                "risk": risk,
                "hostname": (profile.hostname if profile else "N/A") or "N/A",
                "user": (profile.user if profile else "System") or "System",
                "os": (profile.os if profile else "Unknown") or "Unknown",
                "group": group
            })

        # 3. Map Flows to Edges
        edges = []
        seen_edges = set()
        if hasattr(report, 'streams') and report.streams:
            for flow_id in report.streams.keys():
                src, dst = flow_id[0], flow_id[1]
                if src == dst or "127.0.0.1" in (src, dst): continue
                if dst.startswith(("224.", "239.")) or dst == "255.255.255.255": continue
                
                pair = tuple(sorted((src, dst)))
                if pair not in seen_edges:
                    edges.append([src, dst])
                    seen_edges.add(pair)

        # 4. Fill Template
        title = "Watchtower"
        wordmark = f"{title} · {report.source.upper() if report.source else 'FORENSICS'}"
        
        # We use json.dumps for the data to ensure it's safe for JS
        html_content = ForensicGraphGenerator.TOPOLOGY_TEMPLATE.format(
            title=title,
            wordmark=wordmark,
            high_risk_count=high_risk_count,
            raw_json=json.dumps(nodes),
            edge_json=json.dumps(edges)
        )
        
        return html_content

    @staticmethod
    def _is_internal(ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_link_local
        except ValueError: return False

    @staticmethod
    def _get_cloud_group(ip: str) -> Optional[str]:
        # Compacted prefixes for clarity
        azure = ("13.64.", "13.65.", "13.67.", "13.69.", "13.71.", "13.74.", "13.77.", "13.89.", "13.107.", "20.0.", "20.1.", "20.2.", "20.3.", "20.4.", "20.5.", "20.6.", "20.7.", "20.8.", "20.9.", "20.10.", "40.64.", "40.77.", "52.1.", "52.239.", "104.40.")
        gcp = ("8.8.8.", "8.8.4.", "34.0.", "34.1.", "34.2.", "35.184.", "35.190.", "142.250.", "172.217.")
        cloudflare = ("104.16.", "104.17.", "104.18.", "104.19.", "172.64.", "172.67.", "162.158.")
        
        if any(ip.startswith(p) for p in azure): return "Azure"
        if any(ip.startswith(p) for p in gcp): return "GCP"
        if any(ip.startswith(p) for p in cloudflare): return "Cloudflare"
        return None

    # --- Design Template from graph_gen.py ---
    TOPOLOGY_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{title}</title>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        :root {{
            --bg: #080c12;
            --panel: rgba(10, 15, 24, 0.92);
            --border: rgba(255, 255, 255, 0.06);
            --accent: #3b82f6;
            --danger: #ef4444;
            --warn: #f59e0b;
            --text: #cbd5e1;
            --dim: #475569;
        }}
        html, body {{ width: 100%; height: 100%; overflow: hidden; background: var(--bg); font-family: 'JetBrains Mono', monospace; color: var(--text); }}
        #cy {{ position: absolute; inset: 0; z-index: 1; }}
        .hud {{ position: absolute; inset: 0; pointer-events: none; z-index: 10; padding: 20px; display: flex; flex-direction: column; justify-content: space-between; }}
        .top {{ display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; }}
        .wordmark {{ font-size: 11px; letter-spacing: 3px; color: rgba(255, 255, 255, 0.2); text-transform: uppercase; padding: 10px 0; pointer-events: none; }}
        .top-right {{ display: flex; gap: 8px; pointer-events: all; }}
        .pill {{ font-size: 10px; letter-spacing: 1px; padding: 7px 14px; border: 1px solid var(--border); border-radius: 4px; background: var(--panel); color: var(--dim); cursor: pointer; transition: color 0.2s, border-color 0.2s; backdrop-filter: blur(8px); }}
        .pill:hover {{ color: var(--text); border-color: rgba(255, 255, 255, 0.15); }}
        .pill.active {{ color: #fff; border-color: rgba(255, 255, 255, 0.25); }}
        .bottom {{ display: flex; justify-content: space-between; align-items: flex-end; gap: 20px; }}
        .stats {{ display: flex; gap: 24px; pointer-events: none; }}
        .stat-n {{ font-size: 22px; letter-spacing: -1px; color: #fff; line-height: 1; }}
        .stat-n.red {{ color: var(--danger); }}
        .stat-n.blue {{ color: var(--accent); }}
        .stat-lbl {{ font-size: 9px; letter-spacing: 2px; color: var(--dim); margin-top: 3px; }}
        .inspector {{ pointer-events: all; background: var(--panel); border: 1px solid var(--border); border-radius: 6px; padding: 18px; width: 240px; backdrop-filter: blur(12px); opacity: 0; transform: translateY(6px); transition: opacity 0.25s ease, transform 0.25s ease; }}
        .inspector.show {{ opacity: 1; transform: translateY(0); }}
        .ins-ip {{ font-size: 13px; color: #fff; margin-bottom: 14px; word-break: break-all; line-height: 1.4; }}
        .ins-row {{ display: flex; justify-content: space-between; gap: 8px; padding: 6px 0; border-top: 1px solid var(--border); font-size: 10px; }}
        .ins-k {{ color: var(--dim); flex-shrink: 0; }}
        .ins-v {{ color: var(--text); text-align: right; word-break: break-all; }}
        .ins-v.red {{ color: var(--danger); }}
        .ins-v.blue {{ color: var(--accent); }}
        #tip {{ position: absolute; z-index: 20; pointer-events: none; background: var(--panel); border: 1px solid var(--border); border-radius: 4px; padding: 8px 12px; font-size: 10px; opacity: 0; transition: opacity 0.15s; backdrop-filter: blur(8px); white-space: nowrap; }}
        #tip.on {{ opacity: 1; }}
        #tip .t-ip {{ color: #fff; margin-bottom: 4px; }}
        #tip .t-row {{ color: var(--dim); }}
        #tip .t-row b {{ color: var(--text); font-weight: 400; }}
        .left-col {{ position: absolute; left: 20px; bottom: 20px; z-index: 10; display: flex; flex-direction: column; align-items: flex-start; gap: 8px; pointer-events: all; }}
        .collapsible {{ background: var(--panel); border: 1px solid var(--border); border-radius: 6px; backdrop-filter: blur(12px); overflow: hidden; transition: width 0.3s ease; width: 160px; }}
        .col-header {{ display: flex; align-items: center; justify-content: space-between; padding: 9px 12px; cursor: pointer; user-select: none; font-size: 9px; letter-spacing: 2px; color: var(--dim); text-transform: uppercase; transition: color 0.2s; }}
        .col-header:hover {{ color: var(--text); }}
        .col-arrow {{ font-size: 8px; color: var(--dim); transition: transform 0.25s ease; display: inline-block; }}
        .collapsible.open .col-arrow {{ transform: rotate(180deg); }}
        .col-body {{ max-height: 0; overflow: hidden; transition: max-height 0.3s ease, padding 0.3s ease; padding: 0 12px; }}
        .collapsible.open .col-body {{ max-height: 300px; padding: 0 12px 12px; }}
        .leg-item {{ display: flex; align-items: center; gap: 8px; padding: 4px 0; font-size: 10px; color: var(--dim); }}
        .leg-dot {{ width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }}
        .leg-line {{ width: 18px; height: 1px; flex-shrink: 0; }}
        .tl-body {{ display: flex; flex-direction: column; gap: 10px; }}
        .tl-time {{ font-size: 11px; color: var(--text); letter-spacing: 1px; text-align: center; min-height: 16px; }}
        input[type=range].tl-slider {{ -webkit-appearance: none; width: 100%; height: 14px; background: transparent; outline: none; cursor: pointer; display: block; padding: 0; margin: 0; }}
        input[type=range].tl-slider::-webkit-slider-runnable-track {{ height: 2px; border-radius: 2px; background: linear-gradient(to right, rgba(255, 255, 255, 0.9) var(--pct, 0%), rgba(255, 255, 255, 0.08) var(--pct, 0%)); }}
        input[type=range].tl-slider::-webkit-slider-thumb {{ -webkit-appearance: none; width: 14px; height: 14px; border-radius: 50%; background: #fff; border: 2px solid #080c12; box-shadow: 0 0 8px rgba(255, 255, 255, 0.5), 0 0 20px rgba(255, 255, 255, 0.15); cursor: pointer; margin-top: -6px; }}
        .search-wrap {{ position: absolute; top: 20px; left: 20px; z-index: 30; pointer-events: all; width: 220px; }}
        .search-box {{ display: flex; align-items: center; gap: 0; background: var(--panel); border: 1px solid var(--border); border-radius: 5px; backdrop-filter: blur(12px); overflow: visible; transition: border-color 0.2s; }}
        .search-input {{ flex: 1; background: none; border: none; outline: none; font-family: 'JetBrains Mono', monospace; font-size: 10px; color: var(--text); padding: 9px 10px; letter-spacing: 0.5px; min-width: 0; }}
        .search-input::placeholder {{ color: var(--dim); }}
        .search-clear {{ background: none; border: none; color: var(--dim); cursor: pointer; padding: 0 8px; font-size: 14px; line-height: 1; display: none; transition: color 0.15s; }}
        .search-clear.show {{ display: block; }}
        .search-icon {{ padding: 0 10px; color: var(--dim); font-size: 11px; cursor: default; border-left: 1px solid var(--border); height: 100%; display: flex; align-items: center; align-self: stretch; }}
        .search-dropdown {{ position: absolute; top: calc(100% + 4px); left: 0; right: 0; background: rgba(8, 12, 18, 0.97); border: 1px solid var(--border); border-radius: 5px; backdrop-filter: blur(16px); max-height: 260px; overflow-y: auto; opacity: 0; transform: translateY(-4px); pointer-events: none; transition: opacity 0.18s ease, transform 0.18s ease; z-index: 40; }}
        .search-dropdown.show {{ opacity: 1; transform: translateY(0); pointer-events: all; }}
        .dd-item {{ display: flex; align-items: center; gap: 9px; padding: 8px 12px; cursor: pointer; font-size: 10px; transition: background 0.12s; }}
        .dd-item:hover {{ background: rgba(255, 255, 255, 0.05); }}
        .dd-dot {{ width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }}
        .dd-ip {{ color: var(--text); flex: 1; }}
        .dd-tag {{ font-size: 9px; color: var(--dim); }}
        .tl-controls {{ display: flex; align-items: center; gap: 6px; }}
        .tl-play {{ width: 26px; height: 26px; border-radius: 4px; flex-shrink: 0; background: rgba(255, 255, 255, 0.07); border: 1px solid var(--border); color: #fff; cursor: pointer; display: flex; align-items: center; justify-content: center; font-size: 9px; transition: background 0.15s, border-color 0.15s; }}
        .tl-play.playing {{ background: rgba(239, 68, 68, 0.15); border-color: rgba(239, 68, 68, 0.4); color: #ef4444; }}
        .tl-speed {{ flex: 1; background: rgba(255, 255, 255, 0.05); border: 1px solid var(--border); border-radius: 4px; color: var(--dim); font-family: 'JetBrains Mono', monospace; font-size: 9px; padding: 5px 6px; cursor: pointer; outline: none; appearance: none; -webkit-appearance: none; letter-spacing: 0.5px; }}
    </style>
</head>
<body>
    <div id="cy"></div>
    <div id="tip"></div>

    <div class="search-wrap" id="search-wrap">
        <div class="search-box">
            <input class="search-input" id="search-input" type="text" placeholder="Search IP address..." autocomplete="off">
            <button class="search-clear" id="search-clear" onclick="clearSearch()">×</button>
            <div class="search-icon">⌕</div>
        </div>
        <div class="search-dropdown" id="search-dd"></div>
    </div>

    <div class="left-col">
        <div class="collapsible" id="tl-panel">
            <div class="col-header" onclick="togglePanel('tl-panel')"><span>Timeline</span><span class="col-arrow">▼</span></div>
            <div class="col-body"><div class="tl-body">
                <div class="tl-time" id="tl-time">Live</div>
                <input type="range" class="tl-slider" id="tl-slider" min="0" max="10" step="0.01" value="0">
                <div class="tl-controls">
                    <button class="tl-play" id="tl-play" onclick="togglePlay()">▶</button>
                    <select class="tl-speed" id="tl-speed">
                        <option value="0.5">0.5×</option><option value="1" selected>1×</option><option value="2">2×</option>
                    </select>
                </div>
            </div></div>
        </div>
        <div class="collapsible open" id="leg-panel">
            <div class="col-header" onclick="togglePanel('leg-panel')"><span>Legend</span><span class="col-arrow">▼</span></div>
            <div class="col-body">
                <div class="leg-item"><div class="leg-dot" style="background:#ef4444;"></div>Critical risk</div>
                <div class="leg-item"><div class="leg-dot" style="background:#3b82f6;"></div>Azure</div>
                <div class="leg-item"><div class="leg-line" style="background:rgba(255,255,255,0.12);"></div>Connection</div>
            </div>
        </div>
    </div>

    <div class="hud">
        <div class="top">
            <div class="wordmark">{wordmark}</div>
            <div class="top-right">
                <div class="pill active" id="btn-full" onclick="setMode('full')">All nodes</div>
                <div class="pill" id="btn-attack" onclick="setMode('attack')">Risk only</div>
            </div>
        </div>
        <div class="bottom">
            <div class="stats">
                <div class="stat"><div class="stat-n red" id="sn-risk">{high_risk_count}</div><div class="stat-lbl">High risk</div></div>
                <div class="stat"><div class="stat-n blue" id="sn-nodes">0</div><div class="stat-lbl">Nodes</div></div>
                <div class="stat"><div class="stat-n" id="sn-edges">0</div><div class="stat-lbl">Edges</div></div>
            </div>
            <div class="inspector" id="ins"><div class="ins-ip" id="ins-ip"></div><div id="ins-body"></div></div>
        </div>
    </div>

    <script>
        const raw = {raw_json};
        const edgePairs = {edge_json};

        const nodeColor = (d) => {{
            if (d.risk > 500) return '#ef4444';
            if (d.risk > 100) return '#f59e0b';
            if (d.risk > 0) return '#fb923c';
            if (d.group === 'Azure') return '#3b82f6';
            if (d.group === 'GCP') return '#10b981';
            return '#2d3f56';
        }};

        const elements = [
            ...raw.map(d => ({{ data: {{ ...d, color: nodeColor(d), size: d.risk > 500 ? 28 : 10 }} }})),
            ...edgePairs.map(([s, t], i) => {{
                const srcNode = raw.find(n => n.id === s);
                return {{ data: {{ id: `e${{i}}`, source: s, target: t, risk: srcNode ? srcNode.risk : 0 }} }};
            }})
        ];

        const cy = window.cy = cytoscape({{
            container: document.getElementById('cy'),
            elements,
            style: [
                {{ selector: 'node', style: {{ 'background-color': 'data(color)', 'width': 'data(size)', 'height': 'data(size)', 'label': 'data(id)', 'font-family': 'JetBrains Mono', 'font-size': '8px', 'color': '#cbd5e1', 'text-valign': 'bottom', 'text-outline-width': 2, 'text-outline-color': '#080c12' }} }},
                {{ selector: 'edge', style: {{ 'width': 0.6, 'line-color': 'rgba(255,255,255,0.05)', 'curve-style': 'straight' }} }},
                {{ selector: '.focus', style: {{ 'border-width': 2, 'border-color': '#fff', 'border-opacity': 0.9 }} }},
                {{ selector: '.fade', style: {{ 'opacity': 0.06 }} }}
            ],
            layout: {{ name: 'cose', randomize: true, animate: true }}
        }});

        // --- Stats ---
        document.getElementById('sn-nodes').textContent = cy.nodes().length;
        document.getElementById('sn-edges').textContent = cy.edges().length;

        // --- Search Engine ---
        const sInput = document.getElementById('search-input');
        const sDd = document.getElementById('search-dd');
        const sClear = document.getElementById('search-clear');
        const ipListSorted = [...raw].sort((a,b) => b.risk - a.risk);

        function renderDropdown(val) {{
            const filtered = val ? ipListSorted.filter(n => n.id.includes(val)) : ipListSorted;
            sDd.innerHTML = filtered.map(n => `
                <div class="dd-item" onclick="selectIP('${{n.id}}')">
                    <div class="dd-dot" style="background:${{nodeColor(n)}}"></div>
                    <span class="dd-ip">${{n.id}}</span>
                    <span class="dd-tag">${{n.risk > 0 ? n.risk : ''}}</span>
                </div>
            `).join('');
            sDd.classList.add('show');
        }}

        sInput.addEventListener('focus', () => renderDropdown(sInput.value));
        sInput.addEventListener('input', () => {{
            sClear.classList.toggle('show', sInput.value.length > 0);
            renderDropdown(sInput.value);
        }});
        
        window.selectIP = (id) => {{
            sInput.value = id; sDd.classList.remove('show');
            const n = cy.$id(id);
            cy.elements().removeClass('focus fade');
            n.addClass('focus').neighborhood().addClass('focus');
            cy.elements().not(n.closedNeighborhood()).addClass('fade');
            cy.animate({{ center: {{ eles: n }}, zoom: 2.2, duration: 600 }});
            showIns(n.data());
        }};

        window.clearSearch = () => {{
            sInput.value = ''; sClear.classList.remove('show'); sDd.classList.remove('show');
            cy.elements().removeClass('focus fade');
            document.getElementById('ins').classList.remove('show');
        }};

        // --- Timeline Engine ---
        const tlSlider = document.getElementById('tl-slider');
        const tlTime = document.getElementById('tl-time');
        const edgeTimings = {{}};
        cy.edges().forEach(e => edgeTimings[e.id()] = Math.random() * 9 + 0.5);

        function updateTimeline() {{
            const t = parseFloat(tlSlider.value);
            tlTime.textContent = t === 0 ? 'Live' : `T+${{t.toFixed(1)}}s`;
            tlSlider.style.setProperty('--pct', (t/10*100)+'%');
            cy.elements().forEach(el => {{
                if (t === 0) {{ el.style('opacity', 1); return; }}
                const et = edgeTimings[el.id()] || 0;
                el.style('opacity', t >= et ? 1 : 0.05);
            }});
        }}
        tlSlider.addEventListener('input', updateTimeline);

        let isPlaying = false;
        window.togglePlay = () => {{
            isPlaying = !isPlaying;
            document.getElementById('tl-play').textContent = isPlaying ? '■' : '▶';
            if (isPlaying) playLoop();
        }};
        function playLoop() {{
            if (!isPlaying) return;
            let val = parseFloat(tlSlider.value) + 0.05;
            if (val > 10) val = 0;
            tlSlider.value = val;
            updateTimeline();
            setTimeout(playLoop, 30);
        }}

        // --- UI Handlers ---
        window.setMode = (m) => {{
            document.getElementById('btn-full').classList.toggle('active', m === 'full');
            document.getElementById('btn-attack').classList.toggle('active', m === 'attack');
            if (m === 'attack') {{
                cy.nodes().forEach(n => n.style('display', n.data('risk') > 0 ? 'element' : 'none'));
                cy.edges().forEach(e => e.style('display', e.data('risk') > 0 ? 'element' : 'none'));
            }} else {{ cy.elements().style('display', 'element'); }}
        }};

        function showIns(d) {{
            document.getElementById('ins-ip').textContent = d.id;
            document.getElementById('ins-body').innerHTML = `
                <div class="ins-row"><span class="ins-k">hostname</span><span class="ins-v">${{d.hostname}}</span></div>
                <div class="ins-row"><span class="ins-k">user</span><span class="ins-v">${{d.user}}</span></div>
                <div class="ins-row"><span class="ins-k">os</span><span class="ins-v">${{d.os}}</span></div>
                <div class="ins-row"><span class="ins-k">risk</span><span class="ins-v ${{d.risk > 100 ? 'red' : ''}}">${{d.risk}}</span></div>
            `;
            document.getElementById('ins').classList.add('show');
        }}

        cy.on('tap', 'node', e => selectIP(e.target.id()));
        window.togglePanel = (id) => document.getElementById(id).classList.toggle('open');
    </script>
</body>
</html>
"""
