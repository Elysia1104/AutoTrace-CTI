import os
import re
import json
import networkx as nx
from stix2 import Indicator
from pyvis.network import Network
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, FileResponse
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="AutoTrace-CTI Incident Response Engine")

os.makedirs("D:\\AutoTrace-CTI\\output", exist_ok=True)

latest_correlation_hits = []

MITRE_MAPPING = {
    "IPv4": {"id": "T1071.001", "name": "Application Layer Protocol"},
    "Domain": {"id": "T1568", "name": "Dynamic Resolution"},
    "SHA256": {"id": "T1204.002", "name": "User Execution"},
    "Registry": {"id": "T1547.001", "name": "Boot/Logon Autostart"}
}

def extract_all_iocs(text):
    iocs = {
        "ips": list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text))),
        "domains": list(set(re.findall(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', text))),
        "sha256": list(set(re.findall(r'\b[a-fA-F0-9]{64}\b', text))),
        "registry": list(set(re.findall(r'(?:HKLM|HKCU)\\[a-zA-Z0-9_\\-]+', text, re.IGNORECASE)))
    }
    iocs["domains"] = [d for d in iocs["domains"] if not d.endswith(('.png', '.json', '.py', '.html'))]
    return iocs

def build_stix_indicators(iocs):
    stix_objects = []
    
    for ip in iocs["ips"]:
        try:
            ind = Indicator(name=f"IP - {ip}", pattern=f"[ipv4-addr:value = '{ip}']", pattern_type="stix")
            stix_objects.append({"type": "IPv4", "value": ip, "obj": ind})
        except Exception:
            stix_objects.append({"type": "IPv4", "value": ip, "obj": None})

    for domain in iocs["domains"]:
        try:
            ind = Indicator(name=f"Domain - {domain}", pattern=f"[domain-name:value = '{domain}']", pattern_type="stix")
            stix_objects.append({"type": "Domain", "value": domain, "obj": ind})
        except Exception:
            stix_objects.append({"type": "Domain", "value": domain, "obj": None})

    for hash_val in iocs["sha256"]:
        try:
            ind = Indicator(name=f"SHA256 - {hash_val[:8]}...", pattern=f"[file:hashes.'SHA-256' = '{hash_val}']", pattern_type="stix")
            stix_objects.append({"type": "SHA256", "value": hash_val, "obj": ind})
        except Exception:
            stix_objects.append({"type": "SHA256", "value": hash_val, "obj": None})

    for reg in iocs["registry"]:
        # Escape backslashes for STIX 2.1 pattern grammar validation
        escaped_reg = reg.replace("\\", "\\\\")
        try:
            ind = Indicator(name=f"Registry Key", pattern=f"[windows-registry-key:key = '{escaped_reg}']", pattern_type="stix")
            stix_objects.append({"type": "Registry", "value": reg, "obj": ind})
        except Exception:
            # Fallback if pattern validation encounters syntax variation
            stix_objects.append({"type": "Registry", "value": reg, "obj": None})

    return stix_objects

def correlate_and_build_graph(stix_indicators, net_file, proc_file):
    G = nx.DiGraph()
    G.add_node("CTI Feed", label="CTI Feed", color="#ff4d4d")
    
    try:
        with open(net_file, 'r', encoding='utf-8-sig') as f:
            net_conns = json.load(f)
        if isinstance(net_conns, dict): net_conns = [net_conns]
    except Exception: net_conns = []

    try:
        with open(proc_file, 'r', encoding='utf-8-sig') as f:
            processes = json.load(f)
        if isinstance(processes, dict): processes = [processes]
        proc_dict = {p.get("Id"): p.get("ProcessName") for p in processes}
    except Exception: proc_dict = {}

    hits = []

    for item in stix_indicators:
        ioc_type = item["type"]
        val = item["value"]
        mitre = MITRE_MAPPING.get(ioc_type, {"id": "T1000", "name": "Unknown"})
        
        node_id = f"{ioc_type}: {val[:12]}..." if len(val) > 15 else f"{ioc_type}: {val}"
        G.add_node(node_id, label=f"{ioc_type}: {val[:15]}\n[{mitre['id']}]", color="#ffa64d")
        G.add_edge("CTI Feed", node_id)

        if ioc_type == "IPv4":
            matched = False
            for conn in net_conns:
                if conn.get("RemoteAddress") == val:
                    matched = True
                    pid = conn.get("OwningProcess")
                    pname = proc_dict.get(pid, "Volatile Process")
                    socket_node = f"Port: {conn.get('LocalPort')}"
                    proc_node = f"PID: {pid} ({pname})"
                    
                    G.add_node(socket_node, label=socket_node, color="#ffff4d")
                    G.add_node(proc_node, label=proc_node, color="#4d94ff")
                    G.add_edge(node_id, socket_node)
                    G.add_edge(socket_node, proc_node)

                    hits.append({
                        "Type": ioc_type,
                        "Value": val,
                        "MITRE_ID": mitre["id"],
                        "MITRE_Name": mitre["name"],
                        "Artifact_Detail": f"Process: {pname} (PID {pid}), Port: {conn.get('LocalPort')}"
                    })
            if not matched:
                hits.append({
                    "Type": ioc_type,
                    "Value": val,
                    "MITRE_ID": mitre["id"],
                    "MITRE_Name": mitre["name"],
                    "Artifact_Detail": "Extracted Indicator (No Active Host Socket)"
                })
        else:
            hits.append({
                "Type": ioc_type,
                "Value": val,
                "MITRE_ID": mitre["id"],
                "MITRE_Name": mitre["name"],
                "Artifact_Detail": "Extracted Host/Registry Artifact"
            })

    return hits, G

def generate_pdf_report(hits, output_pdf_path):
    doc = SimpleDocTemplate(output_pdf_path, pagesize=letter)
    styles = getSampleStyleSheet()
    cell_style = ParagraphStyle('CellStyle', parent=styles['Normal'], fontSize=7, leading=9)
    story = []

    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor("#1A252C"))
    story.append(Paragraph("AutoTrace-CTI: Forensic & MITRE ATT&CK Summary", title_style))
    story.append(Spacer(1, 10))

    summary_text = f"<b>Execution Summary:</b> Identified <b>{len(hits)}</b> threat indicators."
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 12))

    table_data = [[
        Paragraph("<b>IoC Type</b>", cell_style),
        Paragraph("<b>Indicator</b>", cell_style),
        Paragraph("<b>MITRE ID</b>", cell_style),
        Paragraph("<b>Technique Name</b>", cell_style),
        Paragraph("<b>Host Details</b>", cell_style)
    ]]

    if hits:
        for h in hits:
            val_clean = str(h.get("Value")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            table_data.append([
                Paragraph(str(h.get("Type")), cell_style),
                Paragraph(val_clean, cell_style),
                Paragraph(str(h.get("MITRE_ID")), cell_style),
                Paragraph(str(h.get("MITRE_Name")), cell_style),
                Paragraph(str(h.get("Artifact_Detail")), cell_style)
            ])
    else:
        table_data.append([Paragraph("N/A", cell_style)] * 5)

    t = Table(table_data, colWidths=[50, 140, 55, 120, 155])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2C3E50")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#BDC3C7"))
    ]))

    story.append(t)
    doc.build(story)

generate_pdf_report([], "D:\\AutoTrace-CTI\\output\\forensic_report.pdf")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    html_content = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>AutoTrace-CTI Dashboard</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
    </head>
    <body class="bg-dark text-white p-4">
        <div class="container-fluid">
            <h1 class="mb-4">⚡ AutoTrace-CTI Engine</h1>
            <div class="row">
                <div class="col-md-5">
                    <div class="card bg-secondary text-white p-3 mb-3">
                        <h5>Ingest Live Threat Report</h5>
                        <form action="/analyze" method="post">
                            <textarea name="cti_text" class="form-control mb-3" rows="8" placeholder="Paste report here..."></textarea>
                            <button type="submit" class="btn btn-danger w-100 mb-2">Run Correlation & MITRE Mapping</button>
                        </form>
                        <a href="/download-pdf" target="_blank" class="btn btn-primary w-100">View SOC Forensic PDF Report</a>
                    </div>
                </div>
                <div class="col-md-7">
                    <div class="card bg-secondary text-white p-3">
                        <h5>Correlated Threat Graph</h5>
                        <iframe src="/graph" width="100%" height="480px" style="border:none; background:#fff;"></iframe>
                    </div>
                </div>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request, cti_text: str = Form(...)):
    global latest_correlation_hits
    extracted_iocs = extract_all_iocs(cti_text)
    stix_iocs = build_stix_indicators(extracted_iocs)
    
    hits, graph = correlate_and_build_graph(
        stix_iocs, 
        "D:\\AutoTrace-CTI\\data\\samples\\network_artifacts.json",
        "D:\\AutoTrace-CTI\\data\\samples\\process_artifacts.json"
    )
    
    latest_correlation_hits = hits
    
    net = Network(height="460px", width="100%", directed=True)
    net.from_nx(graph)
    net.set_options("""
    var options = {
      "physics": { "enabled": false },
      "layout": { "randomSeed": 42 }
    }
    """)
    net.write_html("D:\\AutoTrace-CTI\\output\\attack_graph.html")
    generate_pdf_report(latest_correlation_hits, "D:\\AutoTrace-CTI\\output\\forensic_report.pdf")
    
    return await home(request)

@app.get("/graph", response_class=HTMLResponse)
async def get_graph():
    graph_path = "D:\\AutoTrace-CTI\\output\\attack_graph.html"
    if os.path.exists(graph_path):
        with open(graph_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<h5 class='p-3 text-muted'>No graph generated yet.</h5>")

@app.get("/download-pdf")
async def download_pdf():
    pdf_path = "D:\\AutoTrace-CTI\\output\\forensic_report.pdf"
    generate_pdf_report(latest_correlation_hits, pdf_path)
    if os.path.exists(pdf_path):
        return FileResponse(pdf_path, media_type="application/pdf", headers={"Content-Disposition": "inline; filename=Forensic_Threat_Report.pdf"})
    return HTMLResponse(content="<h5>No PDF generated yet.</h5>")