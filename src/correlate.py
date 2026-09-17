import re
import json
import networkx as nx
from stix2 import Indicator
from pyvis.network import Network

sample_cti_report = """
[CRITICAL THREAT ALERT]
Threat Actor APT-42 active infrastructure detected.
Targeting enterprise endpoints using C2 node: 23.155.96.128
"""

def extract_iocs(text):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    return list(set(re.findall(ip_pattern, text)))

def build_stix_indicators(ip_list):
    return [Indicator(name=f"C2 IP Indicator - {ip}", pattern=f"[ipv4-addr:value = '{ip}']", pattern_type="stix") for ip in ip_list]

def correlate_and_build_graph(stix_indicators, net_file, proc_file):
    G = nx.DiGraph()
    G.add_node("CTI Report: APT-42", label="CTI Report: APT-42", color="#ff4d4d")
    
    with open(net_file, 'r', encoding='utf-8-sig') as f:
        net_conns = json.load(f)
    if isinstance(net_conns, dict):
        net_conns = [net_conns]

    try:
        with open(proc_file, 'r', encoding='utf-8-sig') as f:
            processes = json.load(f)
        if isinstance(processes, dict):
            processes = [processes]
        proc_dict = {p.get("Id"): p.get("ProcessName") for p in processes}
    except Exception:
        proc_dict = {}

    hits = []

    for ind in stix_indicators:
        ip = ind.pattern.split("'")[1]
        ip_node = f"STIX IP: {ip}"
        G.add_node(ip_node, label=ip_node, color="#ffa64d")
        G.add_edge("CTI Report: APT-42", ip_node)

        for conn in net_conns:
            if conn.get("RemoteAddress") == ip:
                pid = conn.get("OwningProcess")
                pname = proc_dict.get(pid, "Unknown/System")
                
                socket_node = f"Socket: Port {conn.get('LocalPort')}"
                proc_node = f"Process: {pname} (PID {pid})"
                
                G.add_node(socket_node, label=socket_node, color="#ffff4d")
                G.add_node(proc_node, label=proc_node, color="#4d94ff")
                
                G.add_edge(ip_node, socket_node)
                G.add_edge(socket_node, proc_node)

                hits.append({
                    "Matched_IP": ip,
                    "Process_ID": pid,
                    "Process_Name": pname,
                    "Local_Port": conn.get("LocalPort"),
                    "State": conn.get("State")
                })

    return hits, G

if __name__ == "__main__":
    print("[+] Extracting Threat Intelligence from CTI Report...")
    extracted_ips = extract_iocs(sample_cti_report)
    stix_iocs = build_stix_indicators(extracted_ips)
    print(f"[+] Generated {len(stix_iocs)} STIX 2.1 Indicator objects.")

    print("[+] Correlating network & process artifacts...")
    hits, graph = correlate_and_build_graph(
        stix_iocs, 
        "D:\\AutoTrace-CTI\\data\\samples\\network_artifacts.json",
        "D:\\AutoTrace-CTI\\data\\samples\\process_artifacts.json"
    )

    if hits:
        print(f"\n[!] THREAT CORRELATION MATCHES:\n{json.dumps(hits, indent=2)}")
        
        net = Network(height="600px", width="100%", directed=True)
        net.from_nx(graph)
        output_html = "D:\\AutoTrace-CTI\\output\\attack_graph.html"
        net.write_html(output_html)
        print(f"\n[+] Interactive Attack Graph exported to: {output_html}")
    else:
        print("[+] No active threats correlated.")
