import json
import networkx as nx


def correlate_and_build_graph(stix_indicators, net_file, proc_file):
    G = nx.DiGraph()
    G.add_node(
        "CTI Report: APT-42",
        label="CTI Report: APT-42",
        color="#ff4d4d"
    )

    try:
        with open(net_file, 'r', encoding='utf-8-sig') as f:
            net_conns = json.load(f)
        if isinstance(net_conns, dict):
            net_conns = [net_conns]
    except Exception:
        net_conns = []

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
                    "IP": ip,
                    "LocalPort": conn.get("LocalPort"),
                    "PID": pid,
                    "ProcessName": pname
                })

    return hits, G
