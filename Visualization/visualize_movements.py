import csv
import sys
import networkx as nx
from pyvis.network import Network
import re

def clean_port(address):
    """
    remove :port suffix
    """
    if not address:
            return address
    return re.sub(r':\d+$','',address)

def load_and_merge_csvs(filepaths):
    """
    read CSV files and return list of rows.
    """
    merged = []
    for path in filepaths:
        with open(path, encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                merged.append(row)
    return merged

def build_graph(records):
    """
    build networkx.DiGraph and aggregate attributes on edges.
    """
    G = nx.DiGraph()
    for r in records:
        direction = r.get('direction').lower()
        src = clean_port(r.get('src'))
        dst = clean_port(r.get('dst'))


        if direction not in {'inbound', 'outbound'}:
            continue

        if direction == 'outbound' and not dst:
            #on recupere dans ce cas le champs Target
            dst = r.get('server_name')

        if not src or not dst:
            continue
        
        proto = r.get('protocol', 'UNKNOWN')
        start = r.get('start_time', '')
        end = r.get('end_time', '')
        user = r.get('user', '')

        
        # ensure nodes exist
        if not G.has_node(src):
            G.add_node(src, title=src)
        if not G.has_node(dst):
            G.add_node(dst, title=dst)

        if G.has_edge(src, dst):
            attrs = G.get_edge_data(src, dst) or {}
            existing_users = [u for u in (attrs.get('users_list') or '').split(';') if u]
            existing_protos = [p for p in (attrs.get('protocols_list') or '').split(';') if p]
            existing_dirs = [d for d in (attrs.get('directions_list') or '').split(';') if d]

            if user and user not in existing_users:
                existing_users.append(user)
            if proto and proto not in existing_protos:
                existing_protos.append(proto)
            if direction and direction not in existing_dirs:
                existing_dirs.append(direction)

            attrs['users_list'] = ';'.join(existing_users)
            attrs['protocols_list'] = ';'.join(existing_protos)
            attrs['directions_list'] = ';'.join(existing_dirs)
            attrs['title'] = f"Users: {attrs['users_list'] or '-'}  |  Protocols: {attrs['protocols_list'] or '-'}  |  Directions: {attrs['directions_list'] or '-'}"

            G[src][dst].update(attrs)
        else:
            G.add_edge(src, dst,
                       users_list=(user or ''),
                       protocols_list=(proto or ''),
                       title=f"Users: {user or '-'}  |  Protocols: {proto or '-'}  |  Directions: {direction or '-'}",
                       directions_list=(direction or ''))
    return G

def visualize_pyvis(G, output_html=None):
    """
    Render the graph to an interactive HTML file using PyVis.
    """
    net = Network(height='800px', width='100%', directed=True, notebook=False)

    for n, n_attrs in G.nodes(data=True):
        net.add_node(n, title=n_attrs.get('title', n))

    color_map = {
        "RDP": "red",
        "Powershell Remoting": "blue",
        "MIXED": "green",
        "UNKNOWN":"gray"

    }

    for u, v, data in G.edges(data=True):
        users_list = (data.get('users_list') or '')
        protos_list = (data.get('protocols_list') or '')

        proto_candidates = [p.strip() for p in protos_list.split(';') if p.strip()]
        unique_protos = sorted(set(proto_candidates))

        if len(unique_protos) == 1:
            proto = unique_protos[0]
        elif len(unique_protos) == 0:
            proto = 'UNKNOWN'
        else:
            proto = 'MIXED' 
        
        directions_list = (data.get('directions_list') or '')
        dir_candidates = [d.strip() for d in directions_list.split(';') if d.strip()]
        color = color_map.get(proto, "gray")

        # decide smoothing:
        if len(set(dir_candidates)) > 1:
            smooth_type = 'dynamic'   # mixed -> no forced curve
        elif dir_candidates:
            d = dir_candidates[0].lower()
            if d == 'outbound':
                smooth_type = 'curvedCW'
            elif d == 'inbound':
                smooth_type = 'curvedCCW'
            else:
                smooth_type = 'dynamic'
        else:
            smooth_type = 'dynamic'

        title = data.get('title') or f"Users: {users_list or '-'}  |  Protocols: {protos_list or '-'}"

        net.add_edge(u, v,
                     title=title,
                     color=color,
                     arrows='to',
                     smooth={'enabled': True, 'type': smooth_type, 'roundness': 0.15})
                     

    if output_html is None:
        from datetime import datetime
        date_suffix = datetime.now().strftime("%d%m%Y_%H%M")
        output_html = f"lateral_movement_{date_suffix}.html"

    net.toggle_physics(True)
    net.show(output_html, notebook=False)
    print(f"Generated interactive graph → {output_html}")


if __name__ == "__main__":
    # Usage: python visualize_movements.py sessions1.csv sessions2.csv ...
    if len(sys.argv) < 2:
        print("Usage: python visualize_movements.py <sessions.csv> [more.csv ...]")
        sys.exit(1)

    filepaths = sys.argv[1:]
    records = load_and_merge_csvs(filepaths)
    G = build_graph(records)
    visualize_pyvis(G)
