# AskJOE Function Graph - Export binary function map, GUI, and optional Neo4j context layer
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @menupath Tools.SecurityJOES.Function Graph
# @runtime PyGhidra

"""
Export the binary's function call graph to Neo4j only (no file exports, no popup/browser).

Set [NEO4J] enabled = true in config.ini. Neo4j is the context layer for cross-sample analysis:
"Have I seen this API chain?", "Which samples had similar call patterns?", etc.
Requires: pip install neo4j and a running Neo4j instance.
"""

import os
import sys
import math

# AskJOE base dir; repo root must be on path for "import AskJOE"
_ASKJOE_DIR = os.path.dirname(os.path.abspath(__file__))
_repo_root = os.path.dirname(_ASKJOE_DIR)
if _repo_root not in sys.path:
    sys.path.insert(0, _repo_root)

try:
    from AskJOE.logging_utils import setup_logging, log_info, log_error, log_warning
except ImportError:
    def setup_logging(name):
        import logging
        logger = logging.getLogger(name)
        return logger, None
    def log_info(lg, msg): lg.info(msg) if lg else None
    def log_error(lg, msg): lg.error(msg) if lg else None
    def log_warning(lg, msg): lg.warning(msg) if lg else None

logger, _ = setup_logging("function_graph")


def _escape_html(text):
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _get_functions_and_calls(program):
    """Return (list of (addr_str, name, size), list of (caller_addr, callee_addr))."""
    if not program:
        return [], []
    func_manager = program.getFunctionManager()
    ref_manager = program.getReferenceManager()
    listing = program.getListing()

    nodes = []
    edges = []

    # Build set of function entry addresses for quick lookup
    entry_to_func = {}
    for func in func_manager.getFunctions(True):
        entry = func.getEntryPoint()
        if entry:
            entry_to_func[str(entry)] = func

    for func in func_manager.getFunctions(True):
        entry = func.getEntryPoint()
        if not entry:
            continue
        name = func.getName() or ("sub_%s" % entry)
        body = func.getBody()
        size = body.getNumAddresses() if body else 0
        addr_str = str(entry)
        nodes.append((addr_str, name, size))

        # References from this function (calls to other addresses)
        addr_iter = body.getAddresses(True)
        while addr_iter.hasNext():
            addr = addr_iter.next()
            refs = ref_manager.getReferencesFrom(addr)
            try:
                ref_list = list(refs) if hasattr(refs, "__iter__") else []
                if not ref_list and hasattr(refs, "iterator"):
                    riter = refs.iterator()
                    while riter.hasNext():
                        ref_list.append(riter.next())
            except Exception:
                ref_list = []
            for ref in ref_list:
                try:
                    if ref.getReferenceType().isCall():
                        to_addr = ref.getToAddress()
                        to_str = str(to_addr)
                        if to_str in entry_to_func:
                            edges.append((addr_str, to_str))
                except Exception:
                    pass

    return nodes, edges


def _safe_filename(name):
    """Make a string safe for use in file names."""
    return "".join(c if c.isalnum() or c in "._-" else "_" for c in name)


def _export_to_graphml(nodes, edges, graph_name, out_dir):
    """Write GraphML (XML) for Gephi, yEd, Cytoscape. No extra deps."""
    import xml.etree.ElementTree as ET
    safe = _safe_filename(graph_name)
    path = os.path.join(out_dir, "{}_callgraph.graphml".format(safe))
    root = ET.Element("graphml", xmlns="http://graphml.graphdrawing.org/xmlns")
    root.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
    root.set("xsi:schemaLocation", "http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd")
    ET.SubElement(root, "key", {"id": "name", "for": "node", "attr_name": "name", "attr_type": "string"})
    ET.SubElement(root, "key", {"id": "address", "for": "node", "attr_name": "address", "attr_type": "string"})
    ET.SubElement(root, "key", {"id": "size", "for": "node", "attr_name": "size", "attr_type": "long"})
    graph = ET.SubElement(root, "graph", id="G", edgedefault="directed")
    addr_to_id = {}
    for i, (addr_str, name, size) in enumerate(nodes):
        addr_to_id[addr_str] = "n{}".format(i)
        node = ET.SubElement(graph, "node", id=addr_to_id[addr_str])
        ET.SubElement(node, "data", key="name").text = str(name)
        ET.SubElement(node, "data", key="address").text = str(addr_str)
        ET.SubElement(node, "data", key="size").text = str(size)
    for j, (from_addr, to_addr) in enumerate(edges):
        eid = "e{}".format(j)
        if from_addr in addr_to_id and to_addr in addr_to_id:
            ET.SubElement(graph, "edge", id=eid, source=addr_to_id[from_addr], target=addr_to_id[to_addr])
    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    with open(path, "wb") as f:
        tree.write(f, encoding="utf-8", xml_declaration=True, default_namespace=None)
    return path


def _export_to_dot(nodes, edges, graph_name, out_dir):
    """Write DOT for Graphviz (dot -Tpng file.dot -o out.png). No extra deps."""
    safe = _safe_filename(graph_name)
    path = os.path.join(out_dir, "{}_callgraph.dot".format(safe))
    lines = ["digraph \"{}\" {{".format(graph_name.replace("\\", "\\\\").replace('"', '\\"'))]
    addr_to_id = {}
    for i, (addr_str, name, size) in enumerate(nodes):
        nid = "n{}".format(i)
        addr_to_id[addr_str] = nid
        label = "{} ({})".format(name, addr_str).replace("\\", "\\\\").replace('"', '\\"')
        lines.append('  {} [label="{}"];'.format(nid, label))
    for from_addr, to_addr in edges:
        if from_addr in addr_to_id and to_addr in addr_to_id:
            lines.append("  {} -> {};".format(addr_to_id[from_addr], addr_to_id[to_addr]))
    lines.append("}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return path


def _export_to_json(nodes, edges, graph_name, out_dir):
    """Write JSON (nodes + edges) for custom viewers or scripts. No extra deps."""
    import json
    safe = _safe_filename(graph_name)
    path = os.path.join(out_dir, "{}_callgraph.json".format(safe))
    data = {
        "binary": graph_name,
        "nodes": [{"address": a, "name": n, "size": s} for a, n, s in nodes],
        "edges": [{"from": a, "to": b} for a, b in edges],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    return path


def _export_to_html(nodes, edges, graph_name, out_dir):
    """Write a self-contained HTML viewer (open in browser, no install). Uses vis-network from CDN."""
    import json
    safe = _safe_filename(graph_name)
    path = os.path.join(out_dir, "{}_callgraph.html".format(safe))
    # Build node id -> label; vis-network needs node ids that match edge from/to
    addr_to_label = {}
    for a, n, s in nodes:
        addr_to_label[a] = "{} ({})".format(n, a) if n else a
    valid_addrs = set(addr_to_label)
    vis_nodes = [{"id": a, "label": addr_to_label[a], "title": "{} | size: {}".format(addr_to_label[a], s)} for a, n, s in nodes]
    vis_edges = [{"from": a, "to": b} for a, b in edges if a in valid_addrs and b in valid_addrs]
    data = {"binary": graph_name, "nodes": vis_nodes, "edges": vis_edges}
    json_str = json.dumps(data, indent=2)
    json_str = json_str.replace("</script>", "<\\/script>")
    html = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Call graph: {title}</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>
body {{ font-family: sans-serif; margin: 0; }}
#info {{ padding: 8px; background: #f0f0f0; }}
#mynetwork {{ width: 100%; height: calc(100vh - 40px); }}
</style>
</head>
<body>
<div id="info"><b>{title}</b> &ndash; {n} nodes, {e} edges. Drag to pan, scroll to zoom.</div>
<div id="mynetwork"></div>
<script>
var graphData = {json};
var nodes = new vis.DataSet(graphData.nodes);
var edges = new vis.DataSet(graphData.edges);
var container = document.getElementById("mynetwork");
var data = {{ nodes: nodes, edges: edges }};
var options = {{
  nodes: {{ shape: "box", font: {{ size: 12 }} }},
  edges: {{ arrows: "to" }},
  layout: {{ improvedLayout: true, hierarchical: false }}
}};
var network = new vis.Network(container, data, options);
</script>
</body>
</html>""".format(
        title=graph_name.replace("\\", "/").split("/")[-1],
        n=len(vis_nodes),
        e=len(vis_edges),
        json=json_str,
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path


# -----------------------------------------------------------------------------
# Neo4j context layer (optional): Binary + Function + CALLS for cross-sample analysis
# -----------------------------------------------------------------------------

def _get_neo4j_config():
    """Read [NEO4J] from config.ini. enabled = true to push graph to Neo4j."""
    try:
        import configparser
        cfg_path = os.path.join(_ASKJOE_DIR, "config.ini")
        if os.path.isfile(cfg_path):
            cfg = configparser.ConfigParser()
            cfg.read(cfg_path, encoding="utf-8")
            if cfg.has_section("NEO4J"):
                raw = cfg.get("NEO4J", "enabled", fallback="false").strip().lower()
                enabled = raw in ("true", "1", "yes")
                return {
                    "enabled": enabled,
                    "uri": cfg.get("NEO4J", "uri", fallback="bolt://localhost:7687"),
                    "user": cfg.get("NEO4J", "user", fallback="neo4j"),
                    "password": cfg.get("NEO4J", "password", fallback="password"),
                }
    except Exception:
        pass
    return {"enabled": False, "uri": "bolt://localhost:7687", "user": "neo4j", "password": "password"}


def _export_to_neo4j(nodes, edges, graph_name, uri, user, password):
    """
    Push function graph to Neo4j using batch Cypher (UNWIND + MERGE).
    Schema: (Binary)-[:HAS_FUNCTION]->(Function)-[:CALLS]->(Function).
    Enables cross-sample queries: same API chains, similar call patterns, etc.
    """
    try:
        from neo4j import GraphDatabase
    except ImportError:
        log_error(logger, "neo4j package not installed. Run: pip install neo4j")
        println("[-] neo4j not installed. Run: pip install neo4j")
        return False

    binary_id = _safe_filename(graph_name)
    driver = None
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))
        driver.verify_connectivity()
    except Exception as e:
        log_error(logger, "Neo4j connection failed: {}".format(e))
        println("[-] Neo4j connection failed: {}".format(e))
        println("[!] Start Neo4j (copy and run in a terminal):")
        println("    docker run -d --name neo4j -p 7474:7474 -p 7687:7687 -e NEO4J_AUTH=neo4j/your_password neo4j:5")
        println("[!] Then set config.ini [NEO4J] password = your_password")
        println("[!] Windows: ensure Docker Desktop is running first (npipe/docker daemon error = Docker not running).")
        println("[!] To remove the container later:")
        println("    docker stop neo4j && docker rm neo4j")
        return False

    try:
        with driver.session() as session:
            # 1) Ensure Binary node (sample) exists; updated on each run
            session.run(
                """
                MERGE (b:Binary {id: $binary_id})
                SET b.name = $binary_name, b.updated_at = datetime()
                """,
                binary_id=binary_id,
                binary_name=graph_name.replace("\\", "/").split("/")[-1],
            )
            # 2) Batch-merge Function nodes (UNWIND)
            node_list = [{"address": a, "name": n, "size": int(s) if s is not None else 0} for a, n, s in nodes]
            if node_list:
                session.run(
                    """
                    UNWIND $nodes AS n
                    MERGE (f:Function {address: n.address, binary: $binary_id})
                    SET f.name = n.name, f.size = n.size
                    WITH f
                    MATCH (b:Binary {id: $binary_id})
                    MERGE (b)-[:HAS_FUNCTION]->(f)
                    """,
                    nodes=node_list,
                    binary_id=binary_id,
                )
            # 3) Batch-merge CALLS relationships (only between functions in this binary)
            valid = set(a for a, _, _ in nodes)
            edge_list = [{"from_addr": a, "to_addr": b} for a, b in edges if a in valid and b in valid]
            if edge_list:
                session.run(
                    """
                    UNWIND $edges AS e
                    MATCH (a:Function {address: e.from_addr, binary: $binary_id})
                    MATCH (b:Function {address: e.to_addr, binary: $binary_id})
                    MERGE (a)-[:CALLS]->(b)
                    """,
                    edges=edge_list,
                    binary_id=binary_id,
                )
        log_info(logger, "Exported {} functions, {} calls to Neo4j (binary: {})".format(len(nodes), len(edges), binary_id))
        println("[+] Neo4j: {} functions, {} calls (binary: {})".format(len(nodes), len(edges), binary_id))
        return True
    except Exception as e:
        log_error(logger, "Neo4j write failed: {}".format(e))
        println("[-] Neo4j write failed: {}".format(e))
        return False
    finally:
        if driver:
            driver.close()


def _generate_and_open_graph_viewer(nodes, edges, binary_id, graph_name):
    """
    Generate a self-contained HTML graph viewer (vis-network) and open it in the default browser.
    Writes the file path to AskJOE/last_neo4j_graph_path.txt so the launcher can re-open it.
    """
    import json

    try:
        # Build vis-network nodes: id (address string), label (short name), title (tooltip)
        node_ids = {}
        vis_nodes = []
        for addr, name, size in nodes:
            aid = str(addr)
            node_ids[aid] = True
            label = (name or aid)[:24] + ("..." if len(name or "") > 24 else "")
            title = "{}  |  {}  |  size: {}".format(name or "(unnamed)", aid, size or 0)
            vis_nodes.append({"id": aid, "label": label, "title": title})
        # Build vis-network edges
        valid = set(str(a) for a, _, _ in nodes)
        vis_edges = []
        for a, b in edges:
            sa, sb = str(a), str(b)
            if sa in valid and sb in valid:
                vis_edges.append({"from": sa, "to": sb})
        nodes_json = json.dumps(vis_nodes)
        edges_json = json.dumps(vis_edges)
        binary_title = _escape_html((graph_name or binary_id).replace("_", " "))

        html = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8"/>
<title>AskJOE Function Graph – """ + binary_title + """</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style type="text/css">
  body { margin: 0; font-family: 'Segoe UI', Tahoma, sans-serif; background: #1e1e1e; color: #eee; }
  #header { padding: 10px 14px; background: #252526; border-bottom: 1px solid #333; }
  #mynetwork { width: 100%; height: calc(100vh - 50px); }
</style>
</head>
<body>
<div id="header"><b>AskJOE</b> Function Graph: """ + binary_title + """ &nbsp;|&nbsp; """ + str(len(vis_nodes)) + """ functions, """ + str(len(vis_edges)) + """ calls</div>
<div id="mynetwork"></div>
<script>
  var nodes = new vis.DataSet(""" + nodes_json + """);
  var edges = new vis.DataSet(""" + edges_json + """);
  var container = document.getElementById('mynetwork');
  var data = { nodes: nodes, edges: edges };
  var options = {
    nodes: { shape: 'dot', size: 12, font: { size: 10 } },
    edges: { arrows: 'to', width: 0.8 },
    physics: { enabled: true, barnesHut: { gravitationalConstant: -4000, springLength: 120 } },
    interaction: { hover: true, tooltipDelay: 100 }
  };
  var network = new vis.Network(container, data, options);
</script>
</body>
</html>"""

        log_dir = os.path.join(_ASKJOE_DIR, "logs")
        if not os.path.isdir(log_dir):
            try:
                os.makedirs(log_dir, exist_ok=True)
            except Exception:
                log_dir = _ASKJOE_DIR
        safe_id = "".join(c if c.isalnum() or c in "_-" else "_" for c in (binary_id or "graph"))
        graph_path = os.path.join(log_dir, "neo4j_graph_{}.html".format(safe_id[:64]))
        with open(graph_path, "w", encoding="utf-8") as f:
            f.write(html)
        path_file = os.path.join(_ASKJOE_DIR, "last_neo4j_graph_path.txt")
        json_file = os.path.join(_ASKJOE_DIR, "last_neo4j_graph.json")
        try:
            with open(path_file, "w", encoding="utf-8") as pf:
                pf.write(os.path.abspath(graph_path))
        except Exception:
            pass
        try:
            with open(json_file, "w", encoding="utf-8") as jf:
                json.dump({"nodes": vis_nodes, "edges": vis_edges, "title": binary_title}, jf)
        except Exception:
            pass
        log_info(logger, "Graph saved for embedded viewer: {}".format(graph_path))
        return graph_path
    except Exception as e:
        log_warning(logger, "Could not generate/open graph viewer: {}".format(e))
        return None


# Same report CSS as gui_utils for consistent look
_REPORT_CSS = """
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; font-size: 13px; line-height: 1.5; color: #1a1a1a; background: #f8f9fa; padding: 12px; margin: 0; }
h1 { font-size: 1.35em; color: #0d47a1; margin: 0.6em 0 0.3em 0; border-bottom: 1px solid #bbdefb; padding-bottom: 4px; }
h2 { font-size: 1.2em; color: #1565c0; margin: 0.5em 0 0.25em 0; }
p { margin: 0.35em 0; }
li { margin: 0.2em 0 0.2em 1.5em; }
"""


def _show_graph_window(report_body_html, title, program):
    """Show the graph report in a popup. No Java listener (PyGhidra cannot extend Java classes)."""
    try:
        from java.awt import EventQueue, BorderLayout
        from javax.swing import JFrame, JEditorPane, JScrollPane, WindowConstants
    except Exception:
        return False
    full_html = """<!DOCTYPE html><html><head><meta charset="UTF-8"/><title>{title}</title><style type="text/css">{css}</style></head><body>{body}</body></html>""".format(
        title=_escape_html(title), css=_REPORT_CSS, body=report_body_html
    )

    def _show():
        try:
            frame = JFrame(title)
            frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE)
            frame.setSize(900, 700)
            frame.setLocationRelativeTo(None)
            editor = JEditorPane()
            editor.setContentType("text/html")
            editor.setText(full_html)
            editor.setEditable(False)
            editor.setCaretPosition(0)
            scroll = JScrollPane(editor)
            scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED)
            scroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED)
            frame.getContentPane().add(scroll, BorderLayout.CENTER)
            frame.setVisible(True)
        except Exception as e:
            try:
                println("[-] Graph window failed: {}".format(e))
            except Exception:
                pass

    try:
        if EventQueue.isDispatchThread():
            _show()
        else:
            EventQueue.invokeLater(_show)
        return True
    except Exception:
        return False


def _open_html_in_browser(html_path):
    """Open the exported HTML file in the system default browser (Windows and Linux)."""
    try:
        import webbrowser
        path = os.path.abspath(html_path)
        if not os.path.isfile(path):
            return False
        try:
            from pathlib import Path
            url = Path(path).as_uri()
        except ImportError:
            from urllib.request import pathname2url
            url = "file://" + pathname2url(path)
        webbrowser.open(url)
        return True
    except Exception:
        pass
    return False


def _build_graph_report_html(nodes, edges, graph_name):
    """Build HTML for the in-Ghidra results window: summary + clickable SVG graph + function list."""
    short_name = graph_name.replace("\\", "/").split("/")[-1]
    n_nodes = len(nodes)
    n_edges = len(edges)

    # Clickable function list (always works in JEditorPane)
    list_items = []
    for addr_str, name, size in nodes:
        label = "{} ({})".format(_escape_html(name), _escape_html(addr_str))
        link = '<a href="ghidra:goTo/{}">{}</a>'.format(_escape_html(addr_str), label)
        list_items.append("<li>{}</li>".format(link))

    # Simple SVG graph: nodes in circle, edges as lines, each node clickable
    valid_addrs = set(a for a, _, _ in nodes)
    addr_to_idx = {a: i for i, (a, _, _) in enumerate(nodes)}
    cx, cy = 400, 280
    r = 220
    svg_parts = []
    # Edges first (so they appear under nodes)
    for from_addr, to_addr in edges:
        if from_addr not in addr_to_idx or to_addr not in addr_to_idx:
            continue
        i1, i2 = addr_to_idx[from_addr], addr_to_idx[to_addr]
        n = max(len(nodes), 1)
        a1 = 2 * math.pi * i1 / n - math.pi / 2
        a2 = 2 * math.pi * i2 / n - math.pi / 2
        x1 = cx + r * math.cos(a1)
        y1 = cy + r * math.sin(a1)
        x2 = cx + r * math.cos(a2)
        y2 = cy + r * math.sin(a2)
        svg_parts.append('<line x1="{}" y1="{}" x2="{}" y2="{}" stroke="#ccc" stroke-width="1"/>'.format(x1, y1, x2, y2))
    # Nodes as clickable links (circle + short label)
    for i, (addr_str, name, _) in enumerate(nodes):
        n = max(len(nodes), 1)
        a = 2 * math.pi * i / n - math.pi / 2
        x = cx + r * math.cos(a)
        y = cy + r * math.sin(a)
        # Truncate name for node label
        short = (name[:12] + "..") if len(name) > 14 else name
        svg_parts.append(
            '<a xlink:href="ghidra:goTo/{}">'
            '<circle cx="{}" cy="{}" r="14" fill="#1976d2" stroke="#0d47a1"/>'
            '<text x="{}" y="{}" text-anchor="middle" font-size="9" fill="#fff">{}</text>'
            "</a>".format(_escape_html(addr_str), x, y, x, y + 4, _escape_html(short))
        )
    svg_content = "\n".join(svg_parts)
    svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
        'width="800" height="560" viewBox="0 0 800 560" style="background:#f8f9fa;">'
        "{}</svg>".format(svg_content)
    )

    body = """
<h1>Function Graph: {title}</h1>
<p><b>{n_nodes}</b> functions, <b>{n_edges}</b> calls. The interactive graph opens in your browser. In Ghidra, use <b>Search &rarr; Go To Address</b> with an address from the list below.</p>
<div style="margin:1em 0; border:1px solid #cfd8dc; border-radius:4px; overflow:auto;">{svg}</div>
<h2>Functions (click to go to)</h2>
<ul style="column-count:2; margin:0.5em 0;">{list}</ul>
""".format(
        title=_escape_html(short_name),
        n_nodes=n_nodes,
        n_edges=n_edges,
        svg=svg,
        list="\n".join(list_items),
    )
    return body


def run():
    prog = None
    try:
        prog = currentProgram
    except NameError:
        pass
    if not prog:
        prog = globals().get("currentProgram")
    if not prog:
        println("[-] No program loaded. Open a binary first (File → Import).")
        return

    neo_cfg = _get_neo4j_config()
    if not neo_cfg.get("enabled"):
        println("[-] Function Graph uses Neo4j only. Set [NEO4J] enabled = true in config.ini.")
        return

    nodes, edges = _get_functions_and_calls(prog)
    if not nodes:
        println("[-] No functions found in the program.")
        return

    graph_name = (prog.getName() or "binary").replace(" ", "_").replace(".", "_")

    if monitor and hasattr(monitor, 'setMessage'):
        monitor.setMessage("AskJOE Function Graph: pushing to Neo4j...")

    println("Pushing function graph to Neo4j ({} functions, {} calls)...".format(len(nodes), len(edges)))
    try:
        ok = _export_to_neo4j(nodes, edges, graph_name, neo_cfg["uri"], neo_cfg["user"], neo_cfg["password"])
        if ok:
            println("[+] Done. Query the graph in Neo4j Browser (http://localhost:7474).")
            path = _generate_and_open_graph_viewer(nodes, edges, graph_name, graph_name)
            if path:
                println("[+] Graph saved. Embedded viewer will open in this window.")
        else:
            println("[!] Neo4j export failed (see above). Ensure Neo4j is running and config.ini [NEO4J] uri/user/password are correct. See README → Running Neo4j with Docker.")
    except Exception as e:
        log_warning(logger, "Neo4j export error: {}".format(e))
        println("[!] Neo4j: {}".format(e))

    if monitor and hasattr(monitor, 'setMessage'):
        monitor.setMessage("AskJOE Function Graph: done.")


try:
    run()
except Exception as e:
    log_error(logger, "Function Graph failed: {}".format(e))
    println("[-] Function Graph failed: {}".format(e))
    raise
