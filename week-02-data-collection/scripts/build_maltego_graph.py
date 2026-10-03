#!/usr/bin/env python3
"""
build_maltego_graph.py - turn data/maltego_graph_import.csv into a Maltego graph file (.mtgx).

Why: Maltego's "Import Graph from Table" wizard maps one column to ONE entity type, but this
link list mixes types per row (Hash -> URL, URL -> IPv4, Netblock -> AS ...).  Writing the .mtgx
directly keeps every entity typed correctly and every link labelled.  Open it with File -> Open.

.mtgx = zip archive containing Graphs/Graph1.graphml (GraphML + Maltego "mtg" namespace).
Value property names come from Maltego's Standard Entities Catalog
(maltego.Hash=properties.hash, URL=url, AS=as.number, Netblock=ipv4-range, Phrase=text,
Alias=alias, Domain=fqdn, IPv4Address=ipv4-address).

Usage:  python build_maltego_graph.py            -> data/amadey_graph.mtgx
Needs:  networkx (only for the initial layout; falls back to a circle without it)
"""
import csv
import math
import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

HERE = Path(__file__).resolve().parent
CSV_IN = HERE.parent / "data" / "maltego_graph_import.csv"
OUT = HERE.parent / "data" / "amadey_graph.mtgx"
MTG = "http://maltego.paterva.com/xml/mtgx"

# entity type -> list of (property name, display name, data type); first one is the value property
PROPS = {
    "maltego.Hash":        [("properties.hash", "Hash", "string")],
    "maltego.URL":         [("url", "URL", "url"), ("short-title", "Short title", "string"), ("title", "Title", "string")],
    "maltego.AS":          [("as.number", "AS Number", "int")],
    "maltego.Netblock":    [("ipv4-range", "IP Range", "string")],
    "maltego.Phrase":      [("text", "Text", "string")],
    "maltego.Alias":       [("alias", "Alias", "string")],
    "maltego.Domain":      [("fqdn", "Domain Name", "string")],
    "maltego.IPv4Address": [("ipv4-address", "IP Address", "string")],
}


def prop_xml(name, display, dtype, value):
    return (f'<mtg:Property displayName="{escape(display)}" hidden="false" name="{name}" '
            f'nullable="true" readonly="false" type="{dtype}"><mtg:Value>{escape(value)}</mtg:Value></mtg:Property>')


def entity_xml(etype, value):
    props = []
    for name, display, dtype in PROPS[etype]:
        v = value
        if etype == "maltego.URL" and name in ("short-title", "title"):
            v = value if len(value) <= 60 else value[:57] + "..."
        props.append(prop_xml(name, display, dtype, v))
    return (f'<mtg:MaltegoEntity xmlns:mtg="{MTG}" type="{etype}"><mtg:Properties>'
            + "".join(props) + "</mtg:Properties></mtg:MaltegoEntity>")


def link_xml(label):
    return (f'<mtg:MaltegoLink xmlns:mtg="{MTG}" type="maltego.link.manual-link"><mtg:Properties>'
            + prop_xml("maltego.link.manual.type", "Label", "string", label)
            + "</mtg:Properties></mtg:MaltegoLink>")


def layout(nodes, edges):
    try:
        import networkx as nx
        g = nx.Graph()
        g.add_nodes_from(range(len(nodes)))
        g.add_edges_from((s, t) for s, t, _ in edges)
        pos = nx.kamada_kawai_layout(g)
        return {i: (pos[i][0] * 1100, pos[i][1] * 800) for i in pos}
    except Exception:
        n = len(nodes)
        return {i: (900 * math.cos(2 * math.pi * i / n), 900 * math.sin(2 * math.pi * i / n)) for i in range(n)}


def main():
    rows = list(csv.DictReader(CSV_IN.open(encoding="utf-8")))
    index, nodes, edges = {}, [], []
    for r in rows:
        ids = []
        for t, v in ((r["source_type"], r["source_value"]), (r["target_type"], r["target_value"])):
            if t not in PROPS:
                raise SystemExit(f"unknown entity type {t}")
            key = (t, v)
            if key not in index:
                index[key] = len(nodes)
                nodes.append(key)
            ids.append(index[key])
        edges.append((ids[0], ids[1], r["link_label"]))

    pos = layout(nodes, edges)
    parts = ['<?xml version="1.0" encoding="UTF-8"?>',
             '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
             '<key attr.name="MaltegoEntity" for="node" id="d0"/>',
             '<key for="node" id="d1" yfiles.type="nodegraphics"/>',
             '<key attr.name="MaltegoLink" for="edge" id="d2"/>',
             '<graph edgedefault="directed" id="G">']
    for i, (t, v) in enumerate(nodes):
        x, y = pos[i]
        parts.append(f'<node id="n{i}"><data key="d0">{entity_xml(t, v)}</data>'
                     f'<data key="d1"><mtg:EntityRenderer xmlns:mtg="{MTG}"><mtg:Position x="{x:.1f}" y="{y:.1f}"/>'
                     f'</mtg:EntityRenderer></data></node>')
    for j, (s, t, label) in enumerate(edges):
        parts.append(f'<edge id="e{j}" source="n{s}" target="n{t}"><data key="d2">{link_xml(label)}</data></edge>')
    parts += ["</graph>", "</graphml>"]

    with zipfile.ZipFile(OUT, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("Graphs/Graph1.graphml", "\n".join(parts))
    types = {}
    for t, _ in nodes:
        types[t] = types.get(t, 0) + 1
    print(f"{OUT.name}: {len(nodes)} entities, {len(edges)} links  {types}")


if __name__ == "__main__":
    main()
