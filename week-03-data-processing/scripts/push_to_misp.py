#!/usr/bin/env python3
"""
push_to_misp.py — import the Amadey event into a running MISP instance via the REST API (PyMISP).

    pip install pymisp
    set MISP_URL=https://localhost          (Windows)  | export MISP_URL=https://localhost
    set MISP_KEY=<auth key from Administration -> List Auth Keys>
    python push_to_misp.py                  # add or update the event
    python push_to_misp.py --check          # afterwards: list correlations + to_ids counts

--insecure is ON by default because the misp-docker image uses a self-signed certificate.
"""
import argparse
import os
import sys
import warnings
from pathlib import Path

try:
    from pymisp import MISPEvent, PyMISP
except ImportError:
    sys.exit("pip install pymisp")

EVENT_FILE = Path(__file__).resolve().parent.parent / "output" / "misp" / "amadey_misp_event.json"


def connect(verify):
    url, key = os.environ.get("MISP_URL"), os.environ.get("MISP_KEY")
    if not url or not key:
        sys.exit("Set MISP_URL and MISP_KEY environment variables first.")
    if not verify:
        warnings.filterwarnings("ignore")
    return PyMISP(url, key, ssl=verify)


def push(misp):
    ev = MISPEvent()
    ev.load_file(EVENT_FILE)
    if misp.event_exists(ev.uuid):
        print(f"Event {ev.uuid} exists -> updating")
        res = misp.update_event(ev, pythonify=True)
    else:
        res = misp.add_event(ev, pythonify=True)
    if isinstance(res, dict) and res.get("errors"):
        sys.exit(f"MISP error: {res['errors']}")
    print(f"OK: event id={res.id} uuid={res.uuid} attributes={len(res.attributes)} "
          f"to_ids={sum(a.to_ids for a in res.attributes)}")
    return res


def check(misp):
    ev = MISPEvent()
    ev.load_file(EVENT_FILE)
    e = misp.get_event(ev.uuid, pythonify=True)
    print(f"Event {e.id}: {e.info}")
    corr = {}
    for a in e.attributes:
        rel = misp.search(controller="attributes", value=a.value, pythonify=True)
        others = {x.event_id for x in rel if str(x.event_id) != str(e.id)}
        if others:
            corr[a.value] = sorted(others)
    print(f"Attributes correlating with other events (e.g. enabled feeds): {len(corr)}")
    for v, ids in corr.items():
        print(f"  {v}  ->  events {ids}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="show correlations instead of pushing")
    ap.add_argument("--verify-ssl", action="store_true")
    a = ap.parse_args()
    misp = connect(a.verify_ssl)
    check(misp) if a.check else push(misp)


if __name__ == "__main__":
    main()
