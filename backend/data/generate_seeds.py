"""
Regenerate the compact framework seed files consumed by init_prod_db.py:
  - mitre_enterprise.json  (from MITRE ATT&CK Enterprise STIX bundle)
  - nist_csf2.json         (from the NIST CPRT CSF 2.0 export)

Both outputs share one shape:
    {"framework": "...", "description": "...",
     "nodes": [{"external_id","name","description","level"}],
     "links": [["parent_external_id","child_external_id"], ...]}

Usage:
    # MITRE: download the Enterprise STIX bundle first (≈50 MB), then:
    curl -L -o /tmp/enterprise-attack.json \
      https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
    python generate_seeds.py mitre /tmp/enterprise-attack.json

    # NIST: export "JSON / All" from the CPRT CSF 2.0 catalog into
    #   backend/data/nist_csf2_raw.json  (CPRT: csrc.nist.gov/projects/cprt), then:
    python generate_seeds.py nist backend/data/nist_csf2_raw.json
"""

import json
import os
import sys
from collections import Counter

HERE = os.path.dirname(__file__)


def _write(name, obj):
    path = os.path.join(HERE, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, separators=(",", ":"), ensure_ascii=False)
    print(f"  wrote {name}: {len(obj['nodes'])} nodes, {len(obj['links'])} links "
          f"({os.path.getsize(path)//1024} KB)")
    print("  levels:", dict(Counter(n["level"] for n in obj["nodes"])))


def generate_mitre(stix_path):
    data = json.load(open(stix_path, encoding="utf-8"))
    objs = data["objects"]

    def attack_id(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                return ref["external_id"]
        return None

    def live(o):
        return not o.get("revoked") and not o.get("x_mitre_deprecated")

    shortname_to_tid, tactics = {}, []
    for o in objs:
        if o.get("type") == "x-mitre-tactic" and live(o):
            tid, sn = attack_id(o), o.get("x_mitre_shortname")
            if tid and sn:
                shortname_to_tid[sn] = tid
                tactics.append({"external_id": tid, "name": o["name"],
                                "description": (o.get("description") or "").strip(), "level": "tactic"})

    nodes, links, techniques = list(tactics), [], {}
    for o in objs:
        if o.get("type") == "attack-pattern" and live(o):
            aid = attack_id(o)
            if not aid:
                continue
            is_sub = o.get("x_mitre_is_subtechnique", False)
            techniques[aid] = {"external_id": aid, "name": o["name"],
                               "description": (o.get("description") or "").strip()[:1500],
                               "level": "subtechnique" if is_sub else "technique"}
            for ph in o.get("kill_chain_phases", []):
                if ph.get("kill_chain_name") == "mitre-attack" and not is_sub:
                    tid = shortname_to_tid.get(ph.get("phase_name"))
                    if tid:
                        links.append([tid, aid])
            if is_sub and "." in aid:
                links.append([aid.split(".")[0], aid])

    nodes.extend(techniques.values())
    nodes.sort(key=lambda n: ("0" if n["level"] == "tactic" else "1", n["external_id"]))
    links = [list(x) for x in sorted(set(map(tuple, links)))]
    _write("mitre_enterprise.json", {
        "framework": "mitre",
        "description": "MITRE ATT&CK Enterprise - Tactics, Techniques & Sub-techniques",
        "nodes": nodes, "links": links})


def generate_nist(cprt_path):
    d = json.load(open(cprt_path, encoding="utf-8"))
    els = d["response"]["elements"]["elements"]
    rels = d["response"]["elements"]["relationships"]

    # Withdrawn CSF 1.1 holdovers carry a "WR-<id>" withdraw_reason marker.
    withdrawn = {e["element_identifier"][3:] for e in els
                 if e["element_type"] == "withdraw_reason" and e["element_identifier"].startswith("WR-")}
    # "S-<id>" sort elements carry the canonical display order.
    order = {e["element_identifier"][2:]: (e.get("title") or "") for e in els
             if e["element_type"] == "sort" and e["element_identifier"].startswith("S-")}

    levels = {"function": "function", "category": "category", "subcategory": "subcategory"}
    nodes = []
    for e in els:
        lvl = levels.get(e["element_type"])
        eid = e["element_identifier"]
        if not lvl or eid in withdrawn:
            continue
        title = (e.get("title") or "").strip()
        text = (e.get("text") or "").strip()
        nodes.append({"external_id": eid, "name": title or text,
                      "description": text, "level": lvl, "_o": order.get(eid, eid)})
    nodes.sort(key=lambda n: n["_o"])
    for n in nodes:
        n.pop("_o")

    ids = {n["external_id"] for n in nodes}
    links = [list(x) for x in sorted({
        (r["source_element_identifier"], r["dest_element_identifier"]) for r in rels
        if r["relationship_identifier"] == "projection"
        and r["source_element_identifier"] in ids and r["dest_element_identifier"] in ids})]
    _write("nist_csf2.json", {
        "framework": "nist",
        "description": "NIST Cybersecurity Framework 2.0 - Functions, Categories & Subcategories",
        "nodes": nodes, "links": links})


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("mitre", "nist"):
        print(__doc__)
        sys.exit(1)
    (generate_mitre if sys.argv[1] == "mitre" else generate_nist)(sys.argv[2])
