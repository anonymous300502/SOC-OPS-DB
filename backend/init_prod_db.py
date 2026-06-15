"""
Production-ready database initialization with complete sample data
Run this ONCE to populate database with MITRE, NIST, sources, and mappings
"""

import os
import sys
import json
import bcrypt
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import models
sys.path.insert(0, os.path.dirname(__file__))
from database_models import (
    Base, User, Framework, FrameworkVector, SourceType, Brand, SourceModel,
    ModelFrameworkMap, CorrelationRule, ModelCorrelationMap, Parser, SOARFlow,
    Compliance, AttackVector, Highlight, RoleEnum, vector_links
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cybersec_dashboard.db")
DATA_DIR = os.path.join(os.path.dirname(__file__), "data")


def load_framework_tree(db, framework, filename):
    """Load a {nodes, links} framework hierarchy JSON into framework_vectors and
    the vector_links association. Returns the number of nodes inserted."""
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        print(f"  ⚠️  {filename} not found in {DATA_DIR}; skipping {framework.name} hierarchy.")
        return 0
    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    objs = {}
    for n in data.get("nodes", []):
        v = FrameworkVector(
            framework_id=framework.id,
            external_id=n["external_id"],
            name=n["name"],
            description=(n.get("description") or None),
            level=n.get("level"),
        )
        db.add(v)
        objs[n["external_id"]] = v
    db.flush()

    link_rows = []
    for pair in data.get("links", []):
        parent_ext, child_ext = pair[0], pair[1]
        p, c = objs.get(parent_ext), objs.get(child_ext)
        if p is not None and c is not None:
            link_rows.append({"parent_id": p.id, "child_id": c.id})
    if link_rows:
        db.execute(vector_links.insert(), link_rows)
    db.flush()
    print(f"  ✓ {framework.name}: {len(objs)} nodes, {len(link_rows)} hierarchy links")
    return len(objs)


def map_model_to_vectors(db, model, framework, external_ids):
    """Map a source model to framework vectors by external_id (skips unknowns)."""
    for ext in external_ids:
        v = (
            db.query(FrameworkVector)
            .filter(FrameworkVector.framework_id == framework.id,
                    FrameworkVector.external_id == ext)
            .first()
        )
        if v:
            db.add(ModelFrameworkMap(source_model_id=model.id, framework_vector_id=v.id))

# Minimum length enforced for the bootstrap super-admin password.
MIN_PASSWORD_LENGTH = 8

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def get_super_admin_config():
    """Read the bootstrap super-admin credentials from the environment.

    Required env vars: SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD,
    SUPER_ADMIN_EMAIL. Exits with an error if any are missing or the
    password is too weak — there are no hardcoded/demo credentials.
    """
    username = os.getenv("SUPER_ADMIN_USERNAME", "").strip()
    password = os.getenv("SUPER_ADMIN_PASSWORD", "")
    email = os.getenv("SUPER_ADMIN_EMAIL", "").strip()

    missing = [
        name for name, val in (
            ("SUPER_ADMIN_USERNAME", username),
            ("SUPER_ADMIN_PASSWORD", password),
            ("SUPER_ADMIN_EMAIL", email),
        ) if not val
    ]
    if missing:
        print(
            "❌ Cannot bootstrap the super admin account. Missing required "
            f"environment variable(s): {', '.join(missing)}.\n"
            "   Set SUPER_ADMIN_USERNAME, SUPER_ADMIN_PASSWORD and "
            "SUPER_ADMIN_EMAIL before initializing the database."
        )
        sys.exit(1)
    if len(password) < MIN_PASSWORD_LENGTH:
        print(
            f"❌ SUPER_ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} "
            "characters long."
        )
        sys.exit(1)
    return username, password, email

def ensure_super_admin(db):
    """Create the bootstrap super-admin from env vars if it does not exist.

    Idempotent: runs on every startup. If a user with the configured
    username already exists it is left untouched (passwords are managed via
    the API afterwards, never reset from the environment).
    """
    username, password, email = get_super_admin_config()
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        print(f"✅ Super admin '{username}' already exists. Skipping bootstrap.")
        return
    db.add(User(
        username=username,
        email=email,
        password_hash=hash_password(password),
        role=RoleEnum.SUPER_ADMIN.value,
        is_active=True,
    ))
    db.commit()
    print(f"👑 Bootstrap super admin '{username}' created.")

def init_database():
    """Initialize database, seed reference catalog (once) and bootstrap admin."""

    print("🔧 Initializing database...")
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()

    # Validate super-admin config up front so we fail fast before any writes.
    get_super_admin_config()

    # Seed the reference catalog only when the database is empty (no
    # frameworks) unless explicitly forced. This protects user-created and
    # uploaded data from being wiped on every restart.
    force_seed = os.getenv("FORCE_SEED", "false").lower() == "true"
    try:
        framework_count = db.query(Framework).count()
    except Exception:
        framework_count = 0

    if framework_count > 0 and not force_seed:
        print("✅ Catalog already populated. Skipping seed. Use FORCE_SEED=true to re-seed.")
        ensure_super_admin(db)
        db.close()
        return

    print("🧹 Clearing existing catalog data...")
    # Clear existing data (vector_links first — association rows reference vectors)
    db.execute(vector_links.delete())
    db.query(ModelFrameworkMap).delete()
    db.query(ModelCorrelationMap).delete()
    db.query(CorrelationRule).delete()
    db.query(Parser).delete()
    db.query(SOARFlow).delete()
    db.query(SourceModel).delete()
    db.query(Brand).delete()
    db.query(SourceType).delete()
    db.query(FrameworkVector).delete()
    db.query(Framework).delete()
    db.query(Highlight).delete()
    db.query(AttackVector).delete()
    db.query(Compliance).delete()
    db.query(User).delete()
    db.commit()
    
    print("📚 Creating frameworks...")
    
    # ========================================================================
    # FRAMEWORKS
    # ========================================================================
    
    mitre = Framework(name="mitre", description="MITRE ATT&CK Enterprise - Adversary Tactics, Techniques & Sub-techniques")
    nist = Framework(name="nist", description="NIST Cybersecurity Framework 2.0 - Functions, Categories & Subcategories")
    db.add_all([mitre, nist])
    db.flush()

    # ========================================================================
    # FRAMEWORK HIERARCHIES (loaded from bundled reference data)
    # ========================================================================

    print("🎯 Loading framework hierarchies (MITRE ATT&CK / NIST CSF 2.0)...")
    load_framework_tree(db, mitre, "mitre_enterprise.json")
    load_framework_tree(db, nist, "nist_csf2.json")
    db.flush()

    # ========================================================================
    # SOURCE TYPES
    # ========================================================================
    
    print("🖥️  Adding source types...")
    
    source_types = {
        "Server": "Operating systems and server software",
        "Firewall": "Network firewall appliances and software",
        "Endpoint": "Endpoint detection and response (EDR) / antivirus",
        "Network": "Network monitoring and packet analysis",
        "Cloud": "Cloud infrastructure and services",
        "Database": "Database management systems",
    }
    
    st_objects = {}
    for name, desc in source_types.items():
        st = SourceType(name=name, description=desc)
        st_objects[name] = st
        db.add(st)
    db.flush()
    
    # ========================================================================
    # BRANDS
    # ========================================================================
    
    print("🏢 Adding security vendors...")
    
    brands_data = {
        "Microsoft": "Microsoft Corporation - Windows, Azure",
        "Palo Alto": "Palo Alto Networks - Firewalls, XDR",
        "CrowdStrike": "CrowdStrike - EDR and threat intelligence",
        "Cisco": "Cisco Systems - Networking and security",
        "Splunk": "Splunk - Log analysis and SIEM",
        "Elastic": "Elastic - ELK Stack, SIEM",
        "Fortinet": "Fortinet - FortiGate firewalls",
        "Okta": "Okta - Identity and access management",
        "Cloudflare": "Cloudflare - DDoS, WAF, DNS",
        "AWS": "Amazon Web Services - Cloud infrastructure",
        "Google": "Google Cloud - Cloud infrastructure",
        "Rapid7": "Rapid7 - Vulnerability management",
    }
    
    brand_objects = {}
    for name, desc in brands_data.items():
        b = Brand(name=name, description=desc)
        brand_objects[name] = b
        db.add(b)
    db.flush()
    
    # ========================================================================
    # SOURCE MODELS
    # ========================================================================
    
    print("🎯 Adding security source models...")
    
    models_data = [
        ("Server", "Microsoft", "Windows Server 2022", "Enterprise Windows Server"),
        ("Server", "Microsoft", "Windows Server 2019", "Legacy Windows Server"),
        ("Server", "Google", "Linux (Ubuntu 22.04)", "Ubuntu Linux Server"),
        ("Firewall", "Palo Alto", "PA-5220", "Enterprise firewall appliance"),
        ("Firewall", "Palo Alto", "PA-3260", "Mid-range firewall"),
        ("Firewall", "Cisco", "ASA 5520", "Cisco Adaptive Security Appliance"),
        ("Firewall", "Fortinet", "FortiGate 3200D", "Fortinet firewall"),
        ("Endpoint", "CrowdStrike", "Falcon", "CrowdStrike EDR agent"),
        ("Endpoint", "Microsoft", "Defender for Endpoint", "Microsoft EDR solution"),
        ("Endpoint", "Palo Alto", "Cortex XDR", "Palo Alto extended detection"),
        ("Network", "Cisco", "Meraki MX100", "Cloud-managed firewall"),
        ("Network", "Splunk", "Universal Forwarder", "Log collection agent"),
        ("Network", "Elastic", "Filebeat", "Lightweight log shipper"),
        ("Cloud", "AWS", "EC2 + VPC", "Amazon Elastic Compute + networking"),
        ("Cloud", "Google", "GCP Compute Engine", "Google Cloud compute instances"),
        ("Cloud", "Okta", "Identity Cloud", "Okta identity platform"),
        ("Database", "Microsoft", "SQL Server 2022", "SQL Server database"),
        ("Database", "Splunk", "Enterprise Security", "Splunk SIEM"),
    ]
    
    model_objects = {}
    for src_type, brand, model_name, desc in models_data:
        sm = SourceModel(
            source_type_id=st_objects[src_type].id,
            brand_id=brand_objects[brand].id,
            name=model_name,
            description=desc
        )
        model_objects[f"{brand}:{model_name}"] = sm
        db.add(sm)
    db.flush()
    
    # ========================================================================
    # FRAMEWORK MAPPINGS (source_model ↔ framework_vector)
    # ========================================================================
    
    print("🔗 Mapping sample sources to MITRE techniques (TTPs)...")

    windows_model = model_objects["Microsoft:Windows Server 2022"]
    pa_model = model_objects["Palo Alto:PA-5220"]
    falcon_model = model_objects["CrowdStrike:Falcon"]
    splunk_model = model_objects["Splunk:Universal Forwarder"]

    # Map to real ATT&CK techniques / sub-techniques (skipped silently if a
    # given id is absent from the loaded dataset).
    map_model_to_vectors(db, windows_model, mitre,
                         ["T1078", "T1055", "T1059.001", "T1053.005", "T1547.001", "TA0005"])
    map_model_to_vectors(db, pa_model, mitre,
                         ["T1071", "T1090", "T1048", "T1041", "TA0011"])
    map_model_to_vectors(db, falcon_model, mitre,
                         ["T1055", "T1059", "T1486", "T1003", "TA0002"])
    map_model_to_vectors(db, splunk_model, mitre,
                         ["T1078", "T1110", "T1098"])

    print("🔗 Mapping sample sources to NIST CSF 2.0 subcategories...")
    # Common CSF 2.0 subcategory ids; skipped if NIST data not loaded.
    map_model_to_vectors(db, windows_model, nist, ["ID.AM-01", "PR.AA-01", "DE.CM-01"])
    map_model_to_vectors(db, pa_model, nist, ["PR.IR-01", "DE.CM-01", "DE.AE-02"])
    map_model_to_vectors(db, falcon_model, nist, ["DE.CM-01", "RS.MA-01"])

    db.flush()
    
    # ========================================================================
    # CORRELATION RULES (Reusable)
    # ========================================================================
    
    print("🔍 Creating correlation rules...")
    
    rules_data = [
        {
            "name": "Suspicious Outbound Connection",
            "logic": "destination_port NOT IN (80,443,53) AND bytes_out > 1000000",
            "severity": "high",
            "author": "SOC Team",
            "tags": ["network", "exfiltration", "c2"],
            "description": "Detects unusual outbound traffic patterns indicative of data exfiltration"
        },
        {
            "name": "Multiple Failed Login Attempts",
            "logic": "event_type='login_failed' | stats count by source_ip | where count > 5",
            "severity": "medium",
            "author": "SOC Team",
            "tags": ["credential", "bruteforce", "initial_access"],
            "description": "Identifies accounts with multiple failed login attempts"
        },
        {
            "name": "Privilege Escalation Detected",
            "logic": "privilege_level_before < privilege_level_after",
            "severity": "critical",
            "author": "SOC Team",
            "tags": ["privilege_escalation", "persistence"],
            "description": "Detects when user privileges are elevated without authorization"
        },
        {
            "name": "Lateral Movement - RDP Access",
            "logic": "event_type='network_connection' AND destination_port IN (3389,22)",
            "severity": "high",
            "author": "SOC Team",
            "tags": ["lateral_movement", "c2"],
            "description": "Detects RDP or SSH access between internal systems"
        },
        {
            "name": "Process Injection Detected",
            "logic": "process_injection=true OR memory_write_protection_bypass=true",
            "severity": "critical",
            "author": "SOC Team",
            "tags": ["execution", "defense_evasion"],
            "description": "Identifies process injection techniques used by malware"
        },
        {
            "name": "Suspicious PowerShell Activity",
            "logic": "process_name='powershell' AND command CONTAINS ('System.Net.', 'Invoke-', 'WebClient')",
            "severity": "high",
            "author": "SOC Team",
            "tags": ["execution", "command_line"],
            "description": "Detects suspicious PowerShell commands often used in attacks"
        },
        {
            "name": "File Deletion at Scale",
            "logic": "event_type='file_delete' | stats count by source_host | where count > 50",
            "severity": "critical",
            "author": "SOC Team",
            "tags": ["impact", "ransomware"],
            "description": "Identifies mass file deletion patterns typical of ransomware"
        },
        {
            "name": "Suspicious Scheduled Task",
            "logic": "event_type='scheduled_task_created' AND command LIKE '%cmd%'",
            "severity": "high",
            "author": "SOC Team",
            "tags": ["persistence", "execution"],
            "description": "Detects creation of suspicious scheduled tasks"
        },
        {
            "name": "Data Staging",
            "logic": "process_name IN ('rar.exe', '7z.exe', 'winrar') AND file_size > 100000000",
            "severity": "medium",
            "author": "SOC Team",
            "tags": ["exfiltration", "collection"],
            "description": "Detects compression tools compressing large amounts of data"
        },
        {
            "name": "DNS Exfiltration",
            "logic": "query_type='A' AND subdomain_count > 50 AND bytes_query > 255",
            "severity": "high",
            "author": "SOC Team",
            "tags": ["exfiltration", "c2"],
            "description": "Identifies DNS tunneling used for data exfiltration"
        },
    ]
    
    rule_objects = {}
    for rule_data in rules_data:
        rule = CorrelationRule(
            name=rule_data["name"],
            description=rule_data["description"],
            rule_logic=rule_data["logic"],
            author=rule_data["author"],
            severity=rule_data["severity"],
            tags=rule_data["tags"]
        )
        rule_objects[rule_data["name"]] = rule
        db.add(rule)
    db.flush()
    
    # ========================================================================
    # MAP CORRELATION RULES TO MODELS
    # ========================================================================
    
    print("🔗 Mapping correlation rules to source models...")
    
    # Windows Server gets most rules
    for rule_name in ["Suspicious Outbound Connection", "Multiple Failed Login Attempts",
                      "Privilege Escalation Detected", "Suspicious PowerShell Activity",
                      "Suspicious Scheduled Task"]:
        mapping = ModelCorrelationMap(
            source_model_id=windows_model.id,
            correlation_rule_id=rule_objects[rule_name].id
        )
        db.add(mapping)
    
    # Firewall gets network rules
    for rule_name in ["Suspicious Outbound Connection", "DNS Exfiltration", "Lateral Movement - RDP Access"]:
        mapping = ModelCorrelationMap(
            source_model_id=pa_model.id,
            correlation_rule_id=rule_objects[rule_name].id
        )
        db.add(mapping)
    
    # EDR gets execution rules
    falcon_model = model_objects["CrowdStrike:Falcon"]
    for rule_name in ["Process Injection Detected", "Suspicious PowerShell Activity",
                      "File Deletion at Scale", "Privilege Escalation Detected"]:
        mapping = ModelCorrelationMap(
            source_model_id=falcon_model.id,
            correlation_rule_id=rule_objects[rule_name].id
        )
        db.add(mapping)
    
    # SIEM gets all
    for rule_name in rule_objects.keys():
        mapping = ModelCorrelationMap(
            source_model_id=splunk_model.id,
            correlation_rule_id=rule_objects[rule_name].id
        )
        db.add(mapping)
    
    db.flush()
    
    # ========================================================================
    # PARSERS (Model-specific)
    # ========================================================================
    
    print("⚙️  Creating log parsers...")
    
    parsers_data = [
        (windows_model, "Windows Event Log (JSON)", "json", {
            "fields": ["event_id", "source_name", "computer", "message"],
            "timestamp_field": "time_generated",
            "event_type_field": "event_id"
        }),
        (windows_model, "Windows Sysmon", "json", {
            "fields": ["Image", "CommandLine", "ParentImage", "TargetFilename"],
            "timestamp_field": "UtcTime",
            "source": "sysmon"
        }),
        (pa_model, "Palo Alto CEF Logs", "cef", {
            "signature": "Palo Alto Networks",
            "product": "PAN-OS",
            "fields": ["shost", "dhost", "dport", "proto"],
            "timestamp_format": "MMM dd HH:mm:ss"
        }),
        (pa_model, "Palo Alto JSON API", "json", {
            "message_field": "log_forwarding",
            "severity_field": "severity",
            "source_ip_field": "source_address",
            "dest_ip_field": "destination_address"
        }),
        (falcon_model, "CrowdStrike Event Stream", "json", {
            "fields": ["event_type", "event_subtype_string", "process_id", "process_path"],
            "correlation_field": "cid"
        }),
        (splunk_model, "Splunk Raw Logs", "kv", {
            "key_value_separator": "=",
            "pair_separator": " ",
            "field_extraction": "auto"
        }),
    ]
    
    for model, name, format_type, config in parsers_data:
        parser = Parser(
            source_model_id=model.id,
            name=name,
            format=format_type,
            parser_config=config,
            is_active=True
        )
        db.add(parser)
    
    db.flush()
    
    # ========================================================================
    # SOAR FLOWS (Model-specific)
    # ========================================================================
    
    print("🔄 Creating SOAR workflows...")
    
    soar_workflows = [
        {
            "model": windows_model,
            "name": "Isolate Compromised Host",
            "description": "Automatically isolates a compromised Windows server from network",
            "workflow": {
                "steps": [
                    {"id": 1, "action": "isolate_host", "params": {"method": "network_disconnect"}},
                    {"id": 2, "action": "notify", "params": {"priority": "critical", "channels": ["email", "slack"]}},
                    {"id": 3, "action": "collect_forensics", "params": {"types": ["memory", "disk", "logs"]}},
                    {"id": 4, "action": "create_incident", "params": {"severity": "critical"}}
                ]
            }
        },
        {
            "model": pa_model,
            "name": "Block Malicious IP",
            "description": "Automatically blocks detected malicious IPs at firewall",
            "workflow": {
                "steps": [
                    {"id": 1, "action": "add_to_blocklist", "params": {"duration": "7d"}},
                    {"id": 2, "action": "drop_connections", "params": {"direction": "both"}},
                    {"id": 3, "action": "log_rule_change", "params": {"severity": "high"}},
                    {"id": 4, "action": "notify_soc", "params": {"method": "api"}}
                ]
            }
        },
        {
            "model": falcon_model,
            "name": "Terminate Malicious Process",
            "description": "Automatically terminates suspicious processes on endpoints",
            "workflow": {
                "steps": [
                    {"id": 1, "action": "kill_process", "params": {"preserve_parent": False}},
                    {"id": 2, "action": "quarantine_file", "params": {"hash_type": "sha256"}},
                    {"id": 3, "action": "isolate_endpoint", "params": {"network_isolation": True}},
                    {"id": 4, "action": "trigger_response", "params": {"escalation": "high"}}
                ]
            }
        },
    ]
    
    for workflow in soar_workflows:
        flow = SOARFlow(
            source_model_id=workflow["model"].id,
            name=workflow["name"],
            description=workflow["description"],
            workflow_json=workflow["workflow"],
            is_active=True
        )
        db.add(flow)
    
    db.flush()
    
    # ========================================================================
    # STATIC INTELLIGENCE
    # ========================================================================
    
    print("📊 Adding compliance and threat data...")
    
    compliances = [
        Compliance(
            name="PCI-DSS",
            description="Payment Card Industry Data Security Standard",
            requirements=["6.2", "8.2", "10.1", "11.3"]
        ),
        Compliance(
            name="HIPAA",
            description="Health Insurance Portability and Accountability Act",
            requirements=["164.308", "164.312", "164.314"]
        ),
        Compliance(
            name="SOC2",
            description="Service Organization Control 2",
            requirements=["CC7.1", "CC7.2", "CC9.1"]
        ),
        Compliance(
            name="ISO27001",
            description="Information Security Management",
            requirements=["A.12.4", "A.14.1", "A.16.1"]
        ),
    ]
    db.add_all(compliances)
    
    attack_vectors = [
        AttackVector(
            name="Ransomware",
            category="Impact",
            severity="critical",
            description="Encrypts systems and demands payment for recovery"
        ),
        AttackVector(
            name="Data Exfiltration",
            category="Collection",
            severity="critical",
            description="Unauthorized copying of sensitive data"
        ),
        AttackVector(
            name="Privilege Escalation",
            category="Privilege Escalation",
            severity="high",
            description="Elevation of user permissions to gain higher access"
        ),
        AttackVector(
            name="Lateral Movement",
            category="Lateral Movement",
            severity="high",
            description="Moving through network to access other systems"
        ),
        AttackVector(
            name="C2 Communication",
            category="Command and Control",
            severity="high",
            description="Attacker communicates with compromised systems"
        ),
        AttackVector(
            name="Supply Chain Attack",
            category="Initial Access",
            severity="critical",
            description="Compromise through trusted vendor or partner"
        ),
    ]
    db.add_all(attack_vectors)
    
    highlights = [
        Highlight(
            title="Critical: Windows Print Spooler RCE (CVE-2021-1732)",
            content="Remote code execution vulnerability in Windows Print Spooler service. Patch immediately.",
            priority="critical"
        ),
        Highlight(
            title="High: Active Log4j Exploitation Campaign",
            content="Multiple threat actors exploiting Log4Shell vulnerability. Update log4j to 2.17.1+",
            priority="high"
        ),
        Highlight(
            title="Medium: Increased Credential Stuffing Activity",
            content="Spike in credential stuffing attacks detected. Enable MFA across all systems.",
            priority="medium"
        ),
    ]
    db.add_all(highlights)

    db.flush()
    db.commit()

    # ========================================================================
    # BOOTSTRAP SUPER ADMIN (from environment, no demo/default credentials)
    # ========================================================================
    ensure_super_admin(db)

    mitre_nodes = db.query(FrameworkVector).filter(FrameworkVector.framework_id == mitre.id).count()
    nist_nodes = db.query(FrameworkVector).filter(FrameworkVector.framework_id == nist.id).count()

    db.close()

    print("\n" + "="*60)
    print("✅ DATABASE INITIALIZATION COMPLETE!")
    print("="*60)
    print("\n📊 Data Summary:")
    print(f"  • Frameworks: 2 (MITRE ATT&CK Enterprise, NIST CSF 2.0)")
    print(f"  • MITRE vectors (tactics/techniques/sub-techniques): {mitre_nodes}")
    print(f"  • NIST vectors (functions/categories/subcategories): {nist_nodes}")
    print(f"  • Source Types: {len(source_types)}")
    print(f"  • Brands: {len(brands_data)}")
    print(f"  • Source Models: {len(models_data)}")
    print(f"  • Correlation Rules: {len(rules_data)}")
    print(f"  • Parsers: {len(parsers_data)}")
    print(f"  • SOAR Workflows: {len(soar_workflows)}")
    print(f"  • Compliance Frameworks: {len(compliances)}")
    print(f"  • Attack Vectors: {len(attack_vectors)}")

    print("\n📚 Next Steps:")
    print("  1. Start the application")
    print("  2. Log in with the bootstrap super-admin credentials (SUPER_ADMIN_*)")
    print("  3. Create admin and analyst users from the Users screen")
    print("  4. Select a framework (MITRE or NIST) and explore sources/mappings")

    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    init_database()
