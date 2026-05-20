"""
Production-ready database initialization with complete sample data
Run this ONCE to populate database with MITRE, NIST, sources, and mappings
"""

import os
import sys
import bcrypt
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Import models
sys.path.insert(0, os.path.dirname(__file__))
from database_models import (
    Base, User, Framework, FrameworkVector, SourceType, Brand, SourceModel,
    ModelFrameworkMap, CorrelationRule, ModelCorrelationMap, Parser, SOARFlow,
    Compliance, AttackVector, Highlight, RoleEnum
)

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///cybersec_dashboard.db")

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode(), salt).decode()

def init_database():
    """Initialize database and populate with sample data"""
    
    print("🔧 Initializing database...")
    engine = create_engine(DATABASE_URL)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    db = Session()
    
    # Check if database is already seeded
    try:
        user_count = db.query(User).count()
    except Exception:
        user_count = 0
        
    force_seed = os.getenv("FORCE_SEED", "false").lower() == "true"
    if user_count > 0 and not force_seed:
        print("✅ Database already populated. Skipping seeding. Use FORCE_SEED=true to force re-initialization.")
        db.close()
        return
        
    print("🧹 Clearing existing data...")
    # Clear existing data
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
    
    mitre = Framework(name="mitre", description="MITRE ATT&CK Framework - Adversary Tactics and Techniques")
    nist = Framework(name="nist", description="NIST Cybersecurity Framework - Govern, Manage, Protect")
    db.add_all([mitre, nist])
    db.flush()
    
    # ========================================================================
    # MITRE ATT&CK TACTICS
    # ========================================================================
    
    print("🎯 Adding MITRE ATT&CK tactics...")
    
    mitre_tactics = [
        ("TA0001", "Initial Access", "The adversary is trying to get into your network."),
        ("TA0002", "Execution", "The adversary is trying to run malicious code."),
        ("TA0003", "Persistence", "The adversary is trying to stay in your network."),
        ("TA0004", "Privilege Escalation", "The adversary is trying to gain higher-level permissions."),
        ("TA0005", "Defense Evasion", "The adversary is trying to avoid being detected."),
        ("TA0006", "Credential Access", "The adversary is trying to steal account names and passwords."),
        ("TA0007", "Discovery", "The adversary is trying to figure out your environment."),
        ("TA0008", "Lateral Movement", "The adversary is trying to move through your network."),
        ("TA0009", "Collection", "The adversary is trying to gather data of interest."),
        ("TA0010", "Exfiltration", "The adversary is trying to steal data."),
        ("TA0011", "Command and Control", "The adversary is trying to communicate with compromised systems."),
        ("TA0040", "Impact", "The adversary is trying to manipulate, interrupt, or destroy your systems."),
        ("TA0043", "Reconnaissance", "The adversary is trying to gather information they can use to plan future operations."),
        ("TA0042", "Resource Development", "The adversary is trying to establish resources they can use to support operations."),
    ]
    
    mitre_vectors = []
    for ext_id, name, desc in mitre_tactics:
        v = FrameworkVector(
            framework_id=mitre.id,
            external_id=ext_id,
            name=name,
            description=desc
        )
        mitre_vectors.append(v)
        db.add(v)
    db.flush()
    
    # ========================================================================
    # NIST FUNCTIONS
    # ========================================================================
    
    print("📋 Adding NIST Cybersecurity Framework functions...")
    
    nist_functions = [
        ("ID.AM", "Asset Management", "Organizational assets are inventoried and classified."),
        ("ID.BE", "Business Environment", "The organization's mission, objectives, and stakeholders are established."),
        ("ID.GV", "Governance", "Policies, procedures, and processes to manage the organization."),
        ("ID.RA", "Risk Assessment", "The organization understands the cybersecurity risk to operations."),
        ("ID.RM", "Risk Management Strategy", "The organization addresses identified cybersecurity risks."),
        ("ID.SC", "Supply Chain Risk Management", "The organization manages cybersecurity risks in supply chain."),
        ("ID.IR", "Incident Response Planning", "Procedures are in place to handle incidents."),
        ("PR.AC", "Access Control", "Access to physical and cyber assets is limited to authorized users."),
        ("PR.AT", "Awareness and Training", "The organization provides cybersecurity awareness and training."),
        ("PR.DS", "Data Security", "Information and records are managed per data classification scheme."),
        ("PR.IP", "Information Protection Processes", "Processes are maintained to ensure delivery of information."),
        ("PR.MA", "Maintenance", "Maintenance and repairs are performed on assets."),
        ("PR.PT", "Protective Technology", "Technical security solutions protect against attacks."),
        ("DE.AE", "Anomalies and Events", "Anomalies and events are detected and analyzed."),
        ("DE.CM", "Security Continuous Monitoring", "The information system and assets are continuously monitored."),
        ("DE.DP", "Detection Processes", "Detection processes and procedures are maintained and tested."),
        ("RS.RP", "Response Planning", "Response processes and procedures are executed and maintained."),
        ("RS.CO", "Communications", "Response activities are coordinated with internal and external stakeholders."),
        ("RS.AN", "Analysis", "Analysis is conducted to ensure effective response and support recovery activities."),
        ("RS.MI", "Mitigation", "Activities are performed to prevent expansion of an event."),
        ("RS.IM", "Improvements", "Organizational response activities are improved by incorporating lessons learned."),
        ("RC.RP", "Recovery Planning", "Incident recovery plans are established and tested."),
        ("RC.IM", "Improvements", "Recovery procedures are updated and improvements are implemented."),
        ("RC.CO", "Communications", "Restoration activities and progress are communicated."),
    ]
    
    nist_vectors = []
    for ext_id, name, desc in nist_functions:
        v = FrameworkVector(
            framework_id=nist.id,
            external_id=ext_id,
            name=name,
            description=desc
        )
        nist_vectors.append(v)
        db.add(v)
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
    
    print("🔗 Mapping sources to MITRE tactics...")
    
    # Windows Server 2022 maps to multiple MITRE tactics
    windows_model = model_objects["Microsoft:Windows Server 2022"]
    for idx in [0, 2, 3, 4, 5, 8, 10]:  # Initial Access, Persistence, PrivEsc, DefEvasion, CredAccess, Collection, C&C
        mapping = ModelFrameworkMap(
            source_model_id=windows_model.id,
            framework_vector_id=mitre_vectors[idx].id
        )
        db.add(mapping)
    
    # PA-5220 maps to firewall-relevant tactics
    pa_model = model_objects["Palo Alto:PA-5220"]
    for idx in [0, 4, 5, 9, 10]:  # Initial Access, DefEvasion, CredAccess, Exfiltration, C&C
        mapping = ModelFrameworkMap(
            source_model_id=pa_model.id,
            framework_vector_id=mitre_vectors[idx].id
        )
        db.add(mapping)
    
    # CrowdStrike Falcon maps to detection tactics
    falcon_model = model_objects["CrowdStrike:Falcon"]
    for idx in [1, 3, 4, 6, 7, 8, 9]:  # Execution, PrivEsc, DefEvasion, Discovery, LateralMovement, Collection, Exfiltration
        mapping = ModelFrameworkMap(
            source_model_id=falcon_model.id,
            framework_vector_id=mitre_vectors[idx].id
        )
        db.add(mapping)
    
    # Splunk maps to detection/monitoring
    splunk_model = model_objects["Splunk:Universal Forwarder"]
    for idx in [5, 8, 9, 10]:  # CredAccess, Collection, Exfiltration, C&C
        mapping = ModelFrameworkMap(
            source_model_id=splunk_model.id,
            framework_vector_id=mitre_vectors[idx].id
        )
        db.add(mapping)
    
    print("🔗 Mapping sources to NIST functions...")
    
    # Windows maps to NIST
    for idx in [0, 7, 8, 9, 13, 14]:  # Asset Management, Access Control, Awareness, Data Security, Anomalies, Monitoring
        mapping = ModelFrameworkMap(
            source_model_id=windows_model.id,
            framework_vector_id=nist_vectors[idx].id
        )
        db.add(mapping)
    
    # PA-5220 maps to NIST
    for idx in [7, 12, 13, 14, 15]:  # Access Control, Protective Tech, Anomalies, Monitoring, Detection
        mapping = ModelFrameworkMap(
            source_model_id=pa_model.id,
            framework_vector_id=nist_vectors[idx].id
        )
        db.add(mapping)
    
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
    
    # ========================================================================
    # USERS
    # ========================================================================
    
    print("👥 Creating demo users...")
    
    users = [
        User(
            username="analyst",
            email="analyst@company.com",
            password_hash=hash_password("demo"),
            role="analyst",
            is_active=True
        ),
        User(
            username="admin",
            email="admin@company.com",
            password_hash=hash_password("demo"),
            role="admin",
            is_active=True
        ),
        User(
            username="superadmin",
            email="superadmin@company.com",
            password_hash=hash_password("demo"),
            role="super_admin",
            is_active=True
        ),
    ]
    db.add_all(users)
    
    db.commit()
    db.close()
    
    print("\n" + "="*60)
    print("✅ DATABASE INITIALIZATION COMPLETE!")
    print("="*60)
    print("\n📊 Data Summary:")
    print(f"  • Frameworks: 2 (MITRE ATT&CK, NIST)")
    print(f"  • MITRE Tactics: {len(mitre_tactics)}")
    print(f"  • NIST Functions: {len(nist_functions)}")
    print(f"  • Source Types: {len(source_types)}")
    print(f"  • Brands: {len(brands_data)}")
    print(f"  • Source Models: {len(models_data)}")
    print(f"  • Correlation Rules: {len(rules_data)}")
    print(f"  • Parsers: {len(parsers_data)}")
    print(f"  • SOAR Workflows: {len(soar_workflows)}")
    print(f"  • Compliance Frameworks: {len(compliances)}")
    print(f"  • Attack Vectors: {len(attack_vectors)}")
    print(f"  • Demo Users: 3")
    
    print("\n🔐 Demo Credentials:")
    print("  Analyst:  analyst / demo (read-only)")
    print("  Admin:    admin / demo (manage artifacts)")
    print("  Super:    superadmin / demo (full control)")
    
    print("\n📚 Next Steps:")
    print("  1. Start the application")
    print("  2. Login with one of the demo credentials")
    print("  3. Select a framework (MITRE or NIST)")
    print("  4. Explore the security sources and mappings")
    print("  5. View correlation rules and detection artifacts")
    
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    init_database()
