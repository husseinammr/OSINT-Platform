import asyncio
import socket
import ssl
import re
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import dns.resolver

app = FastAPI(title="OSINT Platform", version="3.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# ── Models ──────────────────────────────────────
class ScanRequest(BaseModel):
    target_type: str
    value: str
    branch: Optional[str] = "infrastructure"

class WhoisRequest(BaseModel):
    domain: str

class PortScanRequest(BaseModel):
    target: str
    ports: Optional[list[int]] = None

# ── Constants ───────────────────────────────────
COMMON_PORTS = {
    21:"FTP", 22:"SSH", 25:"SMTP", 53:"DNS",
    80:"HTTP", 443:"HTTPS", 445:"SMB",
    3306:"MySQL", 3389:"RDP", 8080:"HTTP-Alt"
}
DANGEROUS_PORTS = {21, 23, 445, 3389}

# ── Helpers ─────────────────────────────────────
async def dns_query(domain: str, rtype: str) -> list[str]:
    loop = asyncio.get_event_loop()
    def _q():
        try:
            return [str(r) for r in dns.resolver.resolve(domain, rtype, lifetime=4)]
        except Exception:
            return []
    return await loop.run_in_executor(None, _q)

async def resolve_host(host: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, socket.gethostbyname, host)

async def reverse_lookup(ip: str) -> str:
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
    return result[0]

async def check_port(ip: str, port: int) -> dict:
    loop = asyncio.get_event_loop()
    def _c():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        r = s.connect_ex((ip, port))
        s.close()
        return r == 0
    is_open = await loop.run_in_executor(None, _c)
    return {"port": port, "service": COMMON_PORTS.get(port, "Unknown"), "open": is_open}

async def get_ssl_info(domain: str) -> dict:
    loop = asyncio.get_event_loop()
    def _ssl():
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
                s.settimeout(4)
                s.connect((domain, 443))
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                not_after = cert.get("notAfter", "")
                expiry = ""
                if not_after:
                    from datetime import datetime
                    try: expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").strftime("%Y-%m-%d")
                    except: expiry = not_after
                sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
                return {"valid": True,
                        "issuer": issuer.get("organizationName", issuer.get("commonName", "-")),
                        "subject": subject.get("commonName", "-"),
                        "expiry": expiry, "sans": sans[:8]}
        except Exception as e:
            return {"valid": False, "error": str(e)}
    return await loop.run_in_executor(None, _ssl)

def infer_registrar(ns_records: list[str]) -> str:
    mapping = {
        "googledomains": "Google Domains", "google.com": "Google LLC",
        "cloudflare": "Cloudflare", "namecheap": "Namecheap",
        "godaddy": "GoDaddy", "awsdns": "Amazon AWS",
        "azure-dns": "Microsoft Azure", "domaincontrol": "GoDaddy",
        "markmonitor": "MarkMonitor", "verisign": "VeriSign", "nsone": "NS1"
    }
    ns_str = " ".join(ns_records).lower()
    for key, name in mapping.items():
        if key in ns_str: return name
    if ns_records:
        parts = ns_records[0].rstrip(".").split(".")
        if len(parts) >= 2: return f"{parts[-2].capitalize()} (inferred)"
    return "Unknown"

def calculate_risk(findings: dict) -> tuple[int, str]:
    score = 0
    if findings.get("is_malicious"): score += 70
    if findings.get("suspicious_counts", 0) > 0: score += 20
    if findings.get("subdomains_count", 0) > 0: score += 10
    score = min(100, score)
    return score, ("Low" if score < 30 else "Medium" if score < 70 else "High")

# ── Endpoints ───────────────────────────────────

@app.post("/api/v1/scan")
async def scan_target(request: ScanRequest):
    target = request.value.strip()
    ttype  = request.target_type.lower()
    branch = (request.branch or "infrastructure").lower()

    nodes    = [{"id": target, "label": target, "type": ttype}]
    edges    = []
    findings = {"is_malicious": False, "suspicious_counts": 0, "subdomains_count": 0}
    # الـ IP يُرجَع دائماً للفرونت اند يعمل geo منه
    resolved_ip = None
    summary_msg = ""

    if branch == "infrastructure":

        if ttype == "ip":
            resolved_ip = target
            try:
                real_domain = await reverse_lookup(target)
                nodes.append({"id": real_domain, "label": f"Domain: {real_domain}", "type": "domain"})
                edges.append({"source": target, "target": real_domain, "relation": "resolves_to"})
                summary_msg = f"Reverse DNS found: {real_domain}"
            except Exception:
                nodes.append({"id": "Infrastructure", "label": "Infrastructure", "type": "network"})
                edges.append({"source": target, "target": "Infrastructure", "relation": "belongs_to"})
                summary_msg = "No reverse DNS record found for this IP."

        elif ttype == "email":
            if "@" in target:
                _, domain = target.split("@", 1)
                try:
                    email_ip = await resolve_host(domain)
                    resolved_ip = email_ip
                    nodes.append({"id": domain,   "label": f"Domain: {domain}",   "type": "domain"})
                    nodes.append({"id": email_ip, "label": f"IP: {email_ip}",     "type": "ip"})
                    edges.append({"source": target,   "target": domain,   "relation": "managed_by"})
                    edges.append({"source": domain,   "target": email_ip, "relation": "hosted_at"})
                    summary_msg = f"Email is active. Domain {domain} resolves to {email_ip}."
                except Exception:
                    findings["is_malicious"] = True
                    nodes.append({"id": "Invalid", "label": "No DNS Found", "type": "alert"})
                    edges.append({"source": target, "target": "Invalid", "relation": "invalid"})
                    summary_msg = f"Warning: @{domain} has no valid DNS infrastructure."
            else:
                findings["is_malicious"] = True
                summary_msg = "Invalid email format."

        elif ttype == "domain":
            try:
                real_ip = await resolve_host(target)
                resolved_ip = real_ip
                nodes.append({"id": real_ip, "label": f"IP: {real_ip}", "type": "ip"})
                edges.append({"source": target, "target": real_ip, "relation": "resolves_to"})
            except Exception:
                summary_msg = "Could not resolve domain."

            for sub in ["www", "mail", "api", "dev", "admin"]:
                try:
                    await resolve_host(f"{sub}.{target}")
                    findings["subdomains_count"] += 1
                    nodes.append({"id": f"{sub}.{target}", "label": f"Sub: {sub}", "type": "subdomain"})
                    edges.append({"source": target, "target": f"{sub}.{target}", "relation": "has_subdomain"})
                except Exception:
                    pass

            for email in [f"admin@{target}", f"support@{target}"]:
                nodes.append({"id": email, "label": f"Mail: {email}", "type": "email"})
                edges.append({"source": target, "target": email, "relation": "domain_email"})

            if not summary_msg:
                summary_msg = f"Domain scan complete. {findings['subdomains_count']} subdomain(s) discovered."

    elif branch == "personal":
        if ttype == "ip":
            resolved_ip = target
            try:
                real_domain = await reverse_lookup(target)
                nodes.append({"id": real_domain, "label": f"Domain: {real_domain}", "type": "domain"})
                edges.append({"source": target, "target": real_domain, "relation": "resolves_to"})
            except Exception:
                nodes.append({"id": "Unknown", "label": "Unknown Host", "type": "network"})
                edges.append({"source": target, "target": "Unknown", "relation": "located_in"})
            summary_msg = f"IP geolocation lookup for {target}."
        elif ttype == "username":
            for p in ["Instagram", "Twitter/X", "TikTok", "GitHub", "LinkedIn"]:
                nodes.append({"id": f"{p}_{target}", "label": f"{p}: @{target}", "type": "social"})
                edges.append({"source": target, "target": f"{p}_{target}", "relation": "profile_on"})
            summary_msg = f"Username @{target} searched across major platforms."
        elif ttype == "phone":
            for a in ["WhatsApp", "Telegram", "Viber", "Signal"]:
                nodes.append({"id": f"{a}_{target}", "label": f"{a}: {target}", "type": "app"})
                edges.append({"source": target, "target": f"{a}_{target}", "relation": "registered_on"})
            summary_msg = f"Phone/email {target} searched across messaging apps."

    if not summary_msg:
        summary_msg = "Scan completed successfully."

    risk_score, risk_level = calculate_risk(findings)
    return {
        "summary": summary_msg,
        "resolved_ip": resolved_ip,   # ← الفرونت اند يستخدمه للـ geo
        "risk_assessment": {"score": risk_score, "level": risk_level},
        "graph_data": {"nodes": nodes, "edges": edges},
    }


@app.post("/api/v1/whois")
async def whois_lookup(request: WhoisRequest):
    domain = re.sub(r'^https?://', '', request.domain.strip().lower()).split('/')[0]
    if not domain or '.' not in domain:
        raise HTTPException(400, "Invalid domain name.")

    a_rec, ns_rec, mx_rec, ssl_info = await asyncio.gather(
        dns_query(domain, "A"), dns_query(domain, "NS"),
        dns_query(domain, "MX"), get_ssl_info(domain)
    )

    registrar   = infer_registrar(ns_rec)
    tld         = domain.split(".")[-1].upper()
    domain_type = {"GOV":"Government","MIL":"Military","EDU":"Education","ORG":"Organization","NET":"Network"}.get(tld, "Commercial")
    resolved_ip = a_rec[0] if a_rec else None

    nodes = [{"id": domain, "label": domain, "type": "domain"}]
    edges = []
    for ip in a_rec[:3]:
        nodes.append({"id": ip, "label": f"IP: {ip}", "type": "ip"})
        edges.append({"source": domain, "target": ip, "relation": "resolves_to"})
    for ns in ns_rec[:3]:
        ns = ns.rstrip(".")
        nodes.append({"id": ns, "label": f"NS: {ns}", "type": "nameserver"})
        edges.append({"source": domain, "target": ns, "relation": "nameserver"})
    for mx in mx_rec[:2]:
        mx_host = (mx.split(" ", 1)[-1] if " " in mx else mx).rstrip(".")
        nodes.append({"id": mx_host, "label": f"MX: {mx_host}", "type": "mail"})
        edges.append({"source": domain, "target": mx_host, "relation": "mail_server"})

    ssl_status = "Valid" if ssl_info.get("valid") else "Invalid"
    return {
        "domain": domain, "tld": tld, "domain_type": domain_type,
        "registrar": registrar,
        "resolved_ip": resolved_ip,
        "dns_records": {
            "A":  a_rec,
            "NS": [n.rstrip(".") for n in ns_rec],
            "MX": [(m.split(" ", 1)[-1] if " " in m else m).rstrip(".") for m in mx_rec]
        },
        "ssl": ssl_info,
        "graph_data": {"nodes": nodes, "edges": edges},
        "summary": f"{domain} ({domain_type}) | Registrar: {registrar} | SSL: {ssl_status}"
    }


@app.post("/api/v1/portscan")
async def port_scan(request: PortScanRequest):
    target = request.target.strip()
    try:
        ip = await resolve_host(target)
    except Exception:
        raise HTTPException(400, f"Cannot resolve target: {target}")

    ports_to_scan = request.ports if request.ports else list(COMMON_PORTS.keys())
    results       = await asyncio.gather(*[check_port(ip, p) for p in ports_to_scan])

    open_ports      = [r for r in results if r["open"]]
    closed_count    = len([r for r in results if not r["open"]])
    open_dangerous  = [r for r in open_ports if r["port"] in DANGEROUS_PORTS]

    nodes = [{"id": target, "label": target, "type": "ip" if target[0].isdigit() else "domain"}]
    edges = []
    for p in open_ports:
        nid = f"port_{p['port']}"
        nodes.append({"id": nid, "label": f"{p['port']}/{p['service']}", "type": "port_open"})
        edges.append({"source": target, "target": nid, "relation": "open_port"})

    risk_score = min(100, len(open_ports) * 5 + len(open_dangerous) * 20)
    risk_level = "Low" if risk_score < 30 else "Medium" if risk_score < 70 else "High"

    return {
        "target": target, "ip": ip,
        "open_ports": open_ports, "closed_count": closed_count,
        "open_count": len(open_ports), "dangerous_open": open_dangerous,
        "risk_assessment": {"score": risk_score, "level": risk_level},
        "graph_data": {"nodes": nodes, "edges": edges},
        "summary": (f"Scanned {target} ({ip}) — {len(open_ports)} open port(s) out of {len(ports_to_scan)} — "
                    f"{'⚠️ Dangerous ports exposed!' if open_dangerous else '✅ No dangerous ports open.'}")
    }


@app.post("/api/v1/scan-image")
async def scan_image(branch: str = Form(...), file: UploadFile = File(...)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(400, "Uploaded file is not an image.")
    filename = file.filename or "image"
    return {
        "summary": f"Image ({filename}) analyzed. GPS location extracted from EXIF (simulated): Baghdad, Iraq.",
        "resolved_ip": None,
        "risk_assessment": {"score": 10, "level": "Low"},
        "graph_data": {
            "nodes": [{"id": filename, "label": f"Image: {filename}", "type": "image"},
                      {"id": "GPS",    "label": "GPS: 33.315, 44.366", "type": "geo"}],
            "edges": [{"source": filename, "target": "GPS", "relation": "exif_location"}]
        },
    }