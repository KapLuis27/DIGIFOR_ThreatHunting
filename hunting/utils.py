import psutil
import socket
import hashlib
import os
import requests
import json
from datetime import datetime, timedelta
import winreg
from reportlab.pdfgen import canvas
from .models import Process, NetworkConnection, IOC, RegistryKey

# Original VirusTotal API key
VIRUSTOTAL_API_KEY = '3a4b21f73e04210fa98b7167623f43e96b2ef73a84e8ea7e41820069b2594d33'

# Original functions

def generate_incident_report():
    file_name = "incident_report.pdf"
    c = canvas.Canvas(file_name)
    c.drawString(100, 800, "Incident Report - Threat Hunting System")

    y_position = 750
    has_threats = False  # Track if threats exist

    # Add Malicious Processes
    for proc in Process.objects.filter(detected=True):
        c.drawString(100, y_position, f"⚠️ Malicious Process: {proc.name} - PID {proc.pid}")
        y_position -= 20
        has_threats = True

    # Add Malicious Network Connections
    for conn in NetworkConnection.objects.filter(detected=True):
        c.drawString(100, y_position, f"⚠️ Malicious Connection: {conn.remote_ip}:{conn.remote_port}")
        y_position -= 20
        has_threats = True

    # If no threats, add a "No threats detected" message
    if not has_threats:
        c.drawString(100, y_position, "✅ No threats detected in the system.")

    c.save()
    return file_name

def check_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        return response.json()
    except Exception as e:
        print(f"Error checking VirusTotal: {e}")
        return {"malicious": 0}

def get_running_processes():
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            processes.append({
                "name": proc.info['name'],
                "pid": proc.info['pid'],
                "path": proc.info['exe'],
                "hash_value": hash_file(proc.info['exe']) if proc.info['exe'] else None
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return processes

def get_network_connections():
    connections = []
    for conn in psutil.net_connections(kind='inet'):
        try:
            connections.append({
                "local_ip": conn.laddr.ip,
                "local_port": conn.laddr.port,
                "remote_ip": conn.raddr.ip if conn.raddr else None,
                "remote_port": conn.raddr.port if conn.raddr else None,
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
            })
        except Exception:
            continue
    return connections

def hash_file(filepath):
    if not os.path.exists(filepath):
        return None
    try:
        hasher = hashlib.sha256()
        with open(filepath, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception:
        return None

def get_registry_keys():
    registry_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce"
    ]
    extracted_keys = []
    
    for path in registry_paths:
        try:
            reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path)
            i = 0
            while True:
                try:
                    value_name, value_data, _ = winreg.EnumValue(reg, i)
                    if value_data:  # skip empty values
                        extracted_keys.append({"key": path, "value": f"{value_name}: {value_data}"})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(reg)
        except Exception:
            pass

    return extracted_keys

def check_iocs():
    iocs = IOC.objects.all()

    # Convert IOCs to lookup lists
    process_iocs = [ioc.value.lower() for ioc in iocs if ioc.ioc_type == "process"]
    ip_iocs = [ioc.value for ioc in iocs if ioc.ioc_type == "ip"]

    # Check processes against user-defined IOCs
    for proc in Process.objects.all():
        if proc.name.lower() in process_iocs:
            proc.detected = True
            proc.save()

    # Check network connections against user-defined IOCs
    for conn in NetworkConnection.objects.all():
        if conn.remote_ip in ip_iocs:
            conn.detected = True
            conn.save()

# New automated threat intelligence functions

# AlienVault OTX API integration
def fetch_otx_iocs(api_key):
    """Fetch IOCs from AlienVault OTX"""
    base_url = "https://otx.alienvault.com/api/v1"
    headers = {"X-OTX-API-KEY": api_key}
    
    # Get subscribed pulses from the last 30 days
    time_frame = datetime.now() - timedelta(days=30)
    time_frame_str = time_frame.strftime("%Y-%m-%d")
    
    # Fetch recent pulses
    pulses_url = f"{base_url}/pulses/subscribed?modified_since={time_frame_str}"
    try:
        response = requests.get(pulses_url, headers=headers)
        response.raise_for_status()
        
        pulses = response.json().get("results", [])
        
        # Extract IOCs
        process_iocs = []
        ip_iocs = []
        
        for pulse in pulses:
            for indicator in pulse.get("indicators", []):
                indicator_type = indicator.get("type")
                indicator_value = indicator.get("indicator")
                
                if indicator_type == "FileHash-SHA256" or indicator_type == "FileHash-MD5":
                    # Find associated file names if available
                    if "file_name" in indicator:
                        process_iocs.append(indicator.get("file_name"))
                
                elif indicator_type == "executable" or indicator_type == "file":
                    if "file_name" in indicator:
                        process_iocs.append(indicator.get("file_name"))
                
                elif indicator_type == "IPv4" or indicator_type == "IPv6":
                    ip_iocs.append(indicator_value)
        
        # Save the IOCs to the database
        saved_iocs = []
        for process_name in process_iocs:
            if process_name:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="process", 
                    value=process_name
                )
                if created:
                    saved_iocs.append({"type": "process", "value": process_name})
        
        for ip in ip_iocs:
            if ip:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="ip", 
                    value=ip
                )
                if created:
                    saved_iocs.append({"type": "ip", "value": ip})
        
        return saved_iocs
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching OTX IOCs: {e}")
        return []

# MISP API integration (open source threat intelligence platform)
def fetch_misp_iocs(misp_url, misp_key):
    """Fetch IOCs from MISP"""
    headers = {
        "Authorization": misp_key,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    # Get recent events
    events_url = f"{misp_url}/events/index"
    params = {"limit": 50, "published": 1}  # Get latest 50 published events
    
    try:
        response = requests.post(events_url, headers=headers, json=params)
        response.raise_for_status()
        
        events = response.json()
        
        process_iocs = []
        ip_iocs = []
        
        # For each event, get attributes
        for event in events:
            event_id = event.get("Event", {}).get("id")
            if not event_id:
                continue
                
            attributes_url = f"{misp_url}/attributes/restSearch"
            attribute_params = {
                "eventid": event_id,
                "type": ["filename", "md5", "sha256", "ip-src", "ip-dst"]
            }
            
            try:
                attr_response = requests.post(attributes_url, headers=headers, json=attribute_params)
                attr_response.raise_for_status()
                
                attributes = attr_response.json().get("response", {}).get("Attribute", [])
                
                for attribute in attributes:
                    attr_type = attribute.get("type")
                    attr_value = attribute.get("value")
                    
                    if attr_type == "filename":
                        process_iocs.append(attr_value)
                    elif attr_type in ["ip-src", "ip-dst"]:
                        ip_iocs.append(attr_value)
            except:
                continue
        
        # Save the IOCs to the database
        saved_iocs = []
        for process_name in process_iocs:
            if process_name:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="process", 
                    value=process_name
                )
                if created:
                    saved_iocs.append({"type": "process", "value": process_name})
        
        for ip in ip_iocs:
            if ip:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="ip", 
                    value=ip
                )
                if created:
                    saved_iocs.append({"type": "ip", "value": ip})
        
        return saved_iocs
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching MISP IOCs: {e}")
        return []

# Improved MITRE ATT&CK IOC fetching
def fetch_mitre_iocs():
    """Fetch known MITRE ATT&CK IOCs from STIX/TAXII."""
    # MITRE ATT&CK STIX data - improved to extract useful IOCs
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        ioc_list = []

        # Process objects more effectively
        for item in data.get("objects", []):
            if item.get("type") == "attack-pattern":
                # Get technique name and ID
                technique_name = item.get("name", "")
                technique_id = item.get("external_references", [{}])[0].get("external_id", "")
                
                # Check if there are specific software references
                if "x_mitre_detection" in item:
                    detection_text = item["x_mitre_detection"]
                    
                    # Extract potential process names from detection text
                    # This is a simple example - more sophisticated parsing may be needed
                    if "process" in detection_text.lower():
                        lines = detection_text.split("\n")
                        for line in lines:
                            if ".exe" in line.lower():
                                # Extract potential executable names
                                words = line.split()
                                for word in words:
                                    if word.lower().endswith(".exe"):
                                        # Clean up the word to get just the process name
                                        process_name = word.strip(".,()[]{}\"'").lower()
                                        ioc_list.append({"type": "process", "value": process_name})
            
            # Look for malware or tool objects which often have associated file names
            elif item.get("type") in ["malware", "tool"]:
                malware_name = item.get("name", "")
                
                # Some malware entries use the same name for the process
                if ".exe" not in malware_name.lower():
                    malware_name += ".exe"
                
                ioc_list.append({"type": "process", "value": malware_name.lower()})
                
                # If there are aliases, add them too
                for alias in item.get("x_mitre_aliases", []):
                    if alias and alias != malware_name:
                        if ".exe" not in alias.lower():
                            alias += ".exe"
                        ioc_list.append({"type": "process", "value": alias.lower()})
        
        # Save the IOCs
        saved_iocs = []
        for ioc in ioc_list:
            if ioc["value"]:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type=ioc["type"], 
                    value=ioc["value"]
                )
                if created:
                    saved_iocs.append(ioc)
        
        return saved_iocs

    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE ATT&CK data: {e}")
        return []

# Abuse.ch MalwareBazaar integration
def fetch_malwarebazaar_iocs():
    """Fetch IOCs from MalwareBazaar (abuse.ch)"""
    url = "https://mb-api.abuse.ch/api/v1/"
    
    # Query for recent samples
    data = {
        "query": "get_recent",
        "selector": "time",
        "limit": 100  # Get latest 100 samples
    }
    
    try:
        response = requests.post(url, data=data)
        response.raise_for_status()
        
        result = response.json()
        
        process_iocs = []
        
        if result.get("query_status") == "ok":
            for entry in result.get("data", []):
                # Get file names
                if "file_name" in entry and entry["file_name"]:
                    process_iocs.append(entry["file_name"])
                
                # Get tags which sometimes contain malware family names
                for tag in entry.get("tags", []):
                    if tag and len(tag) > 3:  # Avoid too short tags
                        # Add common malware extensions if not present
                        if not any(tag.lower().endswith(ext) for ext in ['.exe', '.dll', '.bin']):
                            tag += ".exe"
                        process_iocs.append(tag)
        
        # Save the IOCs
        saved_iocs = []
        for process_name in process_iocs:
            if process_name:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="process", 
                    value=process_name
                )
                if created:
                    saved_iocs.append({"type": "process", "value": process_name})
        
        return saved_iocs
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching MalwareBazaar IOCs: {e}")
        return []

# PhishTank integration for malicious URLs/domains
def fetch_phishtank_iocs():
    """Fetch phishing IOCs from PhishTank"""
    url = "https://data.phishtank.com/data/online-valid.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        
        data = response.json()
        ip_iocs = []
        
        for entry in data:
            # Extract IP if available
            if "ip_address" in entry and entry["ip_address"]:
                ip_iocs.append(entry["ip_address"])
        
        # Save the IOCs
        saved_iocs = []
        for ip in ip_iocs:
            if ip:  # Skip empty values
                obj, created = IOC.objects.get_or_create(
                    ioc_type="ip", 
                    value=ip
                )
                if created:
                    saved_iocs.append({"type": "ip", "value": ip})
        
        return saved_iocs
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching PhishTank IOCs: {e}")
        return []

# Integrated threat intelligence function
def update_threat_intelligence():
    """Update threat intelligence from multiple sources"""
    # Store results from all sources
    all_results = []
    
    # 1. MITRE ATT&CK
    mitre_results = fetch_mitre_iocs()
    all_results.extend(mitre_results)
    
    # 2. MalwareBazaar
    malwarebazaar_results = fetch_malwarebazaar_iocs()
    all_results.extend(malwarebazaar_results)
    
    # 3. PhishTank
    phishtank_results = fetch_phishtank_iocs()
    all_results.extend(phishtank_results)
    
    # 4. AlienVault OTX (if configured)
    from django.conf import settings
    otx_api_key = getattr(settings, 'OTX_API_KEY', '')
    if otx_api_key:
        otx_results = fetch_otx_iocs(otx_api_key)
        all_results.extend(otx_results)
    
    # 5. MISP (if configured)
    misp_url = getattr(settings, 'MISP_URL', '')
    misp_key = getattr(settings, 'MISP_API_KEY', '')
    if misp_url and misp_key:
        misp_results = fetch_misp_iocs(misp_url, misp_key)
        all_results.extend(misp_results)
    
    # After updating IOCs, check them against current system state
    check_iocs()
    
    return all_results