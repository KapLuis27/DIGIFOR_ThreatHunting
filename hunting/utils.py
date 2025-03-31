import psutil
import socket
import hashlib
import os
import requests
import winreg
from reportlab.pdfgen import canvas
from .models import Process, NetworkConnection, IOC

VIRUSTOTAL_API_KEY = '991b53382a4f41a02dd4e35bf2ad9a4daabd8008d9f838577f2b5a55df6963d6'

def generate_incident_report():
    file_name = "incident_report.pdf"
    c = canvas.Canvas(file_name)
    c.drawString(100, 800, "Incident Report - Threat Hunting System")

def check_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    return response.json()

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
        connections.append({
            "local_ip": conn.laddr.ip,
            "local_port": conn.laddr.port,
            "remote_ip": conn.raddr.ip if conn.raddr else None,
            "remote_port": conn.raddr.port if conn.raddr else None,
            "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
        })
    return connections

def hash_file(filepath):
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

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
                    if value_data:  #skip empty values
                        extracted_keys.append({"key": path, "value": f"{value_name}: {value_data}"})
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(reg)
        except Exception:
            pass

    return extracted_keys


def generate_incident_report():
    file_name = "incident_report.pdf"
    c = canvas.Canvas(file_name)
    c.drawString(100, 800, "Incident Report - Threat Hunting System")

    y_position = 750
    has_threats = False  # ✅ Track if threats exist

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

    # ✅ If no threats, add a "No threats detected" message
    if not has_threats:
        c.drawString(100, y_position, "✅ No threats detected in the system.")

    c.save()
    return file_name

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

def fetch_mitre_iocs():
    """Fetch known MITRE ATT&CK IOCs from public sources."""
    url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        ioc_list = []

        for item in data["objects"]:
            if "x_mitre_data_sources" in item:
                if "Process monitoring" in item["x_mitre_data_sources"]:
                    # Extract process names linked to attack techniques
                    process_name = item.get("name", "Unknown Process")
                    ioc_list.append({"type": "process", "value": process_name})
                if "Network traffic" in item["x_mitre_data_sources"]:
                    # Extract associated IP indicators
                    network_name = item.get("name", "Unknown Network Indicator")
                    ioc_list.append({"type": "ip", "value": network_name})

        return ioc_list

    except requests.exceptions.RequestException as e:
        print(f"Error fetching MITRE ATT&CK data: {e}")
        return []