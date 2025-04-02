from django.shortcuts import render, redirect
from .models import Process, NetworkConnection, RegistryKey, IOC
from .utils import (
    get_running_processes, get_network_connections, get_registry_keys, 
    check_virustotal, generate_incident_report, check_iocs,
    update_threat_intelligence, fetch_mitre_iocs
)
from django.http import FileResponse
from datetime import datetime

def index(request):
    processes = get_running_processes()
    network_connections = get_network_connections()
    registry_keys = get_registry_keys()
    iocs = IOC.objects.all()
    
    # Save running processes
    for proc in processes:
        process_obj, _ = Process.objects.get_or_create(
            name=proc["name"], pid=proc["pid"], path=proc["path"], hash_value=proc["hash_value"]
        )
        
        # Check VirusTotal for process hash
        if process_obj.hash_value:
            result = check_virustotal(process_obj.hash_value)
            if result and result.get("malicious", 0) > 0:
                process_obj.detected = True
                process_obj.save()

    # Save network connections
    for conn in network_connections:
        NetworkConnection.objects.get_or_create(
            local_ip=conn["local_ip"],
            local_port=conn["local_port"],
            remote_ip=conn.get("remote_ip", "0.0.0.0"),  # Default to "0.0.0.0"
            remote_port=conn.get("remote_port", 0),  # Default to port 0
            protocol=conn["protocol"]
        )

    # Save registry keys
    for key in registry_keys:
        RegistryKey.objects.get_or_create(key=key["key"], value=key["value"])

    # Check stored IOCs against current system state
    check_iocs()
    
    # Get last update time
    last_update = request.session.get('last_ti_update', 'Never')

    return render(request, 'hunting/index.html', {
        'processes': Process.objects.all(),
        'network_connections': NetworkConnection.objects.all(),
        'registry_keys': RegistryKey.objects.all(),
        'iocs': iocs,
        'last_update': last_update
    })

def add_ioc(request):
    if request.method == "POST":
        ioc_type = request.POST.get("ioc_type")
        ioc_value = request.POST.get("ioc_value")

        IOC.objects.get_or_create(ioc_type=ioc_type, value=ioc_value)  # Save IOC
    return redirect('index')

def download_report(request):
    file_name = generate_incident_report()
    return FileResponse(open(file_name, "rb"), as_attachment=True, content_type="application/pdf")

def update_threat_intel(request):
    """Update threat intelligence from all configured sources"""
    # Call the integrated function to update from all sources
    all_results = update_threat_intelligence()
    
    # Save the current time as the last update time
    request.session['last_ti_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return render(request, 'hunting/update_intel.html', {
        "fetched_iocs": all_results,
        "sources": [
            "MITRE ATT&CK",
            "MalwareBazaar",
            "PhishTank",
            "AlienVault OTX (if configured)",
            "MISP (if configured)"
        ]
    })

# Legacy function for compatibility
def update_mitre_iocs(request):
    """Fetch MITRE ATT&CK IOCs."""
    mitre_iocs = fetch_mitre_iocs()
    
    request.session['last_ti_update'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    return render(request, 'hunting/update_intel.html', {
        "fetched_iocs": mitre_iocs,
        "sources": ["MITRE ATT&CK"]
    })