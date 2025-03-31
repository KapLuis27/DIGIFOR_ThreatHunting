from django.shortcuts import render, redirect
from .models import Process, NetworkConnection, RegistryKey, IOC
from .utils import get_running_processes, get_network_connections, get_registry_keys, check_virustotal, generate_incident_report, check_iocs
from .utils import fetch_mitre_iocs
from django.http import FileResponse

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

      ### ADD TEST DATA (FAKE MALICIOUS IOC MATCHES) ###
    #Process.objects.get_or_create(
     #   name="mimikatz.exe", pid=9999, path="C:\\temp\\mimikatz.exe", hash_value="dummyhash", detected=False
    #)

   #NetworkConnection.objects.get_or_create(
   #    local_ip="192.168.0.101", local_port=4444, remote_ip="192.168.1.100", remote_port=80, protocol="TCP", detected=False
   # )

    check_iocs()

    return render(request, 'hunting/index.html', {
        'processes': Process.objects.all(),
        'network_connections': NetworkConnection.objects.all(),
        'registry_keys': RegistryKey.objects.all(),
        'iocs' : iocs
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

def update_mitre_iocs(request):
    """Fetch MITRE ATT&CK IOCs and display them to the user."""
    mitre_iocs = fetch_mitre_iocs()
    
    fetched_iocs = []  # Store newly fetched IOCs to show the user
    for ioc in mitre_iocs:
        obj, created = IOC.objects.get_or_create(ioc_type=ioc["type"], value=ioc["value"])
        if created:
            fetched_iocs.append(ioc)  # Only show newly added IOCs
    
    ### ADD TEST DATA (FAKE MALICIOUS IOC MATCHES) ###
    Process.objects.get_or_create(
        name="mimikatz.exe", pid=9999, path="C:\\temp\\mimikatz.exe", hash_value="dummyhash", detected=False
    )

    Process.objects.get_or_create(
        name="hacker-tool.exe", pid=8888, path="C:\\temp\\hacker-tool.exe", hash_value="fakehash", detected=False
    )

    NetworkConnection.objects.get_or_create(
        local_ip="192.168.0.101", local_port=4444, remote_ip="192.168.1.100", remote_port=80, protocol="TCP", detected=False
    )

    NetworkConnection.objects.get_or_create(
        local_ip="192.168.0.102", local_port=5555, remote_ip="203.0.113.45", remote_port=443, protocol="TCP", detected=False
    )
    

    return render(request, 'hunting/update_mitre.html', {"fetched_iocs": fetched_iocs})