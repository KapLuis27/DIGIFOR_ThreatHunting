import os
import django
import time
import threading
import schedule
from datetime import datetime

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_hunting.settings')
django.setup()

from django.conf import settings
from hunting.utils import update_threat_intelligence, check_iocs

def update_threat_intel_job():
    """Scheduled job to update threat intelligence"""
    print(f"[{datetime.now()}] Running scheduled threat intelligence update...")
    try:
        # Update threat intelligence
        results = update_threat_intelligence()
        print(f"[{datetime.now()}] Added {len(results)} new IOCs to the database")
        
        # Check current system against updated IOCs
        check_iocs()
        print(f"[{datetime.now()}] Completed IOC checking against system")
    except Exception as e:
        print(f"[{datetime.now()}] Error in scheduled update: {e}")

def run_scheduler():
    """Run the scheduler in a separate thread"""
    # Set up the scheduler
    interval_hours = getattr(settings, 'THREAT_INTEL_UPDATE_INTERVAL', 24)
    schedule.every(interval_hours).hours.do(update_threat_intel_job)
    
    # Also run once at startup
    update_threat_intel_job()
    
    print(f"[{datetime.now()}] Scheduler started. Will update threat intelligence every {interval_hours} hours")
    
    while True:
        schedule.run_pending()
        time.sleep(60)  # Check every minute

def start_scheduler():
    """Start the scheduler in a background thread"""
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()
    return scheduler_thread

# For manual testing
if __name__ == "__main__":
    print("Starting scheduler in foreground for testing...")
    run_scheduler()