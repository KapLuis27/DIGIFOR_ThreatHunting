# threat_hunting/wsgi.py

import os
from django.core.wsgi import get_wsgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'threat_hunting.settings')

application = get_wsgi_application()

# # Start the scheduler
# from hunting.scheduled_tasks import start_scheduler
# scheduler_thread = start_scheduler()