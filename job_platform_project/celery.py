import os
from celery import Celery

# მიუთითე settings.py
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'job_platform_project.settings')

app = Celery('job_platform_project')

# გამოიყენე Django-ს settings Celery-სთვის
app.config_from_object('django.conf:settings', namespace='CELERY')

# ავტომატურად იპოვოს tasks.py ფაილები ყველა აპში
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
