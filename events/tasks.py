from celery.decorators import task
from celery.utils.log import get_task_logger
#from feedback.emails import send_feedback_email
from .models import Event
from celery.task.schedules import crontab
from celery.decorators import periodic_task
from celery.utils.log import get_task_logger
from datetime import datetime
from datetime import date
from datetime import time
from django.db import models
from django.core.exceptions import ValidationError
from django.core.urlresolvers import reverse
import subprocess
import requests
from requests.auth import HTTPBasicAuth
from mycalendar.webex_teams import *
from pprint import pprint
from django.contrib.auth.models import User



logger = get_task_logger(__name__)


#@task(name="send_feedback_email_task")
#def send_feedback_email_task(email, message):
#    """sends an email when feedback form is filled successfully"""
#    logger.info("Sent feedback email")
#    return send_feedback_email(email, message)

#@task(name="get_day_task")
#def get_day_task(Event):
 #   print(Event)

@periodic_task(
    run_every=(crontab(minute='*/1')),
    name="backup_config",
    ignore_result=True
)
def backup_config():
    print('Checking calendar for events...')
    #logger.info("Saved image from Flickr")
    events = Event.objects.all()
    #subprocess.call("python3 meraki-backup.py \"DevNet Sandbox\"", shell=True)
    if events.exists():
        for event in events:
            #print(event.get_day())
            #print(date.today())
            if event.get_day() == date.today():
                if event.get_start_time().hour == datetime.now().hour:
                    if event.get_start_time().minute == datetime.now().minute:
                        subprocess.call("python3 meraki-backup.py \"DevNet Sandbox\"", shell=True)
                        print('found our event')
                        wt = webexTeams()
                        ret = wt.send_to_email("Y2lzY29zcGFyazovL3VzL1JPT00vMGM4MThjMDAtODM4Zi0xMWVhLTkyOTUtNjU1NDliMDQxYTIy", "Backup configuration to all devices is created.")
                        superusers_emails = User.objects.filter(is_superuser=True).values_list('email')
                        print(superusers_emails[0][0])
                        print("Script finished")


               # now = datetime.now()
               # print(event.get_start_time().hour)
               # print(now.hour)

    #wt = webexTeams()


    #ret = wt.send_to_email("Y2lzY29zcGFyazovL3VzL1JPT00vMGM4MThjMDAtODM4Zi0xMWVhLTkyOTUtNjU1NDliMDQxYTIy", "Backup configuration is created.")
    #superusers_emails = User.objects.filter(is_superuser=True).values_list('email')
    #print(superusers_emails[0][0])
    #print("Script finished")

