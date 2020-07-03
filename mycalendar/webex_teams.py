import requests
import json
from pprint import pprint
from configparser import ConfigParser
import os

class webexTeams():

    def __init__(self):

        path = os.path.dirname(os.path.abspath(__file__))
        file = path + '/config/webex.cfg'
        config = ConfigParser()
        config.read(file)
        self.API_TOKEN = config.get('Webex', 'token')

        if not self.API_TOKEN:
            print('Error: Webex token must be defined in config \
            file (config/webex.cfg)')
            exit(1)

        self.API_ENDPOINT = "https://api.ciscospark.com/v1/"
        self.API_AUTH = 'Bearer ' + self.API_TOKEN
        self.headers = {
            'Authorization': self.API_AUTH,
        }

    def send_to_email(self, recipient, message):

        url = self.API_ENDPOINT + "messages"
        data = [
          ('roomId', recipient),
          ('text', message),
        ]

        try:
            # send message
            response = requests.post(url, headers=self.headers, data=data)
            response.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        # convert <str> to <dict>
        json_data = json.loads(response.text)
        return json_data

    def get_domain_people(self):

        url = self.API_ENDPOINT + "people"

        try:
            # send message
            response = requests.get(url, headers=self.headers)
            response.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        # convert <str> to <dict>
        json_data = json.loads(response.text)
        return json_data

    def send_hello_to_sparky(self):
        url = self.API_ENDPOINT + "messages"
        sparky_id = 'Y2lzY29zcGFyazovL3VzL1BFT1BMRS83MjJiYjI3MS1kN2NhLTRiY2UtYTllMy00NzFlNDQxMmZhNzc'
        data = [
          ('toPersonId', sparky_id),
          ('text', 'Hello Sparky'),
        ]

        try:
            # send message
            response = requests.post(url, headers=self.headers, data=data)
            response.raise_for_status()
        except Exception as e:
            print(e)
            exit(1)

        # convert <str> to <dict>
        json_data = json.loads(response.text)
        return json_data

if __name__ == '__main__':
    wt = webexTeams()
    ret = wt.send_to_email("marco.signorini88@gmail.com", "hello world")
    pprint(ret)