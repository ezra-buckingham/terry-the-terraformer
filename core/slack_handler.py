import requests

from core.jinja_handler import JinjaHandler
from core.log_handler import LogHandler


class SlackHandler:
    """A class to help with sending Slack Messages to webhooks"""

    def __init__(self, webhook_url, quiet_mode=False):
        self.webhook_url = webhook_url
        self.quiet_mode = quiet_mode
        self._jinja_handler = JinjaHandler('templates/slack')
    
    def send_success(self, data):
        payload = self._jinja_handler.get_and_render_template('slack_success_message.j2', data)
        self._send(payload)

    def send_destroy_success(self, data):
        payload = self._jinja_handler.get_and_render_template('slack_destroy_success_message.j2', data)
        self._send(payload)

    def send_error(self, message):
        payload = self._jinja_handler.get_and_render_template('slack_error_message.j2', {'message': message})
        self._send(payload)
        
    def _send(self, payload):
        if self.quiet_mode:
            LogHandler.debug('Skipping sending Slack Notification because quiet mode is on. SHHHHHHH!')
            return
        try:
            payload = payload.encode("utf-8")
            results = requests.post(self.webhook_url, payload)
            results.raise_for_status()
        except Exception as e:
            LogHandler.error(f'Some error occured when sending Slack message: {e}')