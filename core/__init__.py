import os
from shutil import which
import jinja2
from jinja2 import meta
from jinja2.environment import Template
from dataclasses import dataclass
import requests
from pathlib import Path

# Bring in files so they are exported with the module
from core.terry_classes import *
from core.ansible_handler import AnsibleHandler
from core.log_handler import LogHandler
from core.shell_handler import ShellHandler
from core.terraform_handler import TerraformHandler
from core.nebula_handler import NebulaHandler
from core.remote_configuration_handler import RemoteConfigurationHandler



class JinjaHandler:
    """
    A class to help with building out the jinja templates
    """

    def __init__(self, search_path):
        self.template_loader = jinja2.FileSystemLoader(searchpath=search_path)
        self.template_env = jinja2.Environment(loader=self.template_loader)

    def get_template(self, template_path):
        """
        """
        template_path = str(template_path)
        template = self.template_env.get_template(template_path)
        return template
    
    def render_template(self, template, data, **kwargs):
        """
        """

        if isinstance(template, Template):
            return template.render(data, **kwargs)
        else:
            raise TypeError('Template provided not of type Template')
    
    def get_and_render_template(self, template_path, data, **kwargs):
        """
        """

        template = self.get_template(template_path)
        return self.render_template(template, data, **kwargs)

    def get_vars_from_template(self, template):
        """ Retrieve the list of variables in a Jinja template
        Takes in a template_path as a string or a template
        Returns a list of the varaibles
        """

        template_source = self.template_env.loader.get_source(self.template_env, template)
        parsed_content = self.template_env.parse(template_source)
        variables = meta.find_undeclared_variables(parsed_content)
        return variables


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


@dataclass
class EnvironmentVariableHandler:
    """
    A class to help with changing environment variables
    """

    name: str
    __value: str = None

    def __post_init__(self):
        self.name = self.name.upper()

    def get(self):
        if not self.__value: 
            self.__value= os.getenv(self.name)
        return self.__value

    def set(self, value):
        self.__value = value
        os.environ[self.name] = value
        return self.__value

@dataclass 
class BinaryExecutableHandler:
    """Class to represent binaries that may be required for Terry to run"""
    name: str
    path: Path

    def __post_init__(self):
        base_message = f'Binary Executable Error: "{self.name}"'

        # Check if it is already in the path
        path_to_binary = which(self.name)

        # Check if a path was given in config and if it doesn't exist
        if self.path and len(self.path) > 0:
            LogHandler.debug(f'Path provided for the "{self.name}" binary, checking to ensure it exists')
            if not Path(self.path).exists():
                message = f'{base_message} provided path "{self.path}" does not exist'
                LogHandler.error(f'{base_message} provided path "{self.path}" does not exist')
                raise FileNotFoundError(message)
        # If not, check to see if it is in the PATH
        else:
            LogHandler.debug(f'Path not provided for "{self.name}" binary, checking if it exists in current PATH')
            if not path_to_binary:
                message = f'{base_message} unable to find "{self.name}" binary in your path; Please make sure it is in your path or the path is provided in the config file'
                LogHandler.error(message)
                raise FileNotFoundError(message)

        # If we make it here, we were successfull in finding the binary
        LogHandler.debug(f'Succesfully found "{self.name}" binary')


