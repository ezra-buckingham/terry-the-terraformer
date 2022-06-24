from audioop import add
from json import JSONDecodeError
from subprocess import CalledProcessError
import jinja2
from jinja2 import meta
from jinja2.environment import Template
from dataclasses import dataclass
import requests
import ansible_runner
import logging
import ipaddress
from pathlib import Path
from python_terraform import *

module_logger = logging.getLogger('library_handlers')

class TerraformHandler:
    """
    A Class used for handling all interactions with Terraform.
    """

    def __init__(self, terraform_path, working_dir):
        self.terraform_path = terraform_path
        self.working_dir = working_dir.joinpath('terraform')
        if self.terraform_path:
            self.terraform = Terraform(working_dir=self.working_dir, terraform_bin_path=self.terraform_path)
        else:
            try:
                self.terraform = Terraform(working_dir=self.working_dir)
            except JSONDecodeError as e:
                message = 'There was a JSON error with the Terraform Handler, there may be a lock file that cannot be read.'
                module_logger.error(message)
                print(message)
                exit(code=1)
            
            
    def apply_plan(self, auto_approve=False):
        """Applies the Terraform plan.
        Takes the Click context object dictionary.
        Returns return_code, stdout, stderr, and terraform_plan string of executed Terraform functions.
        """

        # Check whether Terraform needs to be initialized
        if not self.working_dir.joinpath('terraform/.terraform.lock.hcl').exists():
            return_code, stdout, stderr = self.terraform.init()

        return_code, stdout, stderr = self.terraform.plan()
        terraform_plan = stdout

        # Terraform exit codes:
        # 0 = Succeed with empty diff (no changes)
        # 1 = Error
        # 2 = Succeeded with non-empty diff (changes present)

        # Handle the PLAN Return codes
        if return_code == 0:
            # Get the created resource details from the terraform show command
            return_code, stdout, stderr = self.terraform.show(json=IsFlagged)
            return return_code, stdout, stderr, terraform_plan
        elif return_code == 1:
            return return_code, stdout, stderr, None
        elif return_code == 2:  # Changes to be made
            # The `skip_plan` seems to be the option we need to send for auto_approve, which is a bug in the library
            return_code, stdout, stderr = self.terraform.apply(capture_output=False, skip_plan=auto_approve)
            # Handle the APPLY Return codes
            if return_code == 0:
                # Get the created resource details from the terraform show command
                return_code, stdout, stderr = self.terraform.show(json=IsFlagged)
                return return_code, stdout, stderr, terraform_plan
            elif return_code == 1:
                return return_code, stdout, stderr, terraform_plan
        
        # Non-reachable code
        return return_code, stdout, stderr, terraform_plan

    def destroy_plan(self):
        """Destroys the Terraform plan.
        Returns success (bool), stdout, stderr
        """

        # Check for an existing TF State
        if not self.working_dir.joinpath('terraform.tfstate').exists():
            return None, None, None
        
        return_code, stdout, stderr = self.terraform.destroy(force=IsNotFlagged, auto_approve=True)

        # Terraform exit codes:
        # 0 = Succeed with empty diff (no changes)
        # 1 = Error
        # 2 = Succeeded with non-empty diff (changes present)

        # Handle the DESTROY Return codes
        if return_code == 0:
            return True, stdout, stderr
        elif return_code == 1:
            return False, stdout, stderr
        elif return_code == 2:  # Changes to be made
            return True, stdout, stderr

class AnsibleHandler:
    """
    A Class used for handling all interactions with Ansible.
    """

    """
    Known issue https://github.com/ansible/ansible-runner/issues/544
    """

    def __init__(self, ssh_key=None, working_dir=None, ansible_path=None): 
        self.ansible_path = ansible_path
        self.working_dir = working_dir
        self.ssh_key = ssh_key
        self.template_loader = jinja2.FileSystemLoader(searchpath="./templates")
        self.template_env = jinja2.Environment(loader=self.template_loader)

    def run_playbook(self, playbook_path, user=None, playbook_vars=None, inventory=None, retry_limit=3, **kwargs):
        command_line_args = ''
        if user:
            command_line_args += f'-u {user}'
        if playbook_vars:
            playbook_vars = {**playbook_vars, **kwargs}
        
        runner_args = {
            'private_data_dir': self.working_dir, 
            'playbook': playbook_path,
            'cmdline': command_line_args, 
            'extravars': playbook_vars
        }

        # There are instances where the key will fail to load the first time, so allow the option for retries
        return_code = 1
        counter = 1
        while return_code == 1 and counter < retry_limit:
            if self.ssh_key:
                runner_args['ssh_key'] = self.ssh_key
            if inventory:
                runner_args['inventory'] = inventory
            # Run the command with the spread in of the args
            return_value = ansible_runner.interface.run(**runner_args)
            return_code = return_value.rc
            counter += 1

        return return_value
        

    def build_playbook(self, ctx_obj):
        # Build list of hosts (lighthouses, redirectors, teamservers) etc. as files that can be ansible inventories
        # so Ansible can run different playbooks on different host types. Having hosts as file allows files to be referenced
        # if operators want / need to manually run Ansible commands after the fact.

        template_path = str(ctx_obj['op_path'].parent.joinpath('templates/nebula_file_upload.yml'))
        template = self.template_env.get_template(template_path)

        nebula_dir = ctx_obj['op_path'].joinpath('nebula')

        # Wipe existing playbook
        with open(ctx_obj['op_path'].joinpath('ansible').joinpath('playbook.yml'), 'w') as f:
            f.write('')

        for resource in ctx_obj['resources']:
            ca_crt = nebula_dir.joinpath('ca.crt').absolute()
            host_crt = nebula_dir.joinpath(resource.name + '.crt').absolute()
            host_key = nebula_dir.joinpath(resource.name + '.key').absolute()
            host_conf = nebula_dir.joinpath(resource.name + '.conf').absolute()
            nebula_binary = ctx_obj['script_path'].parent.joinpath('nebula').joinpath('nebula').absolute()
            playbook = template.render(host=resource.public_ip, remote_user=resource.remote_user, ca_crt=ca_crt, host_crt=host_crt, host_key=host_key, host_conf=host_conf, nebula_binary=nebula_binary)

            #If you want a per-host playbook
            #with open(ctx_obj['op_path'].joinpath('ansible').joinpath(resource.name + '.yml'), 'a') as f:
            with open(ctx_obj['op_path'].joinpath('ansible').joinpath('playbook.yml'), 'a') as f:
                f.write(playbook)

        ansible_runner.interface.run(ssh_key=ctx_obj['ssh_key'], private_data_dir=ctx_obj['op_path'].joinpath('ansible'), playbook='playbook.yml', verbosity=10)


class NebulaHandler:
    """
    A Class used for handling all interactions with Nebula.
    """

    def __init__(self, nebula_path, nebula_subnet, working_dir):
        self.nebula_path = nebula_path
        self.nebula_ca_binary = Path(self.nebula_path).joinpath('nebula-cert')
        self.working_dir = working_dir.joinpath('nebula')
        self.nebula_subnet = ipaddress.IPv4Network(nebula_subnet)
        self.__assigned_ips = set()
        self.template_loader = jinja2.FileSystemLoader(searchpath="./")
        self.template_env = jinja2.Environment(loader=self.template_loader)

    def __get_new_ip(self):
        for address in self.nebula_subnet:
            # If any of the bits not set, don't use it
            if len([add for add in str(address).split('.') if add == '0']) > 0:
                self.__assigned_ips.add(address)
            # If the address not in assinged IP space, give it out
            if address not in self.__assigned_ips:
                self.__assigned_ips.add(address)
                return address
        
        raise ipaddress.AddressValueError('No more IP addresses available in the subnet')
        

    def generate_ca_certs(self):
        from utils import make_system_call
        
        # Create the command and run it
        generate_command = f'{ str(self.nebula_ca_binary) } ca -name 5TAG3'

        module_logger.info('Generating Nebula CA Root certificate and key')
        try:
            make_system_call(generate_command, str(self.working_dir))
        except CalledProcessError as e:
            module_logger.error('There was an error generating the Nebula CA Root:')
            module_logger.error(f'Nebula Error: { e.stderr.decode("utf-8") }')
            raise e

        module_logger.info('Generated Nebula CA Root certificate and key')

    def generate_client_cert(self, name):
        from utils import make_system_call

        # Get a new IP from the range
        new_ip = self.__get_new_ip()
        new_ip_cidr = str(new_ip) + '/' + str(self.nebula_subnet.prefixlen)

        # Create the command and run it
        generate_command = f'{ str(self.nebula_ca_binary) } sign -name { name.replace(" ", "") } -ip { new_ip_cidr }'
        
        module_logger.info(f'Generating Nebula client certificate and key for {name} at { new_ip_cidr }')
        try:
            make_system_call(generate_command, str(self.working_dir))
        except CalledProcessError as e:
            module_logger.error('There was an error generating the Nebula Client Certificate and Key:')
            module_logger.error(f'Nebula Error: { e.stderr.decode("utf-8") }')
            raise e

        module_logger.info(f'Generated Nebula client certificate and key for {name} at { new_ip_cidr }')

        return new_ip.exploded

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

@dataclass 
class SlackHandler:
    """A class to help with sending Slack Messages to webhooks"""
    webhook_url: str
    template_location: str = 'templates/slack'
    _jinja_handler: JinjaHandler = None
    _success_template_name: str = 'slack_success_message.j2'
    _destroy_success_template_name: str = 'slack_destroy_success_message.j2'
    _error_template_name: str = 'slack_error_message.j2'
    
    def __post_init__(self):
        self._jinja_handler = JinjaHandler(self.template_location)
    
    def send_success(self, data):
        payload = self._jinja_handler.get_and_render_template(self._success_template_name, data)
        self._send(payload)

    def send_destroy_success(self, data):
        payload = self._jinja_handler.get_and_render_template(self._destroy_success_template_name, data)
        self._send(payload)

    def send_error(self, message):
        payload = self._jinja_handler.get_and_render_template(self._error_template_name, {'message': message})
        self._send(payload)
        
    def _send(self, payload):
        try:
            payload = payload.encode("utf-8")
            results = requests.post(self.webhook_url, payload)
            results.raise_for_status()
        except Exception as e:
            logging.error(f'Some error occured when sending Slack message: {e}')


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

