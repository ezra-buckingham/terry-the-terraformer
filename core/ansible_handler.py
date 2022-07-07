from pathlib import Path
import jinja2
import ansible_runner
import yaml

from core.binary_handler import BinaryHandler
from core.log_handler import LogHandler

class AnsibleHandler:
    """
    A Class used for handling all interactions with Ansible.
    """

    """
    Known issue https://github.com/ansible/ansible-runner/issues/544
    """

    def __init__(self, ansible_path=None, working_dir=None, ssh_key=None): 
        self.ansible_binary = BinaryHandler('ansible', ansible_path)
        self.working_dir = working_dir
        self.ssh_key = ssh_key


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


    @classmethod
    def build_ansible_inventory(self, ctx_obj):
        from core import get_implemented_server_types
        # We want to build a file so that ansible could be independently run outside of terry
        # as opposed to passing a dict to ansible_runner

        server_types = get_implemented_server_types()
        inventory = {inventory: {'hosts': {}} for inventory in server_types}

        for resource in ctx_obj['all_resources']:
            inventory[resource.server_type]['hosts'][resource.public_ip] = resource.prepare_object_for_ansible()
            
        # Ansible will lock this file at times, so we need to try to write the changes, but may not be able to
        try:
            # Create the Global Vars to pass to ansible
            global_vars = ctx_obj["ansible_configuration"]["global"]
            global_vars["op_directory"] = str(ctx_obj["op_directory"].resolve())
            global_vars["nebula"] = not ctx_obj['no_nebula']
            # If installing Nebula, give the additional vars needed for configuring it on the hosts
            if global_vars["nebula"]:
                global_vars["lighthouse_public_ip"] = ctx_obj['lighthouse_public_ip']
                global_vars["lighthouse_nebula_ip"] = ctx_obj['lighthouse_nebula_ip']

            # Give Ansible the default users from the configuration file
            default_users = ctx_obj["ansible_configuration"]["default_users"]
            global_vars['team'] = default_users

            # Check if we have extra_vars to put into the inventory
            path_to_extra_vars = ctx_obj["op_directory"].joinpath('ansible/extra_vars')
            yaml_files = list(path_to_extra_vars.glob('**/*.yml'))
            for yaml_file in yaml_files:
                # Open the file, parse it, and then spread it into the global vars
                open_yaml_file = Path(yaml_file)
                file_contents = open_yaml_file.read_text()
                yaml_contents = yaml.safe_load(file_contents)
                global_vars = {
                    **yaml_contents,
                    **global_vars
                }
                
            # Build the dictionary and write it to disk
            ansible_inventory = {'all': { 'vars': global_vars, 'children': inventory }}
            yaml_text = yaml.safe_dump(ansible_inventory)
            Path(ctx_obj['op_directory']).joinpath('ansible/inventory/hosts').write_text(yaml_text)
        except PermissionError as e:
            LogHandler.warn('There was a "PermissionError" while writing the Ansible inventory file')
        
        return inventory