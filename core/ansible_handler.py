import ansible_runner

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

        LogHandler.debug(f'Running the "{ playbook_path }" playbook')

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
            
            if return_code == 1:
                message = return_value.stdout.read()
                if 'Error loading key' in str(message):
                    LogHandler.warn(f'Known Ansible Error: { message } (ignore if Ansible safely continues)')
                else:
                    LogHandler.error(f'Ansible Error: { message }')

            counter += 1

        return return_value
