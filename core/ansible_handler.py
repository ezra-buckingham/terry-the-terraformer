import jinja2
import ansible_runner

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