from dataclasses import dataclass
import json
from pathlib import Path
from shutil import which
import uuid
import utils


#################################################################################################################
# Core & Miscellaneous
#################################################################################################################

@dataclass 
class BinaryExecutable:
    """Class to represent binaries that may be required for Terry to run"""
    name: str
    path: object

    def __post_init__(self):
        base_message = f'Binary Executable Error: "{self.name}"'

        # Check if it is already in the path
        path_to_binary = which(self.name)

        # Check if a path was given in config and if it doesn't exist
        if self.path and len(self.path) > 0:
            utils.log_debug(f'Path provided for the "{self.name}" binary, checking to ensure it exists')
            if not Path(self.path).exists():
                utils.log_error(f'{base_message} provided path "{self.path}" does not exist', True)
        # If not, check to see if it is in the PATH
        else:
            utils.log_debug(f'Path not provided for "{self.name}" binary, checking if it exists in current PATH')
            if not path_to_binary:
                utils.log_error(f'{base_message} unable to find "{self.name}" binary in your path; Please make sure it is in your path or the path is provided in the config file', True)

        # If we make it here, we were successfull in finding the binary
        utils.log_debug(f'Succesfully found "{self.name}" binary')

@dataclass
class RemoteConfiguration:
    """Class to represent a remote configuration that may can be loaded by Terry"""

    configuration_name: str 
    repository_url: str
    username: str
    personal_access_token: str
    # Default
    repo_uuid = uuid.uuid4()
    repo_folder_on_disk : Path = Path('/tmp')
    git_executable_path : str = ''
    configuration = dict()


    def __post_init__(self):
        base_message = f'Remote Configuration Error:'

        # Generate path to where we will clone the repo
        self.repo_folder_on_disk = self.repo_folder_on_disk.joinpath(str(self.repo_uuid))

        # Check if we have Git installed
        self.git_executable_path = BinaryExecutable('git', self.git_executable_path)

        # TODO Check if we were given a valid git repo URL

        try:
            utils.log_debug(f'Attempting to clone "{self.repository_url}" to "{self.repo_folder_on_disk}" using username "{self.username}"')
            self.__clone_repo()
            utils.log_debug(f'Clone of "{self.repository_url}" successfully written to "{self.repo_folder_on_disk}"')
        except Exception as e:
            utils.log_error(f'{base_message} There was an error cloning "{self.repository_url}" using provided credentials. Please make sure you have the right URL and credentials.') 

        # Now let's loop over what we got back from the remote
        try:
            utils.log_debug(f'Attempting to parse the contents of "{self.repo_folder_on_disk}"')
            self.__parse_contents()
            utils.log_debug(f'Parsing of "{self.repo_folder_on_disk}" was successful')
        except Exception as e:
            utils.log_error(f'{base_message} There was an error parsing the contents of "{self.repository_url}". Please make sure the contents are actual configuration files.') 
            

    def __clone_repo(self):
        # Create the command
        command = f"git clone https://{self.username}:{self.personal_access_token}@{self.repository_url} {self.repo_folder_on_disk}"

        # Use the system call to call git
        utils.make_system_call(command)


    def __parse_contents(self):
        # Get all JSON files from the cloned repo
        utils.log_debug(f'Pulling json files out of "{self.repo_folder_on_disk}"')
        json_files = list(self.repo_folder_on_disk.glob('**/*.json'))

        self.configuration = { self.configuration_name: {}}

        # Loop over the json_files, parse them and place them into the dict
        for file in json_files:
            utils.log_debug(f'Parsing "{file}"')

            # Open the file, parse it, and then append to the dict
            with file.open() as open_file:
                file_contents = open_file.read()
                json_contents = json.loads(file_contents)
                self.configuration[self.configuration_name][file.stem] = json_contents


#################################################################################################################
# Parent Terraform, Ansible, & Container Classes
#################################################################################################################

@dataclass 
class TerraformObject:
    """Base class for all things Terraform"""

    provider: str
    infrastructure_type: str
    terraform_resource_path: object = None
    error_on_missing_resource_file: bool = True
    uuid: str = None

    def __post_init__(self):
        self.uuid = str(uuid.uuid4())

        inferred_path = f'./templates/terraform/resources/{self.provider}/{self.infrastructure_type}.tf.j2'
        path = Path(inferred_path)
        if path.exists():
            self.terraform_resource_path = path
        else:
            raise FileNotFoundError(f'File not found at {inferred_path}')


@dataclass
class AnsibleControlledObject:
    """Base class for representing an Ansible Controlled Resource"""

    def prepare_object_for_ansible(self):
        """Take the Child AnsibleControlled Object and extract the data needed to write an inventory that the playbooks can reference

        Args:
            `None`
        Returns:
            `self_dict (dict)`: The dictonary needed for the ansible playbooks for the child object
        """
        self_dict = {
            **self.core_playbook_vars
        }

        if isinstance(self, Lighthouse):
            self_dict['am_lighthouse'] = True

        # Check for name
        if hasattr(self, 'name') and self.name is not None:
            self_dict['name'] = self.name

        # Check for a nebula ip
        if hasattr(self, 'nebula_ip') and self.nebula_ip is not None:
            self_dict['nebula_ip'] = self.nebula_ip

        # Check for a domain to impersonate
        if hasattr(self, 'domain_to_impersonate') and self.domain_to_impersonate is not None:
            self_dict['domain_to_impersonate'] = self.domain_to_impersonate

        # Check for presence of domains
        if hasattr(self, 'domain_map') and self.domain_map is not None:
            self_dict['domain_map'] = []
            for domain in self.domain_map:
                for domain_record in domain.domain_records:
                    if len(domain_record.subdomain) > 0:
                        fqdn = f'{domain_record.subdomain}.{domain.domain}'
                    else:
                        fqdn = f'{domain.domain}'
                    self_dict['domain_map'].append(fqdn)

        # Check for a redirector type
        if hasattr(self, 'redirector_type') and self.redirector_type is not None:
            self_dict['redirector_type'] = self.redirector_type

        # Check for presence of containers
        if hasattr(self, 'containers') and self.containers is not None and len(self.containers) > 0:
            self_dict['containers'] = {}
            for container in self.containers:
                self_dict['containers'][container.name] = container.prepare_object_for_ansible()
        
        return self_dict


@dataclass
class Container(AnsibleControlledObject):

    # c2_name: str
    name: str
    # Default Values
    required_args = {}
    redirector_ip: str = None
    container_config = {}

    def __post_init__(self):
        self.__base_error_message = f'Container Error ({self.name}):'

        # Get the provider mappings
        parsed_yaml = utils.get_container_mappings(False)
        services = parsed_yaml['services']
        self.container_config = services.get(self.name)

        if not self.container_config:
            utils.log_error(f'{self.__base_error_message} No container configutation found in container mappings YAML')

        # Set the core ansible vars
        self.core_playbook_vars = {
            'name': self.name,
            'redirector_ip': self.redirector_ip,
            **self.required_args
        }

    def validate(self, ctx):
        # Get the required args from config
        required_args = self.container_config.get('required_args', [])

        # If no required args, just return
        if not required_args: 
            return
        
        # Validate we have each arg
        for req_arg in required_args:
            env_var = utils.check_for_required_value(ctx, req_arg)
            self.required_args[env_var.name] = env_var.get()


#################################################################################################################
# Actual Terraform Objects
#################################################################################################################

class Provider(TerraformObject):
    """Base class for representing a Terraform provider"""

    def __init__(self, name, source, version):
        self.name = name
        self.source = source
        self.version = version


class SSHKey(TerraformObject):
    """Base class for representing an ssh key"""

    def __init__(self, provider, ssh_key_name, ssh_pub_key=None):
        self.ssh_key_name = ssh_key_name
        self.ssh_pub_key = ssh_pub_key

        TerraformObject.__init__(self, provider, 'ssh_key')


class DomainRecord(TerraformObject):
    """Base class for representing a domain record entry (such as A record or NS record)"""

    def __init__(self, provider, subdomain, record_type):
        self.subdomain = subdomain
        self.safe_subdomain = subdomain.replace('.', '-')
        self.record_type = record_type

        TerraformObject.__init__(self, provider, 'domain')


class Domain(TerraformObject):
    """Base class for representing a domain resource for Terraform"""

    def __init__(self, domain, provider):
        self.domain = domain

        TerraformObject.__init__(self, provider, 'domain_zone') 

        self.domain_records = []
        split_domain = self.domain.split('.')
        split_domain_length = len(split_domain)

        # Parse out the TLD and root domain
        self.root_domain = split_domain[split_domain_length - 2]
        self.top_level_domain = split_domain[split_domain_length - 1]
        self.domain = f'{self.root_domain}.{self.top_level_domain}'

        # Parse out the subdomain
        full_subdomain = '.'.join(split_domain[:split_domain_length - 2])
        self.domain_records.append(DomainRecord(self.provider, full_subdomain, 'A'))
        

#################################################################################################################
# Servers & Server Types
#################################################################################################################

@dataclass
class Server(AnsibleControlledObject, TerraformObject):
    """Base class for representing servers"""

    def __init__(self, name, provider, server_type, domain_map, containers=[]):
        self.name = name
        self.server_type = server_type
        self.nebula_ip = None
        self.domain_map = domain_map
        self.containers = containers

        TerraformObject.__init__(self, provider, 'server')   
        AnsibleControlledObject.__init__(self)

        # Get the provider mappings
        parsed_yaml = utils.get_terraform_mappings()
        current_provider = parsed_yaml[self.provider]['server']

        # Set the values based on the data in the config
        self.terraform_resource_name = current_provider['resource_name']
        self.ansible_user = current_provider['remote_user']
        self.terraform_ip_reference = current_provider['ip_reference']

        # Populate the options with the Terry default values from the config
        terry_defaults = current_provider['terry_defaults']

        self.terraform_size_reference = terry_defaults['server_size'].get('global', None)
        if (not self.terraform_size_reference):
            utils.log_error(f'No global server size default set for "{self.provider}" in terraform_mappings.yml')

        self.terraform_disk_size_reference = terry_defaults['disk_size'].get('global', None)
        if (not self.terraform_disk_size_reference):
            utils.log_error(f'No global server disk size default set for "{self.provider}" in terraform_mappings.yml')

        # Try to get the server size specific to this server type
        type_specific_terraform_size_reference = terry_defaults['server_size'].get(self.server_type, None)
        if (not type_specific_terraform_size_reference):
            utils.log_debug(f'No "{self.server_type}" server size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            utils.log_debug(f'Found "{self.server_type}" specific server size of "{ type_specific_terraform_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_size_reference = type_specific_terraform_size_reference

        # Try to get the server disk size specific to this server type
        type_specific_terraform_disk_size_reference = terry_defaults['disk_size'].get(self.server_type, None)
        if (not type_specific_terraform_disk_size_reference):
            utils.log_debug(f'No "{self.server_type}" server disk size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            utils.log_debug(f'Found "{self.server_type}" specific disk size of "{ type_specific_terraform_disk_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_disk_size_reference = type_specific_terraform_disk_size_reference

        # Get the core playbook vars setup
        self.core_playbook_vars = {
            'ansible_user': self.ansible_user,
            'provider': self.provider,
            'uuid': self.uuid
        }
        

class Bare(Server):
    """Class for representing a bare server, without any custom config"""

    def __init__(self, name, provider, domain_map, containers):
        Server.__init__(self, name, provider, 'bare', domain_map, containers)


class Lighthouse(Server):
    """Class for representing a nebula Lighthouse server"""

    def __init__(self, name, provider, domain_map):
        Server.__init__(self, name, provider, 'lighthouse', domain_map)


class Mailserver(Server):
    """"""

    def __init__(self, name, provider, domain_map, containers, mailserver_type):
        self.containers = self.containers + [ mailserver_type ]

        Server.__init__(self, name, provider, 'mailserver', domain_map, containers)


class Redirector(Server):
    """Class for Redirectors, providing obfuscation layer between internet / victim and teamserver(s)."""

    def __init__(self, name, provider, domain_map, redirector_type, redirect_to):
        self.redirector_type = redirector_type
        self.redirect_to = redirect_to

        Server.__init__(self, name, provider, 'redirector', domain_map, [])


class Teamserver(Server):
    """Class for Teamservers, the piece of infrastructure running command and control software."""

    def __init__(self, name, provider, domain_map, containers):
        self.redirectors = []

        Server.__init__(self, name, provider, 'teamserver', domain_map, containers)


class Categorize(Server):
    """Class for Categorization servers, infrastructure that allows us to have c2 domains"""

    def __init__(self, name, provider, domain_map, domain_to_impersonate):
        self.domain_to_impersonate = domain_to_impersonate

        Server.__init__(self, name, provider, 'categorize', domain_map, [])
        
        # We can only have one Categorization Server in a build request
        if len(self.domain_map) != 1:
            utils.log_error(f'{self.__base_error_message} a domain map is required and with only one domain specified')
        if not self.domain_to_impersonate:
            utils.log_error(f'{self.__base_error_message} a domain to impersonate required')

            