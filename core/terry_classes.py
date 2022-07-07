import base64
from dataclasses import dataclass
from hashlib import sha256
import hashlib
from pathlib import Path

import yaml

from core.log_handler import LogHandler


BUILD_UUID = ''


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

    def __post_init__(self):
        inferred_path = f'./templates/terraform/resources/{self.provider}/{self.infrastructure_type}.tf.j2'
        path = Path(inferred_path)
        if path.exists():
            self.terraform_resource_path = path
        else:
            raise FileNotFoundError(f'File not found at {inferred_path}')


class AnsibleControlledObject:
    """Base class for representing an Ansible Controlled Resource"""

    def __init__(self):
        pass

    def prepare_object_for_ansible(self):
        """Take the Child AnsibleControlled Object and extract the data needed to write an inventory that the playbooks can reference

        Args:
            `None`
        Returns:
            `self_dict (dict)`: The dictonary needed for the ansible playbooks for the child object
        """
        self_dict = {
            'uuid': self.uuid,
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


class Container(AnsibleControlledObject):

    def __init__(self, name):
        AnsibleControlledObject.__init__(self)
        
        self.name = name
        # Default Values
        self.required_args = {}
        self.container_config = {}

        # Get the container mappings
        from utils import get_container_mappings
        parsed_yaml = get_container_mappings(False)
        services = parsed_yaml['services']
        self.container_config = services.get(self.name)

        if not self.container_config:
            LogHandler.critical(f'Container Error ({self.name}): No container configutation found in container mappings YAML')

        # Set the core ansible vars
        self.core_playbook_vars = {
            'name': self.name,
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
            from utils import check_for_required_value
            env_var = check_for_required_value(ctx, req_arg)
            self.required_args[env_var.name] = env_var.get()

    def to_dict(self):
        self_dict = {
            'name': self.name,
            **self.required_args
        }

        return self_dict
    
    @classmethod
    def from_dict(self, dict):
        return Container(dict['name'])


#################################################################################################################
# Actual Terraform Objects
#################################################################################################################

class Provider(TerraformObject):
    """Base class for representing a Terraform provider"""

    def __init__(self, name, source='', version=''):
        self.name = name
        self.source = source
        self.version = version
        # Default Values
        required_args = {}
        provider_config = {}

    def __post_init__(self):
        # Get the provider mappings
        from utils import get_terraform_mappings
        parsed_yaml = get_terraform_mappings()
        self.provider_config = parsed_yaml.get(self.name)

        if not self.provider_config:
            LogHandler.critical(f'Provider Error ({self.name}): No provider configutation found in terraform mappings YAML')
        
    def validate(self, ctx):
        # Get the required args from config
        required_args = self.provider_config.get('required_args', [])

        # If no required args, just return
        if not required_args: 
            return
        
        # Validate we have each arg
        for req_arg in required_args:
            from utils import check_for_required_value
            env_var = check_for_required_value(ctx, req_arg)
            self.required_args[env_var.name] = env_var.get()
    
    def to_dict(self):
        self_dict = {
            'name': self.name,
            'source': self.source,
            'version': self.version
        }

        return self_dict

    @classmethod
    def from_dict(self, dict):
        return Provider(dict['name'], dict['source'], dict['version'])


class SSHKey(TerraformObject):
    """Base class for representing an ssh key"""

    def __init__(self, provider, name, public_key=None, private_key=None):
        self.name = name
        self.public_key = public_key
        self.private_key = private_key

        TerraformObject.__init__(self, provider, 'ssh_key')

    def get_fingerprint(self):
        stripped_key = self.public_key.strip()
        split_key = stripped_key.split()[1]
        base64_key = base64.b64decode(split_key.encode('ascii'))
        fp_plain = hashlib.md5(base64_key).hexdigest()
        return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))

    def to_dict(self):
        self_dict = {
            'name': self.name,
            'public_key': self.public_key,
            'private_key': self.private_key
        }

        return self_dict

    @classmethod
    def from_dict(self, dict):
        return SSHKey(dict['name'], dict['public_key'], dict['private_key'])


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

    def to_dict(self):
        self_dict = {
            'domain': self.domain,
            'provider': self.provider
        }

        return self_dict

    @classmethod
    def from_dict(self, dict):
        return Domain(dict['domain'], dict['provider'])
    


class DomainRecord(TerraformObject):
    """Base class for representing a domain record entry (such as A record or NS record)"""

    def __init__(self, provider, subdomain, record_type):
        self.subdomain = subdomain
        self.safe_subdomain = subdomain.replace('.', '-')
        self.record_type = record_type

        TerraformObject.__init__(self, provider, 'domain')

        

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
        from utils import get_terraform_mappings
        parsed_yaml = get_terraform_mappings()
        current_provider = parsed_yaml[self.provider]['server']

        # Set the values based on the data in the config
        self.terraform_resource_name = current_provider['resource_name']
        self.ansible_user = current_provider['remote_user']
        self.terraform_ip_reference = current_provider['ip_reference']

        # Populate the options with the Terry default values from the config
        terry_defaults = current_provider['terry_defaults']

        self.terraform_size_reference = terry_defaults['server_size'].get('global', None)
        if (not self.terraform_size_reference):
            LogHandler.error(f'No global server size default set for "{self.provider}" in terraform_mappings.yml')

        self.terraform_disk_size_reference = terry_defaults['disk_size'].get('global', None)
        if (not self.terraform_disk_size_reference):
            LogHandler.error(f'No global server disk size default set for "{self.provider}" in terraform_mappings.yml')

        # Try to get the server size specific to this server type
        type_specific_terraform_size_reference = terry_defaults['server_size'].get(self.server_type, None)
        if (not type_specific_terraform_size_reference):
            LogHandler.debug(f'No "{self.server_type}" server size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            LogHandler.debug(f'Found "{self.server_type}" specific server size of "{ type_specific_terraform_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_size_reference = type_specific_terraform_size_reference

        # Try to get the server disk size specific to this server type
        type_specific_terraform_disk_size_reference = terry_defaults['disk_size'].get(self.server_type, None)
        if (not type_specific_terraform_disk_size_reference):
            LogHandler.debug(f'No "{self.server_type}" server disk size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            LogHandler.debug(f'Found "{self.server_type}" specific disk size of "{ type_specific_terraform_disk_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_disk_size_reference = type_specific_terraform_disk_size_reference

        # Get the core playbook vars setup
        self.core_playbook_vars = {
            'ansible_user': self.ansible_user,
            'provider': self.provider
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
            LogHandler.critical(f'{self.__base_error_message} a domain map is required and with only one domain specified')
        if not self.domain_to_impersonate:
            LogHandler.critical(f'{self.__base_error_message} a domain to impersonate required')

    