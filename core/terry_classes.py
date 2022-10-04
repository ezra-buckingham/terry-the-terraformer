from abc import ABC, abstractmethod
import base64
import hashlib
import yaml
from pathlib import Path
from uuid import uuid4


from core.log_handler import LogHandler


class ISerializable(ABC):
    """Base class for representing a serializable resource"""

    def __init__(self):
        pass

    @abstractmethod
    def to_dict(self):
        pass
    
    @abstractmethod
    @classmethod
    def from_dict(self, dict: dict) -> object:
        pass


#################################################################################################################
# Parent Terraform, Ansible, and Container Classes
#################################################################################################################

class TerraformObject:
    """Base class for all things Terraform"""


    def __init__(self, provider, infrastructure_type, uuid=None, error_on_missing_resource_file=True):
        self.provider = provider
        self.infrastructure_type = infrastructure_type
        self.uuid = 'id-' + (uuid if uuid else str(uuid4()))

        # Set the path of the resources
        inferred_path = f'./templates/terraform/resources/{self.provider}/{self.infrastructure_type}.tf.j2'
        inferred_override_path = f'./templates/terraform/resources/{self.provider}/{self.infrastructure_type}.override.tf.j2'
        
        path = Path(inferred_path)
        path_override = Path(inferred_override_path)
        
        if path_override.exists():
            LogHandler.warn(f'Found override template at "{ path_override.absolute() }", using that template instead of the original')
            self.terraform_resource_path = path_override
        elif path.exists():
            self.terraform_resource_path = path
        elif not error_on_missing_resource_file:
            LogHandler.warn(f'Missing Terraform Resource file for "{self.provider}/{self.infrastructure_type}", but error override provided, continuing...')
        else: 
            raise FileNotFoundError(f'File not found at {inferred_path}')


class Container(ISerializable):
    """Base class for representing a Container that is deployed to a server"""


    def __init__(self, name, required_args={}, container_config={}):
        from core import check_for_required_value, get_container_mappings
        
        self.name = name
        # Default values
        self.required_args = required_args
        self.container_config = {}

        # Get the container mappings
        parsed_yaml = get_container_mappings(False)
        services = parsed_yaml['services']
        self.container_config = services.get(self.name, None)

        if not self.container_config:
            LogHandler.critical(f'Container Error ({self.name}): No container configuration found in container mappings YAML')

        # Set the core Ansible vars
        self.core_playbook_vars = {
            'name': self.name,
            **self.required_args
        }

        # Get the required args from config
        required_args_from_config = self.container_config.get('required_args', [])

        # If required args, validate we have them
        if required_args_from_config: 
            # Validate we have each arg
            LogHandler.debug(f'Validating required arguments for the "{self.name}" container')
            for req_arg in required_args_from_config:
                env_var = check_for_required_value(req_arg)
                self.required_args[env_var.name] = env_var.get()
            

    def to_dict(self):
        """_summary_

        Returns:
            _type_: _description_
        """
        
        self_dict = {
            'name': self.name,
            'required_args': self.required_args
        }

        return self_dict

    
    @classmethod
    def from_dict(self, dict):
        return Container(dict['name'])
    


#################################################################################################################
# Actual Terraform Objects
#################################################################################################################

class Provider(ISerializable, TerraformObject):
    """Base class for representing a Terraform provider"""


    def __init__(self, name, source='', version=''):
        from core import check_for_required_value, get_terraform_mappings
        
        self.name = name
        self.source = source
        self.version = version
        self.required_args = {}

        parsed_yaml = get_terraform_mappings()
        self.provider_config = parsed_yaml.get(self.name, None)

        if not self.provider_config:
            LogHandler.critical(f'Provider Error ({self.name}): No provider configuration found in Terraform mappings YAML')
        
        # Set the source and version
        self.source = self.provider_config['provider'].get('source', source)
        self.version = self.provider_config['provider'].get('version', version)
        required_args = self.provider_config['provider'].get('required_args', [])
        
        # Validate we have each arg
        LogHandler.debug(f'Validating required arguments for the "{self.name}" provider')
        for req_arg in required_args:
            env_var = check_for_required_value(req_arg)
            self.required_args[env_var.name] = env_var.get()
    

    def to_dict(self):
        """_summary_

        Returns:
            _type_: _description_
        """
        
        self_dict = {
            'name': self.name,
            'source': self.source,
            'version': self.version
        }

        return self_dict


    @classmethod
    def from_dict(self, dict):
        """_summary_

        Args:
            dict (_type_): _description_

        Returns:
            _type_: _description_
        """
        
        return Provider(dict['name'], dict['source'], dict['version'])


class SSHKey(ISerializable, TerraformObject):
    """Base class for representing an SSH key"""


    def __init__(self, provider, name, public_key=None, private_key=None):
        self.provider = provider
        self.name = name
        self.resource_type = 'ssh_key'
        self.public_key = public_key
        self.private_key = private_key

        TerraformObject.__init__(self, provider, self.resource_type)


    def get_fingerprint(self):
        """_summary_

        Returns:
            _type_: _description_
        """
        
        stripped_key = self.public_key.strip()
        split_key = stripped_key.split()[1]
        base64_key = base64.b64decode(split_key.encode('ascii'))
        fp_plain = hashlib.md5(base64_key).hexdigest()
        return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))


    def to_dict(self):
        """_summary_

        Returns:
            _type_: _description_
        """
        
        self_dict = {
            'name': self.name,
            'provider': self.provider,
            'public_key': self.public_key.decode('utf-8'),
            'private_key': self.private_key.decode('utf-8') if self.private_key else None
        }

        return self_dict


    @classmethod
    def from_dict(self, dict):
        encoded_public_key = dict['public_key'].encode('utf-8') if dict.get('public_key', None) else None
        encoded_private_key = dict['private_key'].encode('utf-8') if dict.get('private_key', None) else None

        return SSHKey( dict['provider'], dict['name'], encoded_public_key, encoded_private_key)


#################################################################################################################
# Domain Objects
#################################################################################################################


class Domain(ISerializable, TerraformObject):
    """Base class for representing a domain resource for Terraform"""

    def __init__(self, domain, provider):
        self.domain = domain
        self.resource_type = 'domain'

        TerraformObject.__init__(self, provider, self.resource_type) 

        self.domain_records = []
        split_domain = self.domain.split('.')
        split_domain_length = len(split_domain)

        # Parse out the TLD and root domain
        self.root_domain = split_domain[split_domain_length - 2]
        self.top_level_domain = split_domain[split_domain_length - 1]
        self.domain = f'{self.root_domain}.{self.top_level_domain}'


    def add_record(self, subdomain, record_type, value):
        """_summary_

        Args:
            subdomain (_type_): _description_
            record_type (_type_): _description_
            value (_type_): _description_
        """
        
        domain_record = Domain.__DomainRecord(subdomain, record_type, value)
        self.domain_records.append(domain_record)


    def to_dict(self):
        """_summary_

        Returns:
            _type_: _description_
        """
        
        self_dict = {
            'domain': self.domain,
            'provider': self.provider,
            'uuid': self.uuid,
            'domain_records': [ record.to_dict() for record in self.domain_records ]
        }

        return self_dict


    @classmethod
    def get_domain(self, fqdn):
        """_summary_

        Args:
            fqdn (_type_): _description_

        Returns:
            _type_: _description_
        """
        
        split_domain = fqdn.split('.')
        split_domain_length = len(split_domain)

        # Parse out the TLD and root domain
        root_domain = split_domain[split_domain_length - 2]
        top_level_domain = split_domain[split_domain_length - 1]
        domain = f'{root_domain}.{top_level_domain}'

        return domain

    @classmethod
    def get_subdomain(self, fqdn):
        """_summary_

        Args:
            fqdn (_type_): _description_

        Returns:
            _type_: _description_
        """
        split_domain = fqdn.split('.')
        split_domain = split_domain[0:len(split_domain) - 2]

        subdomain = '.'.join(split_domain)

        return subdomain
        

    @classmethod
    def from_dict(self, dict):
        """_summary_

        Args:
            dict (_type_): _description_

        Returns:
            _type_: _description_
        """
        domain = Domain(dict['domain'], dict['provider'])
        domain.uuid = dict.get('uuid', domain.uuid)

        for record in dict['domain_records']:
            domain.add_record(record['subdomain'], record['record_type'], record['value'])

        return domain
    

    class __DomainRecord(ISerializable):
        """Base class for representing a domain record entry (such as A record or NS record)"""

        def __init__(self, subdomain, record_type, value):
            self.subdomain = subdomain
            self.safe_subdomain = subdomain.replace('.', '-')
            self.record_type = record_type
            self.value = value
            
            if len(self.safe_subdomain) == 0:
                self.safe_subdomain = 'ROOT-DOMAIN'

        
        def to_dict(self):
            """_summary_

            Returns:
                _type_: _description_
            """
            self_dict = {
                'subdomain': self.subdomain,
                'record_type': self.record_type,
                'value': self.value
            }

            return self_dict
        

#################################################################################################################
# Servers & Server Types
#################################################################################################################


class Server(ISerializable, TerraformObject):
    """Base class for representing servers"""

    def __init__(self, name: str, provider: str, server_type: str, domain: str, containers: list=[], domain_to_impersonate: str=None, redirector_type: str=None, redirect_to: str=None, dns_setup: bool=None):
        self.resource_type = 'server'
        self.name = name
        self.server_type = server_type
        self.nebula_ip = None
        self.public_ip = None
        self.domain = domain
        self.containers = containers

        # Specific Properties for Server Types
        self.domain_to_impersonate = domain_to_impersonate
        self.redirector_type = redirector_type
        self.redirect_to = redirect_to
        self.dns_setup = dns_setup

        # Init the Parents
        TerraformObject.__init__(self, provider, self.resource_type)   

        # Get the config values
        self.__get_server_config_from_terraform_mappings()
        self.__check_server_size()
        self.__check_server_disk_size()

        # Get the core playbook vars setup
        self.core_playbook_vars = {
            'ansible_user': self.ansible_user,
            'provider': self.provider
        }


    def __get_server_config_from_terraform_mappings(self):
        """"""

        # Get the provider mappings
        parsed_yaml = TerraformObject.get_terraform_mappings()
        self.server_config = parsed_yaml[self.provider]['server']

         # Set the values based on the data in the config
        self.terraform_resource_name = self.server_config['resource_name']
        self.ansible_user = self.server_config['remote_user']
        self.terraform_ip_reference = self.server_config['ip_reference']

        return self.server_config


    def __check_server_size(self):
        """"""

        terry_defaults = self.server_config['terry_defaults']

        self.terraform_size_reference = terry_defaults['server_size'].get('global', None)
        if (not self.terraform_size_reference):
            LogHandler.error(f'No global server size default set for "{self.provider}" in terraform_mappings.yml')

        # Try to get the server size specific to this server type
        type_specific_terraform_size_reference = terry_defaults['server_size'].get(self.server_type, None)
        if (not type_specific_terraform_size_reference):
            LogHandler.debug(f'No "{self.server_type}" server size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            LogHandler.debug(f'Found "{self.server_type}" specific server size of "{ type_specific_terraform_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_size_reference = type_specific_terraform_size_reference
    

    def __check_server_disk_size(self):
        """"""

        terry_defaults = self.server_config['terry_defaults']

        self.terraform_disk_size_reference = terry_defaults['disk_size'].get('global', None)
        if (not self.terraform_disk_size_reference):
            LogHandler.error(f'No global server disk size default set for "{self.provider}" in terraform_mappings.yml')

        # Try to get the server disk size specific to this server type
        type_specific_terraform_disk_size_reference = terry_defaults['disk_size'].get(self.server_type, None)
        if (not type_specific_terraform_disk_size_reference):
            LogHandler.debug(f'No "{self.server_type}" server disk size default set for "{self.provider}" in terraform_mappings.yml. Using global default value.')
        else:
            LogHandler.debug(f'Found "{self.server_type}" specific disk size of "{ type_specific_terraform_disk_size_reference }" for "{self.provider}" in terraform_mappings.yml.')
            self.terraform_disk_size_reference = type_specific_terraform_disk_size_reference
             

    def to_dict(self):
        # Base Dict for all Servers
        self_dict = {
            'uuid': self.uuid,
            'resource_type': self.resource_type,
            'name': self.name,
            'provider': self.provider,
            'server_type': self.server_type,
            'nebula_ip': self.nebula_ip,
            'public_ip': self.public_ip,
            'domain': self.domain
        }

        # Check some of the other potential attributes
        if self.containers:
            self_dict['containers'] = [ container.to_dict() for container in self.containers ]
        
        if self.domain_to_impersonate:
            self_dict['domain_to_impersonate'] = self.domain_to_impersonate

        if self.redirector_type:
            self_dict['redirector_type'] = self.redirector_type

        if self.redirect_to:
            self_dict['redirect_to'] = self.redirect_to
            
        if self.dns_setup:
            self_dict['dns_setup'] = self.dns_setup

        return self_dict

    
    @classmethod
    def from_dict(self, dict):

        # First get the core items
        uuid = dict['uuid']
        name = dict['name']
        provider = dict['provider']
        domain = dict['domain']
        type = dict['server_type']
        public_ip = dict['public_ip']

        # Get the other props
        nebula_ip = dict.get('nebula_ip')
        redirector_type = dict.get('redirector_type')
        redirect_to = dict.get('redirect_to')
        dns_setup = dict.get('dns_setup')
        domain_to_impersonate = dict.get('domain_to_impersonate')
        dict_containers = dict.get('containers', [])

        # Map the containers back
        containers = []
        for container in dict_containers:
            containers.append(Container.from_dict(container))

        # Build the server back
        if type == 'teamserver':
            server = Teamserver(name, provider, domain, containers)
        elif type == 'redirector':
            server = Redirector(name, provider, domain, redirector_type, redirect_to)
        elif type == 'categorize':
            server = Categorize(name, provider, domain, domain_to_impersonate)
        elif type == 'bare':
            server = Bare(name, provider, domain, containers)
        elif type == 'lighthouse':
            server = Lighthouse(name, provider, domain)
        elif type == 'mailserver':
            server = Mailserver(name, provider, domain, containers, '', dns_setup)
        
        server.uuid = uuid
        server.public_ip = public_ip
        server.nebula_ip = nebula_ip

        return server


#################################################################################################################
# Server Types
#
# To add a new server type, create a new class and add properties to the parent Server as needed
# this is important since logic should not be done in the actual classes
#################################################################################################################


class Bare(Server):
    """Class for representing a bare server, without any custom config"""

    def __init__(self, name, provider, domain, containers):
        Server.__init__(
            self, 
            name=name, 
            provider=provider, 
            server_type='bare', 
            domain=domain, 
            containers=containers
        )


class Lighthouse(Server):
    """Class for representing a Nebula Lighthouse server"""

    def __init__(self, name, provider, domain):
        Server.__init__(
            self, 
            name=name, 
            provider=provider, 
            server_type='lighthouse', 
            domain=domain
        )


class Mailserver(Server):
    """Class for representing a mailserver"""

    def __init__(self, name, provider, domain, containers=[], mailserver_type='', dns_setup=False):
        Server.__init__(
            self, 
            name=name, 
            provider=provider, 
            server_type='mailserver', 
            domain=domain, 
            containers= containers + [ mailserver_type ], 
            domain_to_impersonate=None, 
            redirector_type=None, 
            redirect_to=None, 
            dns_setup=False
        )


class Teamserver(Server):
    """Class for Teamservers, the piece of infrastructure running command and control software."""

    def __init__(self, name, provider, domain, containers):
        if domain and len(domain) > 0:
            LogHandler.warn('Domain provided for a Teamserver, this is not recommended, but you do you.')

        Server.__init__(
            self, 
            name=name, 
            provider=provider, 
            server_type='teamserver', 
            domain=domain, 
            containers=containers
        )


class Categorize(Server):
    """Class for Categorization servers, infrastructure that allows us to have C2 domains"""

    def __init__(self, name, provider, domain, domain_to_impersonate):
        if not domain:
            LogHandler.critical(f'Categorization Error: a domain is required')
        if not domain_to_impersonate:
            LogHandler.critical(f'Categorization Error: a domain to impersonate required')

        Server.__init__(
            self, 
            name=name, 
            provider=provider, 
            server_type='categorize', 
            domain=domain, 
            containers=[], 
            domain_to_impersonate=domain_to_impersonate
        )
        

class Redirector(Server):
    """Class for Redirectors, providing obfuscation layer between internet / victim and teamserver(s)."""

    def __init__(self, name, provider, domain, redirector_type, redirect_to, domain_to_impersonate=None):
        Server.__init__(
            self, 
            name=name, 
            provider=provider,
            server_type='redirector', 
            domain=domain, 
            redirector_type=redirector_type, 
            redirect_to=redirect_to, 
            domain_to_impersonate=domain_to_impersonate
        )
