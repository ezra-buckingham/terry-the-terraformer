import base64
import hashlib
from pathlib import Path
from uuid import uuid4

import yaml

from core.log_handler import LogHandler



#################################################################################################################
# Parent Terraform, Ansible, & Container Classes
#################################################################################################################

class TerraformObject:
    """Base class for all things Terraform"""


    def __init__(self, provider, infrastructure_type, uuid=None, error_on_missing_resource_file=True):
        self.provider = provider
        self.infrastructure_type = infrastructure_type
        self.uuid = 'id-' + (uuid if uuid else str(uuid4()))

        inferred_path = f'./templates/terraform/resources/{self.provider}/{self.infrastructure_type}.tf.j2'
        path = Path(inferred_path)
        if path.exists():
            self.terraform_resource_path = path
        elif not error_on_missing_resource_file:
            LogHandler.warn(f'Missing Terraform Resource file for "{self.provider}/{self.infrastructure_type}", but error override provided, continuning...')
        else: 
            raise FileNotFoundError(f'File not found at {inferred_path}')


    @classmethod
    def get_terraform_mappings(self, simple_list=False, type='all'):
        """Get the Terraform Mapping configuration file that will be used to build and remediate differences across the various providers
        
        Args: 
            `None`
        Returns:
            `mappings (dict)`: Dictionary containing the configuration
        """

        # Get the mappings file and read it in
        mappings = Path('./configurations/terraform_mappings.yml').read_text()
        mappings = yaml.safe_load(mappings)

        if type == 'server':
            mappings = dict(filter(lambda provider: 'server' in provider[1], mappings.items()))
        elif type == 'domain':
            mappings = dict(filter(lambda provider: provider[1]['is_registrar'], mappings.items()))

        # Check if we were asked for a simple list
        if simple_list:
            mappings = list(mappings.keys())
        
        return mappings


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
        if hasattr(self, 'domain') and self.domain is not None:
            self_dict['domain'] = self.domain

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
    """Base class for representing a Container that is deployed to a server"""


    def __init__(self, name, required_args={}, container_config={}):
        AnsibleControlledObject.__init__(self)
        
        self.name = name
        # Default Values
        self.required_args = required_args
        self.container_config = {}

        # Get the container mappings
        parsed_yaml = Container.get_container_mappings(False)
        services = parsed_yaml['services']
        self.container_config = services.get(self.name)

        if not self.container_config:
            LogHandler.critical(f'Container Error ({self.name}): No container configutation found in container mappings YAML')

        # Set the core ansible vars
        self.core_playbook_vars = {
            'name': self.name,
            **self.required_args
        }

        from core import check_for_required_value

        # Get the required args from config
        required_args_from_config = self.container_config.get('required_args', [])

        # If no required args, just return
        if not required_args_from_config: 
            return
        
        # Validate we have each arg
        LogHandler.debug(f'Validating required arguments for the "{self.name}" container')
        for req_arg in required_args_from_config:
            env_var = check_for_required_value(req_arg)
            self.required_args[env_var.name] = env_var.get()


    def to_dict(self):
        self_dict = {
            'name': self.name,
            'required_args': self.required_args
        }

        return self_dict

    
    @classmethod
    def from_dict(self, dict):
        return Container(dict['name'])


    @classmethod
    def get_container_mappings(self, simple_list=True):
        """Get the Container Mapping configuration file that will be used to build and deploy docker containers
        
        Args: 
            `simple_list (boolean)`: (DEFAULT=True) Return just the list of containers in the config 
        Returns:
            `mappings (list[str | dict])`: List containing the configuration as a dict or list
        """

        mappings = Path('./configurations/container_mappings.yml').read_text()
        # Parse the yaml and set the proper values
        parsed_yaml = yaml.safe_load(mappings)

        if simple_list:
            return parsed_yaml["services"].keys()

        return parsed_yaml 


#################################################################################################################
# Actual Terraform Objects
#################################################################################################################

class Provider(TerraformObject):
    """Base class for representing a Terraform provider"""


    def __init__(self, name, source='', version=''):
        self.name = name
        self.source = source
        self.version = version
        self.required_args = {}

        parsed_yaml = TerraformObject.get_terraform_mappings()
        self.provider_config = parsed_yaml.get(self.name, None)

        if not self.provider_config:
            LogHandler.critical(f'Provider Error ({self.name}): No provider configutation found in terraform mappings YAML')
        
        # Set the source and version
        self.source = self.provider_config['provider'].get('source', source)
        self.version = self.provider_config['provider'].get('version', version)
        required_args = self.provider_config['provider'].get('required_args', [])
        
        # Validate we have each arg
        LogHandler.debug(f'Validating required arguments for the "{self.name}" provider')
        for req_arg in required_args:
            from core import check_for_required_value
            env_var = check_for_required_value(req_arg)
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
        self.provider = provider
        self.name = name
        self.resource_type = 'ssh_key'
        self.public_key = public_key
        self.private_key = private_key

        TerraformObject.__init__(self, provider, self.resource_type)


    def get_fingerprint(self):
        stripped_key = self.public_key.strip()
        split_key = stripped_key.split()[1]
        base64_key = base64.b64decode(split_key.encode('ascii'))
        fp_plain = hashlib.md5(base64_key).hexdigest()
        return ':'.join(a+b for a,b in zip(fp_plain[::2], fp_plain[1::2]))


    def to_dict(self):
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


class Domain(TerraformObject):
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
        domain_record = Domain.__DomainRecord(subdomain, record_type, value)
        self.domain_records.append(domain_record)


    def to_dict(self):
        self_dict = {
            'domain': self.domain,
            'provider': self.provider,
            'domain_records': [ record.to_dict() for record in self.domain_records ]
        }

        return self_dict


    @classmethod
    def get_domain(self, fqdn):
        split_domain = fqdn.split('.')
        split_domain_length = len(split_domain)

        # Parse out the TLD and root domain
        root_domain = split_domain[split_domain_length - 2]
        top_level_domain = split_domain[split_domain_length - 1]
        domain = f'{root_domain}.{top_level_domain}'

        return domain

    @classmethod
    def get_subdomain(self, fqdn):
        split_domain = fqdn.split('.')
        split_domain = split_domain[0:len(split_domain) - 2]

        subdomain = ''.join(split_domain)

        return subdomain
        

    @classmethod
    def from_dict(self, dict):
        domain = Domain(dict['domain'], dict['provider'])

        for record in dict['domain_records']:
            domain.add_record(record['subdomain'], record['record_type'], record['value'])

        return domain
    

    class __DomainRecord:
        """Base class for representing a domain record entry (such as A record or NS record)"""

        def __init__(self, subdomain, record_type, value):
            self.subdomain = subdomain
            self.safe_subdomain = subdomain.replace('.', '-')
            self.record_type = record_type
            self.value = value

        
        def to_dict(self):
            self_dict = {
                'subdomain': self.subdomain,
                'record_type': self.record_type,
                'value': self.value
            }

            return self_dict
        

#################################################################################################################
# Servers & Server Types
#################################################################################################################


class Server(AnsibleControlledObject, TerraformObject):
    """Base class for representing servers"""

    def __init__(self, name, provider, server_type, domain, containers=[], domain_to_impersonate=None, redirector_type=None, proxy_to=None):
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
        self.proxy_to = proxy_to

        # Init the Parents
        TerraformObject.__init__(self, provider, self.resource_type)   
        AnsibleControlledObject.__init__(self)

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

        if self.proxy_to:
            self_dict['proxy_to'] = self.redirector_type

        return self_dict

    
    @classmethod
    def from_dict(self, dict):

        # First get the core items
        uuid = dict['uuid']
        name = dict['name']
        provider = dict['provider']
        domain = dict['domain'] # TODO
        type = dict['server_type']
        public_ip = dict['public_ip']

        # Get the other props
        nebula_ip = dict.get('nebula_ip')
        redirector_type = dict.get('redirector_type')
        redirect_to = dict.get('redirect_to')
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
            server = Categorize(name, provider, domain, redirect_to)
        elif type == 'bare':
            server = Bare(name, provider, domain, containers)
        elif type == 'lighthouse':
            server = Lighthouse(name, provider, domain)
        
        server.uuid = uuid
        server.public_ip = public_ip
        server.nebula_ip = nebula_ip

        return server


#################################################################################################################
# Server Types
#################################################################################################################


class Bare(Server):
    """Class for representing a bare server, without any custom config"""

    def __init__(self, name, provider, domain, containers):
        Server.__init__(self, name, provider, 'bare', domain, containers)


class Lighthouse(Server):
    """Class for representing a Nebula Lighthouse server"""

    def __init__(self, name, provider, domain):
        Server.__init__(self, name, provider, 'lighthouse', domain)


class Mailserver(Server):
    """Class for representing a mailserver"""

    def __init__(self, name, provider, domain, containers, mailserver_type):
        self.containers = containers + [ mailserver_type ]

        Server.__init__(self, name, provider, 'mailserver', domain, containers)


class Teamserver(Server):
    """Class for Teamservers, the piece of infrastructure running command and control software."""

    def __init__(self, name, provider, domain, containers):
        if domain and len(domain) > 0:
            LogHandler.warn('Domain provided for a Teamserver, this is not reccomended, but you do you.')

        Server.__init__(self, name, provider, 'teamserver', domain, containers)


class Categorize(Server):
    """Class for Categorization servers, infrastructure that allows us to have c2 domains"""

    def __init__(self, name, provider, domain, domain_to_impersonate):

        Server.__init__(self, name, provider, 'categorize', domain, containers=[], domain_to_impersonate=domain_to_impersonate)
        
        # We can only have one Categorization Server in a build request
        if len(self.domain) != 1:
            LogHandler.critical(f'Categorization Error: a domain map is required and with only one domain specified')
        if not self.domain_to_impersonate:
            LogHandler.critical(f'Categorization Error: a domain to impersonate required')


class Redirector(Server):
    """Class for Redirectors, providing obfuscation layer between internet / victim and teamserver(s)."""

    def __init__(self, name, provider, domain, redirector_type, proxy_to):
        self.redirector_type = redirector_type
        self.proxy_to = proxy_to

        Server.__init__(self, name, provider, 'redirector', domain, redirector_type=redirector_type, proxy_to=proxy_to)
