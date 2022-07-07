import pickle
from datetime import datetime
from pathlib import Path
import random
import yaml
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend


from core import *


def get_formatted_time():
    """Get the time formatted in 24-hr local time

    Args:
        `None`
    Returns:
        `time (str)`: The local time in "%H:%M:%S" format
    """

    now = datetime.now()
    time = now.strftime("%H:%M:%S")
    return time


def find_dict_item(obj, key):
    """Recursively search a dictionary for a specific key name

    Args:
        `obj (dict)`: Dictionary to search
        `key (str)`: String to search for
    Returns:
        `value (obj)`: Value of the found key or None if not found
    """
    
    value = obj.get(key.lower(), obj.get(key.upper(), None))
    if value: return value
    for dict_key, dict_value in obj.items():
        if isinstance(dict_value, dict):
            item = find_dict_item(dict_value, key) 
            if item is not None:
                return item


def check_for_required_value(ctx_obj, value_name):
    """Will check for a specific value being an environment variable, then check the cli, then check the config file.
    If it finds nothing, it will prompt the user for the value.

    Args:
        `ctx (Click Context Object)`: the click context object
        `value_name (str)`: Name of the value
    Returns:
        `required_value (EnvironmentVariableHandler)`: The required value as an Environment Variable
    """

    required_value = EnvironmentVariableHandler(value_name)
            
    # First, check the command line for the argument needed for the provider
    cli_value = ctx_obj.get(value_name.lower(), None)
    if cli_value:
        LogHandler.debug(f'{value_name}: Value FOUND in CLI arguments')
        required_value.set(value_name, cli_value)
        return required_value
    else:
        LogHandler.debug(f'{value_name}: Value NOT FOUND in CLI arguments')

    # Second, check the env variable in case it was set manually
    if required_value.get(): 
        LogHandler.debug(f'{value_name}: Value FOUND in envionment variables')
        return required_value
    else: 
        LogHandler.debug(f'{value_name}: Value NOT FOUND in envionment variables')
                
    # Third, check the config file for the argument needed for the provider
    config_values = ctx_obj.get('config_values', {})
    config_value = find_dict_item(config_values, value_name)
    if config_value:
        LogHandler.debug(f'{value_name}: Value FOUND in config file')
        required_value.set(config_value)
        return required_value
    else:
        LogHandler.debug(f'{value_name}: Value NOT FOUND in config file')
                
    # Lastly, prompt the user to give us the creds if not found
    if not required_value.get():
        returned_value = LogHandler.get_input(f'Enter the {value_name}')
        required_value.set(returned_value)
        return returned_value


def remove_directory_recursively(path):
    """Removes the directory and all children elements of that directory

    Args:
        `path (str | Path)`: Path to directory
    Returns:
        `None`
    """

    path = Path(path)
    for child in path.glob('*'):
        if child.is_file():
            child.unlink()
        else:
            remove_directory_recursively(child)
    path.rmdir()


def get_files_from_directory(dir):
    """Gets all files in a specified directory

    Args:
        `dir (str | Path)`: Path to directory
    Returns:
        `None`
    """

    directory_path = Path(dir)
    directory_path = directory_path.glob('**/*')
    files = [x for x in directory_path if x.is_file()]

    return files


def get_implemented_server_types():
    """Gets the types of server types that can be deployed

    Args:
        `None`
    Returns:
        `server_types (List)`: List of server types
    """

    server_types = ['bare', 'categorize', 'teamserver', 'lighthouse', 'redirector']
    return server_types


def get_implemented_redirectors():
    """Gets the list of redirectors as we have them implemented (these are implemented in Ansible)

    Args:
        `None`
    Returns:
        `redirector_types (list[str])`: The list of implemented redirector types
    """

    redirector_types = ['https', 'dns', 'custom']
    return redirector_types


def get_container_mappings(simple_list=True):
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


def get_terraform_mappings(simple_list=False, type='all'):
    """Get the Terraform Mapping configuration file that will be used to build and remediate differences across the various providers
    
    Args: 
        `None`
    Returns:
        `mappings (dict)`: Dictionary containing the configuration
    """

    if type == 'all':
        """"""
    elif type == 'registrar':
        """"""
    elif type == '':
        """"""

    mappings = Path('./configurations/terraform_mappings.yml').read_text()
    # Parse the yaml and set the proper values
    parsed_yaml = yaml.safe_load(mappings)
    
    return parsed_yaml


def build_ansible_inventory(ctx_obj):
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
            with yaml_file.open() as open_yaml_file:
                file_contents = open_yaml_file.read()
                yaml_contents = yaml.safe_load(file_contents)
                global_vars = {
                    **yaml_contents,
                    **global_vars
                }
            
        # Build the dictionary and write it to disk
        ansible_inventory = {'all': { 'vars': global_vars, 'children': inventory }}
        yaml_text = yaml.safe_dump(ansible_inventory)
        ctx_obj['op_directory'].joinpath('ansible/inventory/hosts').write_text(yaml_text)
    except PermissionError as e:
        LogHandler.warn('There was a "PermissionError" while writing the Ansible inventory file')
    
    return inventory


def map_values(ctx_obj, json_data):
    """Map results from Terraform plan application back to class instances.
    Takes the click context object dictionary and JSONified terraform.show() results.
    Returns nothing (updates resource classes in place).
    """

    LogHandler.debug('Mapping Terraform state')

    # Sort both lists by name to ensure same order
    terraform_resources = sorted(json_data, key=lambda x: x['name']) 

    # Get the terraform mappings so we know what keys to search for
    terraform_mappings = get_terraform_mappings()

    for resource in terraform_resources:
        resource_values = resource['values']
        matching_resource = [r for r in ctx_obj['all_resources'] if r.name == resource['name']]
        
        # Get the matching resource, if returned, else continue to next resource
        if (len(matching_resource) > 0):
            matching_resource = matching_resource[0]
        else:
            continue

        # Need to extract the provider from the name returned in the JSON
        current_provider_fqdn = resource['provider_name']
        current_provider_fqdn = current_provider_fqdn.split('/')
        current_provider = current_provider_fqdn[len(current_provider_fqdn) - 1]

        # Get the ip_reference for the specific provider
        ip_reference = terraform_mappings[current_provider]['server']['ip_reference']
        matching_resource.public_ip = resource_values[ip_reference]


def build_resource_domain_map(protocol, domain):
    """Helper class to build out the proper Domain objects needed for the specified protocol

    Args:
        `protocol (str)`: Protocol for the DNS records to allow for 
        `domain (Domain)`: Domain object in which to map records to
    """

    if protocol not in get_implemented_redirectors():
        LogHandler.critical(f'Invalid redirector type provided: "{protocol}". Please use one of the implemented redirectors: {get_implemented_redirectors()}')

    if protocol == 'dns':
        existing_record = domain.domain_records.pop()
        modified_records =  [
            DomainRecord(domain.provider, 'ns1', 'A'),
            DomainRecord(domain.provider, existing_record.subdomain, 'NS')
        ]
        domain.domain_records += modified_records

    return domain

def build_plan(ctx_obj):
    """Build the Terraform plan.
    Takes the Click context object dictionary.
    Returns a complete Terraform plan as a string.
    Uses the utils.render_template function to render the Terraform plan based on
    provider and resource templates.
    """

    plan = ''

    jinja_handler = JinjaHandler(".")

    # Start with adding the providers
    plan += jinja_handler.get_and_render_template('./templates/terraform/provider.tf.j2', {'required_providers' : ctx_obj['required_providers']})+ '\n\n'
    
    # Track the resources that we don't want to duplicate
    hosted_zones = set()
    dns_records = set()
    ssh_keys = set()

    # Now prepare it all
    for resource in ctx_obj["all_resources"]:

        # Check if we have an SSH Key provisioned for that provider first
        if resource.provider not in ssh_keys:
            ssh_key_name = f'{ctx_obj["operation"]}_{resource.provider}_key'
            ssh_key = SSHKey(resource.provider, ssh_key_name, ctx_obj['ssh_pub_key'])
            plan += jinja_handler.get_and_render_template(ssh_key.terraform_resource_path, { **ssh_key.__dict__ } ) + '\n\n'
            ssh_keys.add(resource.provider)

        # Now prepare the resource
        jinja_vars = { **vars(resource), **ctx_obj }
        plan += jinja_handler.get_and_render_template(resource.terraform_resource_path, jinja_vars) + '\n\n'
        
        # If the resource has domain records, build those as well       
        if hasattr(resource, 'domain_map') and resource.domain_map:
            # Loop over the domains
            for registrar in resource.domain_map:
                # Check if the hosted zone exists already in the set
                hosted_zone = f'{registrar.domain}:{registrar.provider}'
                # If hosted zone already exists
                if hosted_zone in hosted_zones:
                    LogHandler.debug(f'Hosted domain zone for {hosted_zone} already built, only building single zone.')
                else:
                    jinja_vars = registrar.__dict__
                    plan += jinja_handler.get_and_render_template(registrar.terraform_resource_path, jinja_vars) + '\n\n'
                # Now loop over the records
                for record in registrar.domain_records:
                    dns_record = f'{hosted_zone}:{record.record_type}:{record.subdomain}'
                    if dns_record in dns_records:
                        LogHandler.critical('Duplicate DNS Records found!')
                    jinja_vars = { 'resource': resource.__dict__, **registrar.__dict__, 'record': record.__dict__ }
                    plan += jinja_handler.get_and_render_template(record.terraform_resource_path, jinja_vars) + '\n\n'
                    dns_records.add(dns_record)
                # Add the hosted zone
                hosted_zones.add(hosted_zone)                    

    return plan


def get_operation_ssh_key_pair(ctx_obj):
    """Gets the SSH key that will be used for ansible (required because the generated key won't work for some reason, but reading it will???)
    Returns the byte string of the SSH key
    """

    public_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key.pub')).read_bytes()
    private_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key')).read_bytes()
    
    return public_key, private_key

def generate_ssh_key():
    """Generate an SSH key if we want to dynamically generate keys for our deployments.
    Takes nothing
    Returns private key, public key
    """
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=2048
    )
    private_key = key.private_bytes(
        crypto_serialization.Encoding.PEM,
        crypto_serialization.PrivateFormat.PKCS8,
        crypto_serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )
    return public_key, private_key

def get_common_subdomain(exclude=None):
    """Generate a random subdomain to use for infrastructure.

    Args:
        `exclude (str | list[str])`: Subdomains to exclude (if already in use for same domain)
    Returns:
        `stem_values (list[str])`: The list of implemented c2's
    """

    options = [
        'file', 'vpn', 'rdp', 'sync', 'mail', 'server', 'test', 
        'portal', 'host', 'support', 'mail2', 'dev', 'owa', 'cloud',
        'admin', 'store', 'api', 'exchange', 'news', 'fileserver',
        'share', 'crm', 'erp', 'book', 'register', 'gateway', 'gw',
        'blog'
    ]
    # Loop over exclusion domains and remove them
    for subdomain in [ *exclude ]:
        options.remove(subdomain)

    return random.choice(options)
