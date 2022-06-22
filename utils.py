import pickle
from datetime import datetime
from xml import dom
import click
from pathlib import Path
import subprocess
import random
import yaml
import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

from classes import *
from handlers import *



logger = logging.getLogger('main')
verbose_logging = False

def log_confirmation(message):
    """Prompts the user for confirmation

    Args:
        `message (str)`: Message / Question to ask user
    Returns:
        `result (bool)`: Result of the confirmation
    """

    result = click.confirm(f'[?] {message}')
    return result


def log_get_input(message):
    """Prompts the user for input

    Args:
        `message (str)`: Message / Prompt to ask user
    Returns:
        `result (str)`: Result from the user
    """

    result = click.prompt(f'[?] {message}')
    return result

def log_debug(message):
    """Logs an debug message to stdout and log file

    Args:
        `message (str)`: Message to log
    Returns:
        `None`
    """

    logger.debug(message)
    if verbose_logging:
        click.secho(f'[*] {message}', fg='blue')

def log_info(message):
    """Logs an info message to stdout and log file

    Args:
        `message (str)`: Message to log
    Returns:
        `None`
    """

    logger.info(message)
    click.secho(f'[+] {message}', fg='green')


def log_warn(message):
    """Log a warn message to stdout and log file

    Args:
        `message (str)`: Message to log
    Returns:
        `None`
    """

    logger.warn(message)
    click.secho(f'[!] {message}', fg='yellow')


def log_error(message, is_fatal=True):
    """Log an error message to stdout and log file
    
    Args:
        `message (str)`: Message to log
        `is_fatal (bool)`: Is the error fatal enough to exit (Default is `True`)
    Returns:
        `None`
    """

    logger.error(message)
    click.secho(f'[x] {message}', fg='red', bold=True)
    if is_fatal: 
        click.secho(f'[x] Error was fatal, exiting...', fg='red', bold=True)
        exit(code=1)


def get_formatted_time():
    """Get the time formatted in 24-hr local time

    Args:
        `None`
    Returns:
        `None`
    """

    # Need to pad the value so that we get a 2 digit hour, min, and sec
    def pad_value(value):
        if value < 10: return f'0{value}'
        else: return value

    datetime_obj = datetime.now()
    time_obj = datetime_obj.time()
    time = f'{pad_value(time_obj.hour)}:{pad_value(time_obj.minute)}:{pad_value(time_obj.second)}'
    return time

def make_system_call(command, working_directory=None):
    """Makes a system call using the subprocess module

    Args: 
        `command (str)`: Shell command
    Returns:
        `None`
    """
    global verbose_logging

    # If there is verbose logging, print out
    stdout = subprocess.DEVNULL
    if verbose_logging:
        stdout = subprocess.PIPE

    # If we have a working directory, change to it
    cwd = os.getcwd()
    if working_directory:
        os.chdir(working_directory)

    # Run the command, catch the error so that we can still change directory, and then raise that error back up
    try:
        output = subprocess.run(command.split(' '), check=True, stdout=stdout, stderr=stdout)
    except subprocess.CalledProcessError as e:
        os.chdir(cwd)
        raise e

    # Change back the OG directory
    os.chdir(cwd)

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
        log_debug(f'{value_name}: Value FOUND in CLI arguments')
        required_value.set(value_name, cli_value)
        return required_value
    else:
        log_debug(f'{value_name}: Value NOT FOUND in CLI arguments')

    # Second, check the env variable in case it was set manually
    if required_value.get(): 
        log_debug(f'{value_name}: Value FOUND in envionment variables')
        return required_value
    else: 
        log_debug(f'{value_name}: Value NOT FOUND in envionment variables')
                
    # Third, check the config file for the argument needed for the provider
    config_values = ctx_obj.get('config_values', {})
    config_value = find_dict_item(config_values, value_name)
    if config_value:
        log_debug(f'{value_name}: Value FOUND in config file')
        required_value.set(config_value)
        return required_value
    else:
        log_debug(f'{value_name}: Value NOT FOUND in config file')
                
    # Lastly, prompt the user to give us the creds if not found
    if not required_value.get():
        returned_value = log_get_input(f'Enter the {value_name}')
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

def get_implemented_providers(simple_list=False, is_registrar=False):
    """Gets the list of provider files in the 'templates/terraform/providers' directory

    Args:
        `simple_list (bool)`: If true, will only return list[str] else list[Path]
        `is_registrar (bool)`: If true, will only retutn list of registrars
    Returns:
        `implmented_providers (list[str] | list[Path])`: The list of implemented providers
    """

    # Get the terraform mappings
    terraform_mappings = get_terraform_mappings()
    implemented_providers = list(terraform_mappings.keys())

    return implemented_providers

def get_implemented_containers():
    """Get the list of containers as defined in the 'container_mappings.yml' file

    Args:
        `None`
    Returns:
        `containers (list[str])`: The list of containers as defined in the `container_mappings.yml` file
    """

    return get_container_mappings(True)

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

    with open('./configurations/container_mappings.yml', 'r') as mappings:
        # Parse the yaml and set the proper values
        parsed_yaml = yaml.safe_load(mappings)

        if simple_list:
            return parsed_yaml["services"].keys()

        return parsed_yaml 

def get_terraform_mappings():
    """Get the Terraform Mapping configuration file that will be used to build and remediate differences across the various providers
    
    Args: 
        `None`
    Returns:
        `mappings (dict)`: Dictionary containing the configuration
    """

    with open('./configurations/terraform_mappings.yml', 'r') as mappings:
        # Parse the yaml and set the proper values
        parsed_yaml = yaml.safe_load(mappings)
    
    return parsed_yaml

def prepare_providers(ctx_obj):
    """Prepares providers by ensuring required credential material is available based on providers selected for a given resource.
    The order of precedence in retreiving the credentials is command line, environment variable, configuration file.
    The program shouldn't continue until all credentials are found in one of sources listed above.

    Args:
        `ctx_obj (Click Context Object)`: the click context object
    Returns:
        `providers (list[Provider])`: The list of providers
    """

    providers = []

    for provider in ctx_obj['required_providers']:
        provider_name = list(provider.keys())[0]
        provider_arguments = provider[provider_name]['provider']

        # Loop over the default_arguments to see if we have what we need for the provider
        for argument_key in provider_arguments['default_arguments']:
            credential_env_var = check_for_required_value(ctx_obj, argument_key)
        
        providers.append(Provider(provider_name, provider_arguments['source'], provider_arguments['version']))

    return providers


def build_ansible_inventory(ctx_obj):
    # We want to build a file so that ansible could be independently run outside of terry
    # as opposed to passing a dict to ansible_runner

    server_types = get_implemented_server_types()
    inventory = {inventory: {'hosts': {}} for inventory in server_types}

    for resource in ctx_obj['all_resources']:
        inventory[resource.server_type]['hosts'][resource.public_ip] = resource.prepare_object_for_ansible()
        
    # Ansible will lock this file at times, so we need to try to write the changes, but may not be able to
    try:
        # Create the Global Vars to pass to ansbible
        global_vars = ctx_obj["ansible_configuration"]["global"]
        # global_vars += ctx_obj["ansible_configuration"]["global"]
        global_vars["op_directory"] = str(ctx_obj["op_directory"].resolve())
        global_vars["nebula"] = not ctx_obj['no_nebula']
        # If installing Nebula, give the addittional vars needed for configuring it on the hosts
        if global_vars["nebula"]:
            global_vars["lighthouse_public_ip"] = ctx_obj['lighthouse_public_ip']
            global_vars["lighthouse_nebula_ip"] = ctx_obj['lighthouse_nebula_ip']

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
        log_warn('There was a "PermissionError" while writing the Ansible inventory file')
    
    return inventory


def map_values(ctx_obj, json_data):
    """Map results from Terraform plan application back to class instances.
    Takes the click context object dictionary and JSONified terraform.show() results.
    Returns nothing (updates resource classes in place).
    """

    # Sort both lists by name to ensure same order
    terraform_resources = sorted(json_data, key=lambda x: x['name']) 

    # Get the terraform mappings so we know what keys to search for
    terraform_mappings = utils.get_terraform_mappings()

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

    return

def build_resource_pickle(ctx_obj):
    """Build a list of the categorization servers and the domain they are categorizing
    Takes the click context object
    Returns nothing
    """

    pickle_obj = pickle.dumps(ctx_obj['resources'])
    resources_pickle_file = ctx_obj['op_directory'].joinpath('resources.pickle')
    resources_pickle_file.write_bytes(pickle_obj)

def build_resource_domain_map(protocol, domain):
    """Helper class to build out the proper Domain objects needed for the specified protocol

    Args:
        `protocol (str)`: Protocol for the DNS records to allow for 
        `domain (Domain)`: Domain object in which to map records to
    """

    if protocol not in utils.get_implemented_redirectors():
        utils.log_error(f'Invalid redirector type provided: "{protocol}". Please use one of the implemented redirectors: {utils.get_implemented_redirectors()}')

    if protocol == 'dns':
        existing_record = domain.domain_records.pop()
        modified_records =  [
            DomainRecord(domain.provider, 'ns1', 'A'),
            DomainRecord(domain.provider, 'ns2', 'A'),
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
                    log_debug(f'Hosted domain zone for {hosted_zone} already built, only building single zone.')
                else:
                    jinja_vars = registrar.__dict__
                    plan += jinja_handler.get_and_render_template(registrar.terraform_resource_path, jinja_vars) + '\n\n'
                # Now loop over the records
                for record in registrar.domain_records:
                    dns_record = f'{hosted_zone}:{record.record_type}:{record.subdomain}'
                    if dns_record in dns_records:
                        utils.log_error('Duplicate DNS Records found!')
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

    pub_file = open(str(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key.pub')), "rb")
    pub_byte = pub_file.read(1)
    public_key = b''
    while pub_byte:
        public_key += pub_byte
        pub_byte = pub_file.read(1)

    priv_file = open(str(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key')), "rb")
    priv_byte = priv_file.read(1)
    private_key = b''
    while priv_byte:
        private_key += priv_byte
        priv_byte = priv_file.read(1)
    
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
