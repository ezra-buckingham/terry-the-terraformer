from pydoc import cli
import random
import click
import yaml

from pathlib import Path
from datetime import datetime
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

# Bring in files so they are exported with the module
from core.terry_classes import *
from core.ansible_handler import AnsibleHandler
from core.log_handler import LogHandler
from core.shell_handler import ShellHandler
from core.terraform_handler import TerraformHandler
from core.nebula_handler import NebulaHandler
from core.remote_configuration_handler import RemoteConfigurationHandler
from core.jinja_handler import JinjaHandler
from core.slack_handler import SlackHandler
from core.environment_variable_handler import EnvironmentVariableHandler


#################################################################################################################
# Helper & Core Functions of Terry
#################################################################################################################

@click.pass_context
def prepare_handlers(ctx):
    """Prepare all the handler objects for the build (all handlers will be given to the Click Context Object at `ctx.obj['<software>_handler']`)

    Args:
        `None`
    Returns:
        `None`
    """

    # Create a Terraform handler
    terraform_path = ctx.obj['config_contents']['global']['terraform_path']
    ctx.obj['terraform_handler'] = TerraformHandler(terraform_path, ctx.obj['op_directory'])

    # Create the Slack Handler
    slack_webhook_url =  ctx.obj['config_contents']['slack']['webhook_url']
    ctx.obj['slack_handler'] = SlackHandler(slack_webhook_url, ctx.obj['quiet'])
    
    # If not destroy, create all the other required handlers
    if not ctx.command.name == 'destroy':
        # Create the Ansible Handler
        ansible_path = ctx.obj['config_contents']['global']['ansible_path']
        ctx.obj['ansible_handler'] = AnsibleHandler(ansible_path, Path(ctx.obj['op_directory']).joinpath('ansible'))

        # Create the Nebula Handler (if applicable)
        if not ctx.obj['no_nebula']:
            nebula_path = ctx.obj['config_contents']['global']['nebula_path']
            ctx.obj['nebula_handler'] = NebulaHandler(nebula_path, ctx.obj['config_contents']['global']['nebula_subnet'], Path(ctx.obj['op_directory']).joinpath('nebula'))   


@click.pass_obj
def validate_credentials(ctx_obj, check_containers=True):
    """Validate that we have credentials needed for the specified actions (all required providers will be given to the Click Context Object at `ctx.obj['required_providers']`)

    Args:
        `check_containers (bool)`: Should we check that we have credentials to deploy containers (not needed when destorying infra)
    Returns:
        `None`
    """

    required_providers = set()
    container_registry_credentials_checked = False

    for resource in ctx_obj['all_resources']:
        required_providers.add(resource.provider)

        if hasattr(resource, 'containers') and len(resource.containers) and check_containers:
            for container in resource.containers:
                # Check if we have already looked for container registry creds
                if not container_registry_credentials_checked:
                    LogHandler.debug('Containers found in build, checking for container registry credentials now')
                    # First Validate we were given registry creds
                    check_for_required_value(ctx_obj, 'container_registry')
                    check_for_required_value(ctx_obj, 'container_registry_username', hide_input=True)
                    check_for_required_value(ctx_obj, 'container_registry_password', hide_input=True)
                    container_registry_credentials_checked = True
                # Now validate the actual container runtime args needed
                container.validate(ctx_obj)

        if resource.domain_map:
            for domain in resource.domain_map:
                registrars = TerraformObject.get_terraform_mappings(simple_list=True, type='registrar')
                if not domain.provider in registrars:
                    LogHandler.critical(f'Registrar of {domain.provider} not implemented. Please implement it and rerun or change the registrar.')
                else: 
                    required_providers.add(domain.provider)

    ctx_obj['required_providers'] = [ Provider(provider) for provider in required_providers ]
    


@click.pass_obj
def create_resource_name(ctx_obj, type):
    """Helper function to create a resource name"""
    return type + (str([x.server_type for x in ctx_obj['all_resources']].count(type) + 1))


@click.pass_obj
def is_verbose_enabled(ctx_obj):
    return ctx_obj['verbose']


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


def check_for_required_value(ctx_obj, value_name, hide_input=False):
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
    config_values = ctx_obj.get('config_contents', {})
    config_value = find_dict_item(config_values, value_name)
    if config_value:
        LogHandler.debug(f'{value_name}: Value FOUND in config file')
        required_value.set(config_value)
        return required_value
    else:
        LogHandler.debug(f'{value_name}: Value NOT FOUND in config file')
                
    # Lastly, prompt the user to give us the creds if not found
    if not required_value.get():
        returned_value = LogHandler.get_input(f'Enter the {value_name}', hide_input=hide_input)
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


def build_resource_domain_map(protocol, domain):
    """Helper class to build out the proper Domain objects needed for the specified protocol

    Args:
        `protocol (str)`: Protocol for the DNS records to allow for 
        `domain (Domain)`: Domain object in which to map records to
    """

    if protocol not in Redirector.get_implemented_redirectors():
        LogHandler.critical(f'Invalid redirector type provided: "{protocol}". Please use one of the implemented redirectors: {Redirector.get_implemented_redirectors()}')

    if protocol == 'dns':
        existing_record = domain.domain_records.pop()
        modified_records =  [
            DomainRecord(domain.provider, 'ns1', 'A'),
            DomainRecord(domain.provider, existing_record.subdomain, 'NS')
        ]
        domain.domain_records += modified_records

    return domain


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


