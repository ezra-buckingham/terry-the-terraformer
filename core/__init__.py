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

@click.pass_obj
def prepare_nebula_handler(ctx_obj):
    """Prepare the nebula handler object for the build (all handlers will be given to the Click Context Object at `ctx.obj['<software>_handler']
    This is split out as we may want not want to search for the Nebula Binary too early in a build as it might not be needed

    Args:
        `None`
    Returns:
        `None`
    """

    # Get all the lighthouses from the resources
    lighthouses = [ x for x in ctx_obj["all_resources"] if isinstance(x, Lighthouse) ]
    
    # Check with user if we want to build nebula when there are many servers in the build
    if not ctx_obj['no_nebula'] and len(ctx_obj['server_resources']) > 1:
        # Check to make sure we only have one lighthouse in the build
        if len(lighthouses) > 1:
            LogHandler.critical('Multiple Lighthouses found in build, Terry can only handle building one per deployment')
    
        if len(lighthouses) == 0:
            LogHandler.warn('Nebula configured for this build, but no Lighthouses found. Either use the "-N" / "--no_nebula" flag or I can build one for you now.')
            response = LogHandler.confirmation('Would you like me to add a Lighthouse to the current build?')
            if response:
                lighthouse_name = generate_random_name()

                # Now get the provider from the user
                provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')
                while provider not in TerraformObject.get_terraform_mappings(simple_list=True):
                    LogHandler.error(f'Invalid provider provided: {provider}. Please enter one of the following providers: {TerraformObject.get_terraform_mappings(simple_list=True)}', is_fatal=False)
                    provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')

                lighthouse = Lighthouse(lighthouse_name, provider, None)
                ctx_obj["server_resources"].insert(0, lighthouse)
                ctx_obj["all_resources"].insert(0, lighthouse)
            else:
                LogHandler.warn('Opting out of Nebula for this build')
                ctx_obj['no_nebula'] = not ctx_obj['no_nebula']

        # Need to check we have enough IPs in the IP space
        # TODO
    else:
        LogHandler.warn('Nebula configured for this build, but only one server is in the manifest. Not going to use Nebula for this build as that would be a waste of resources.')
        ctx_obj['no_nebula'] = not ctx_obj['no_nebula']
    
    # Check if we said to have no nebula, but manually built a lighthouse
    if ctx_obj['no_nebula'] and len(lighthouses) > 0:
        LogHandler.warn('Lighthouse found in build along with "-N / --no_nebula"')
        response = LogHandler.confirmation('Did you want to use Nebula for this build?')
        if response:
            ctx_obj['no_nebula'] = not ctx_obj['no_nebula']

    # Create the Nebula Handler (if applicable)
    if not ctx_obj['no_nebula']:
        nebula_path = ctx_obj['config_contents']['global']['nebula_path']
        ctx_obj['nebula_handler'] = NebulaHandler(nebula_path, ctx_obj['config_contents']['global']['nebula_subnet'], Path(ctx_obj['op_directory']).joinpath('nebula'))   


@click.pass_context
def prepare_core_handlers(ctx):
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


@click.pass_obj
def prepare_and_run_ansible(ctx_obj):

    # Create the Ansible Handler
    ansible_path = ctx_obj['config_contents']['global']['ansible_path']
    public_key, private_key = get_operation_ssh_key_pair()
    ctx_obj['ansible_handler'] = AnsibleHandler(ansible_path, Path(ctx_obj['op_directory']).joinpath('ansible'), private_key)
    
    # Build the Ansible Inventory
    LogHandler.debug('Building Ansible inventory')  
    AnsibleHandler.build_ansible_inventory(ctx_obj)

    # Run all the Prep playbooks
    root_playbook_location = '../../../playbooks'
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/wait-for-system-setup.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/clean-all-systems.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/prep-all-systems.yml')

    # Run all the server-type specific playbooks
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-containers.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-redirector.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-categorization.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-mailserver.yml')


@click.pass_obj
def read_build_manifest(ctx_obj):

    build_manifest_file = Path(ctx_obj['op_directory']).joinpath('.terry/build_manifest.yml')

    # Load the build config
    if build_manifest_file.exists():
        build_manifest = build_manifest_file.read_text()
        build_manifest_yaml = yaml.safe_load(build_manifest)

        return build_manifest_yaml
    else:
        LogHandler.warn(f'No build manifest found for "{ ctx_obj["operation"] }". Building one now...')
        build_manifest_contents = {
            'build_uuid': ctx_obj['build_uuid'],
            'operation': ctx_obj['operation'],
            'all_resources': []
        }
        build_manifest_yaml = yaml.safe_dump(build_manifest_contents)
        build_manifest_file.write_text(build_manifest_yaml)
        return build_manifest_contents


@click.pass_obj
def parse_build_manifest(ctx_obj):

    LogHandler.debug('Parsing the build manifest')

    build_manifest = read_build_manifest()

    # Check if there are resources listed in the build manifest and append to all resources
    if build_manifest['all_resources'] and len(build_manifest['all_resources']) > 0:
        for resource in build_manifest['all_resources']:
            resource_type, resource = list(resource.items())[0]

            if resource_type == 'server':
                resource = Server.from_dict(resource)
            elif resource_type == 'domain':
                resource = Domain.from_dict()

            ctx_obj['all_resources'].append(resource)
        
        extract_nebula_config()


@click.pass_obj
def create_build_manifest(ctx_obj):
    """"""

    existing_build_manifest = read_build_manifest()

    # Pass the build uuid to the CTX
    ctx_obj['build_uuid'] = existing_build_manifest['build_uuid']

    parse_build_manifest()

    added_manifest_items = [ { resource.resource_type: resource.to_dict() } for resource in ctx_obj['all_resources'] ]

    new_manifest = {
        **existing_build_manifest,
        'all_resources': added_manifest_items,
        'lighthouse_nebula_ip': ctx_obj.get('lighthouse_nebula_ip'), 
        'lighthouse_public_ip': ctx_obj.get('lighthouse_public_ip')
    }

    new_manifest_yaml = yaml.safe_dump(new_manifest)

    build_manifest = Path(ctx_obj['op_directory']).joinpath('.terry/build_manifest.yml')
    build_manifest.write_text(new_manifest_yaml)
    

@click.pass_obj
def validate_credentials(ctx_obj, check_containers=True):
    """Validate that we have credentials needed for the specified actions (all required providers will be given to the Click Context Object at `ctx.obj['required_providers']`)

    Args:
        `check_containers (bool)`: Should we check that we have credentials to deploy containers (not needed when destorying infra)
    Returns:
        `None`
    """

    LogHandler.info('Validating that we have all required credentials')

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
                    check_for_required_value('container_registry')
                    check_for_required_value('container_registry_username', hide_input=True)
                    check_for_required_value('container_registry_password', hide_input=True)
                    container_registry_credentials_checked = True

        if resource.domain_map:
            for domain in resource.domain_map:
                registrars = TerraformObject.get_terraform_mappings(simple_list=True, type='registrar')
                if not domain.provider in registrars:
                    LogHandler.critical(f'Registrar of {domain.provider} not implemented. Please implement it and rerun or change the registrar.')
                else: 
                    required_providers.add(domain.provider)

    ctx_obj['required_providers'] = []
    for provider in required_providers:
        current_provider = Provider(provider)
        ctx_obj['required_providers'].append(current_provider)
     
    LogHandler.info('All required credentials found')
    

@click.pass_obj
def retreive_remote_configurations(ctx_obj):

    # Check to see if any remote configurations were defined in the config
    for remote_config in ctx_obj["config_contents"]["ansible_configuration"]["remote"]:
        if not remote_config["name"] or len(remote_config["name"]) == 0:
            LogHandler.error('Found blank entry for a remote configuration in the config file, skipping blank entry...')
            continue

        LogHandler.info(f'Found name of "{ remote_config["name"] }" for a remote configuration, loading it now...')
        remote_config = RemoteConfigurationHandler(remote_config["name"], remote_config["repo_url"], remote_config["username"], remote_config["personal_access_token"])

        # Write out the configuration to the op_directory
        configuration_location = Path(ctx_obj['op_directory']).joinpath(f'ansible/extra_vars/{ remote_config.configuration_name }.yml')
        LogHandler.debug(f'Writing out "{ remote_config.configuration_name }" remote configuration to "{ configuration_location }"')
        yaml_contents = yaml.dump(remote_config.configuration)
        configuration_location.write_text(yaml_contents)


@click.pass_obj
def extract_nebula_config(ctx_obj):

    LogHandler.debug('Getting the Lighthouse Public IP and Nebula IP from build manifest')

    for resource in ctx_obj['all_resources']:
        if isinstance(resource, Lighthouse):
            ctx_obj['lighthouse_public_ip'] = resource.public_ip
            ctx_obj['lighthouse_nebula_ip'] = resource.nebula_ip
            return
    
    LogHandler.debug('No Lighthouse found in build manifest, assuming Nebula was not configured...')
    ctx_obj['no_nebula'] = True


@click.pass_obj
def get_operation_ssh_key_pair(ctx_obj):
    """Gets the SSH key that will be used for ansible (required because the generated key won't work for some reason, but reading it will???)
    Returns the byte string of the SSH key
    """

    public_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key.pub')).read_bytes()
    private_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key')).read_bytes()
    
    return public_key, private_key


def generate_random_name():
    """Helper function to create a random resource name"""

    word_file = Path("/usr/share/dict/words")
    words = word_file.read_text().splitlines()

    random_word1 = words[random.randint(0, len(words))].lower()
    random_word2 = words[random.randint(0, len(words))].lower()

    return f'{random_word1}-{random_word2}'

    # WORDS = open(word_file).read().splitlines()
    # return type + (str([x.server_type for x in ctx_obj['all_resources']].count(type) + 1))


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

@click.pass_obj
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


