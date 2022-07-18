import random
import re
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
def check_for_operation_directory(ctx_obj):
    """Check that the operation directory exists

    Args: 
        `None`
    Returns:
        `None`
    """

    # Check if the folder exists
    if not ctx_obj['op_directory'].exists():
        LogHandler.critical(f'No deployment found with the name "{ ctx_obj["operation"] }"')

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
    lighthouses = [ x for x in ctx_obj["resources"] if isinstance(x, Lighthouse) ]
    
    # Check with user if we want to build nebula when there are many servers in the build
    if not ctx_obj['no_nebula'] and len([ resource for resource in ctx_obj['resources'] if isinstance(resource, Server) ]) > 1:
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
                ctx_obj["resources"].insert(0, lighthouse)
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
    """Prepare all the Ansible handler object and run all playbooks (handler will be given to the Click Context Object at `ctx.obj['ansible_handler']`)

    Args:
        `None`
    Returns:
        `None`
    """

    # Create the Ansible Handler
    ansible_path = ctx_obj['config_contents']['global']['ansible_path']
    public_key, private_key = get_operation_ssh_key_pair()
    ctx_obj['ansible_handler'] = AnsibleHandler(ansible_path, Path(ctx_obj['op_directory']).joinpath('ansible'), private_key)
    
    # Build the Ansible Inventory
    LogHandler.debug('Building Ansible inventory')  
    build_ansible_inventory()

    # Run all the Prep playbooks
    root_playbook_location = '../../../playbooks'
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/wait-for-system-setup.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/clean-all-systems.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/prep-all-systems.yml')

    # Run all the server-type specific playbooks
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-lighthouse.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-containers.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-redirector.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-categorization.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-mailserver.yml')


@click.pass_obj
def read_build_manifest(ctx_obj):
    """Read the build manifest **without passing values into the Click Context** (will create a base build manifest if not found)

    Args:
        `None`
    Returns:
        `build_manifest (dict)`: The build manifest contents
    """

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
            'lighthouse_nebula_ip': None,
            'lighthouse_nebula_ip': None,
            'resources': []
        }
        build_manifest_yaml = yaml.safe_dump(build_manifest_contents, sort_keys=True)
        build_manifest_file.write_text(build_manifest_yaml)
        return build_manifest_contents


@click.pass_obj
def parse_build_manifest(ctx_obj):
    """Read the build manifest **and pass values into the Click Context**

    Args:
        `None`
    Returns:
        `build_manifest (dict)`: The build manifest contents
    """

    LogHandler.debug('Parsing the build manifest')

    # Read the manifest and pass in the top level items to click context
    build_manifest = read_build_manifest()
    ctx_obj['build_uuid'] = build_manifest['build_uuid']

    # Check if there are resources listed in the build manifest and append to all resources
    if build_manifest['resources'] and len(build_manifest['resources']) > 0:
        for resource in build_manifest['resources']:
            resource_type, resource = list(resource.items())[0]

            if resource_type == 'server':
                resource = Server.from_dict(resource)
            elif resource_type == 'domain':
                resource = Domain.from_dict(resource)
                domain_zone = f'{ resource.domain }'
                ctx_obj['required_domains'].add(domain_zone)
            elif resource_type == 'ssh_key':
                resource = SSHKey.from_dict(resource)
                ctx_obj['required_ssh_keys'].add(resource.provider)

            ctx_obj['required_providers'].add(resource.provider)
            ctx_obj['resources'].append(resource)
        
        extract_nebula_config()

    return build_manifest


@click.pass_obj
def create_build_manifest(ctx_obj, full_replace=False):
    """Create the build manifest with all the current build objects

    Args:
        `None`
    Returns:
        `new_build_manifest (dict)`: The newly created build manifest
    """

    LogHandler.debug('Creating the build manifest')

    # Read in the existing build manifest
    existing_build_manifest = read_build_manifest()
    if full_replace:
        LogHandler.debug('Doing full replacement of the build manifest resources')
        existing_build_manifest.pop('resources')

    # Get the items from the current build an create the new manifest
    added_manifest_items = [ { resource.resource_type: resource.to_dict() } for resource in ctx_obj['resources'] ]
    new_manifest = {
        **existing_build_manifest,
        'resources': added_manifest_items,
        'lighthouse_nebula_ip': ctx_obj.get('lighthouse_nebula_ip'), 
        'lighthouse_public_ip': ctx_obj.get('lighthouse_public_ip')
    }
    new_manifest_yaml = yaml.safe_dump(new_manifest, sort_keys=True)

    # Write the new manifest out
    build_manifest = Path(ctx_obj['op_directory']).joinpath('.terry/build_manifest.yml')
    build_manifest.write_text(new_manifest_yaml)

    return new_manifest_yaml


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

    for resource in ctx_obj['resources']:
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

    ctx_obj['required_providers'] = []
    for provider in required_providers:
        current_provider = Provider(provider)
        ctx_obj['required_providers'].append(current_provider)
     
    LogHandler.info('All required credentials found')
    

@click.pass_obj
def retreive_remote_configurations(ctx_obj):
    """Retreive the Ansible remote configuration definitions from the config, load them, and write them to the `ansible/extra_vars` directory

    Args:
        `None`
    Returns:
        `remote_configs_loaded (list(dict))`: List of the loaded remote configurations
    """

    LogHandler.info('Checking config for remote configuration definitions')

    # Check to see if any remote configurations were defined in the config
    if not ctx_obj["config_contents"]["ansible_configuration"]["remote"]:
        LogHandler.warn('No remote configurations found in the config file.')
        return []

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

    LogHandler.info('Parsing of config for remote configuration definitions complete')

    return ctx_obj["config_contents"]["ansible_configuration"]["remote"]


@click.pass_obj
def extract_nebula_config(ctx_obj):
    """Extracts the Lighthouse's Nebula IP as well as Public IP and passes that to the Click Context

    Args:
        `None`
    Returns:
        `nebula_ip (str)`, `public_ip (str)`: The Nebula IP and Public IP of the Lighthouse (`None`, `None` if not found)
    """

    LogHandler.debug('Getting the Lighthouse Public IP and Nebula IP from build manifest')

    for resource in ctx_obj['resources']:
        if isinstance(resource, Lighthouse):
            ctx_obj['lighthouse_public_ip'] = resource.public_ip
            ctx_obj['lighthouse_nebula_ip'] = resource.nebula_ip
            return resource.nebula_ip, resource.public_ip
    
    LogHandler.debug('No Lighthouse found in build manifest, assuming Nebula was not configured...')
    ctx_obj['no_nebula'] = True

    return None, None


@click.pass_obj
def get_operation_ssh_key_pair(ctx_obj):
    """Gets the SSH key that will be used for ansible (required because using the byte array as generated won't work for some reason, but reading after it is written will???)

    Args:
        `None`
    Returns:
        `public_key (bytes)`, `private_key (bytes)`: The public and private key pair as a tuple
    """

    public_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key.pub')).read_bytes()
    private_key = Path(ctx_obj['op_directory'].joinpath(f'{ctx_obj["operation"]}_key')).read_bytes()
    
    return public_key, private_key


@click.pass_obj
def get_domain_zone_index_from_build(ctx_obj, domain_zone):
    """Gets the reference to domain zone from the build (if exists)
    
    Args:
        `domain_zone (str)`: Domain zone (only the TLD and domain formatted as example.com)
    Returns
        `domain (Domain)`: Domain zone
    """

    for index, domain in enumerate(ctx_obj['resources']):
        if isinstance(domain, Domain) and domain.domain == domain_zone:
            return index

    return None


@click.pass_obj
def get_server_from_uuid_or_name(ctx_obj, resource_uuid_or_name):
    """Return the reference to the server given the UUID or name

    Args:
        `resource_uuid_or_name (str)`: Name or UUID of the resource
    Returns
        `resource (Server)`: Reference to the resource 
    """

    # Check if we were given a UUID 
    if len(resource_uuid_or_name) == 39 or len(resource_uuid_or_name) == 36:
        if len(resource_uuid_or_name) == 36:
            resource_uuid_or_name = f'id-{ resource_uuid_or_name }'
        resource = [ server for server in  ctx_obj['resources'] if isinstance(server, Server) and server.uuid == resource_uuid_or_name ]
    # If length doesn't match the UUID, we can safely assume (I hope) we have a name
    else:
        resource = [ server for server in  ctx_obj['resources'] if isinstance(server, Server) and server.name == resource_uuid_or_name ]

    if len(resource) != 1:
        LogHandler.critical(f'Unable to find one and exactly one matching server resource using the value "{ resource_uuid_or_name }"')

    return resource[0]


@click.pass_obj
def build_terraform_plan(ctx_obj):
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
        
    # Now prepare it all
    for resource in ctx_obj["resources"]:

        # Now prepare the resource
        jinja_vars = { **vars(resource), **ctx_obj }
        plan += jinja_handler.get_and_render_template(resource.terraform_resource_path, jinja_vars) + '\n\n'             

    return plan


@click.pass_obj
def map_terraform_values_to_resources(ctx_obj, json_data):
    """Map results from Terraform plan application back to class instances.
    Takes the click context object dictionary and JSONified terraform.show() results.
    Returns nothing (updates resource classes in place).
    """

    LogHandler.debug('Mapping Terraform state')

    # Get the terraform mappings so we know what keys to search for
    terraform_mappings = TerraformObject.get_terraform_mappings()

    for resource in json_data:
        resource_values = resource['values']
        resource_address = resource['address'].split('.')

        # Skip over the data objects
        if resource_address[0] == 'data': continue

        resource_uuid = resource_address[1]
        matching_resource = [r for r in ctx_obj['resources'] if r.uuid == resource_uuid]
            
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


@click.pass_obj
def build_ansible_inventory(ctx_obj):
    """"""

    # We want to build a file so that ansible could be independently run outside of terry
    # as opposed to passing a dict to ansible_runner

    server_types = get_implemented_server_types()
    inventory = {inventory: {'hosts': {}} for inventory in server_types}

    for resource in [ server for server in  ctx_obj['resources'] if isinstance(server, Server) ]:
        inventory[resource.server_type]['hosts'][resource.public_ip] = resource.prepare_object_for_ansible()
            
    # Ansible will lock this file at times, so we need to try to write the changes, but may not be able to
    try:
        # Create the Global Vars to pass to ansible
        global_vars = ctx_obj["config_contents"]["ansible_configuration"]["global"]
        global_vars["op_directory"] = str(ctx_obj["op_directory"].resolve())
        global_vars["nebula"] = not ctx_obj['no_nebula']
        # If installing Nebula, give the additional vars needed for configuring it on the hosts
        if global_vars["nebula"]:
            global_vars["lighthouse_public_ip"] = ctx_obj['lighthouse_public_ip']
            global_vars["lighthouse_nebula_ip"] = ctx_obj['lighthouse_nebula_ip']

        # Give Ansible the default users from the configuration file
        default_users = ctx_obj["config_contents"]["ansible_configuration"]["default_users"]
        global_vars['team'] = default_users

        # Check if we have extra_vars to put into the inventory
        path_to_extra_vars = ctx_obj["op_directory"].joinpath('ansible/extra_vars')
        yaml_files = list(path_to_extra_vars.glob('**/*.yml'))
        for yaml_file in yaml_files:
            # Open the file, parse it, and then spread it into the global vars
            open_yaml_file = Path(yaml_file)
            file_contents = open_yaml_file.read_text()
            yaml_contents = yaml.safe_load(file_contents)
            global_vars = {
                **global_vars,
                **yaml_contents
            }
                
        # Build the dictionary and write it to disk
        ansible_inventory = {'all': { 'vars': global_vars, 'children': inventory }}
        yaml_text = yaml.safe_dump(ansible_inventory)
        Path(ctx_obj['op_directory']).joinpath('ansible/inventory/hosts').write_text(yaml_text)
    except PermissionError as e:
        LogHandler.warn('There was a "PermissionError" while writing the Ansible inventory file')
        
    return inventory


@click.pass_obj
def map_domain_to_server_value(domain: Domain, server: Server):
    """"""


def generate_random_name():
    """Helper function to create 2 random words from `/usr/share/dict/words` to make a name (words limited to 8 characters each)
    
    Args:
        `None`
    Returns:
        `random_name (str)`: A random name consisting of `<word1>-<word2>`
    """

    word_file = Path("/usr/share/dict/words")
    words = word_file.read_text().splitlines()

    def __get_random_word():
        word = words[random.randint(0, len(words))]
        while len(word) > 9:
            word = words[random.randint(0, len(words))]
        return word.lower()

    random_word1 = __get_random_word()
    random_word2 = __get_random_word()

    name = re.sub(r'[^a-zA-Z\-]', '', f'{random_word1}-{random_word2}')

    return name


@click.pass_obj
def is_verbose_enabled(ctx_obj):
    """Checks the Click Context for verbosity level being set by the CLI
    
    Args:
        `None`
    Returns:
        `verbose (bool)`: Verbose logging enabled boolean
    """

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
        return required_value


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


def get_implemented_redirector_types():

    redirector_types = ['http', 'https', 'dns', 'custom']
    return redirector_types


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


