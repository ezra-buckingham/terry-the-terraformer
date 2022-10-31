import click
import random
import re
import yaml
import tabulate

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


@click.pass_context
def prepare_mail_servers(ctx):
    """_summary_

    Args:
        ctx (_type_): _description_
    """
    
    from terry import domain, build_infrastructure
    
    mailservers_in_build = False
    
    for server in ctx.obj["resources"]:
        
        if not isinstance(server, Mailserver):
            continue
        
        if server.dns_setup:
            LogHandler.debug('Mailserver found, but DNS records already present for SMTP to work')
            continue
        
        mailservers_in_build = True
        LogHandler.info('Mailserver found, setting up DNS records for SMTP now')
        
        # Get the MX record for this mailserver from current build
        server_root_domain = Domain.get_domain(server.domain)
        corresponding_domain = [x for x in ctx.obj['resources'] if isinstance(x, Domain) and x.domain == server_root_domain][0]
        domain_provider = corresponding_domain.provider
        
        # Get the DKIM Key
        dkim_record_file = Path(ctx.obj['op_directory']).joinpath(f'ansible/extra_files/{ server.uuid }_dkim_default.txt')
        dkim_record = dkim_record_file.read_text()
                
        # Parse the DKIM file
        dkim_record_split = dkim_record.split('\t')
        dkim_record = re.search(r'\(([^\)]+)\)', dkim_record).group(1)
        dkim_record = list(map(lambda record: re.sub('[" \t\n]', '', record), dkim_record.split('\t')))
        dkim_host_fqdn = f'{dkim_record_split[0]}.{server_root_domain}'
        
        # Build out the proper DKIM value that can be processed by terraform
        dkim_value = '\x5C\x22\x5C\x22'.join(dkim_record)
        
        # Mark the server for having had DNS setup
        server.dns_setup = True
        
        # Run the add with the new DKIM
        ctx.invoke(domain, provider=domain_provider, domain=dkim_host_fqdn, type='TXT', value=dkim_value)    
        
        # Setup the SPF record with the IPv4
        spf_domain_value = f'v=spf1 mx ip4:{ server.public_ip } ~all'
        
        ctx.invoke(domain, provider=domain_provider, domain=server.domain, type='TXT', value=spf_domain_value)
        
    # Build infra again in order to populate the new DNS entries 
    if mailservers_in_build: 
        # Ensure force flag is false so all build infra isn't fully replaced (new UUIDs / Names assigned)
        ctx.obj['force'] = False
        ctx.obj['auto_approve'] = True
        
        # Create the terraform plan and build it 
        build_terraform_plan(write_plan=True)

        # Apply the plan and map results back
        ctx.obj['terraform_handler'].apply_plan(auto_approve=ctx.obj['auto_approve'])
        results = ctx.obj['terraform_handler'].show_state_resources(json=True)
        map_terraform_values_to_resources(results)
        
        return 
    

@click.pass_context
def prepare_lighthouse(ctx):
    """Prepare the Nebula handler object for the build (all handlers will be given to the Click Context Object at `ctx.obj['<software>_handler']
    This is split out as we may want not want to search for the Nebula Binary too early in a build as it might not be needed

    Args:
        `None`
    Returns:
        `None`
    """

    # Get all the lighthouses from the resources
    lighthouses = [ x for x in ctx.obj["resources"] if isinstance(x, Lighthouse) ]
    servers = [ resource for resource in ctx.obj['resources'] if isinstance(resource, Server) ]
    
    # Ensure we only have one lighthouse
    if len(lighthouses) > 1:
        LogHandler.critical('Multiple Lighthouses found in build, Terry can only handle building one per deployment')
    
    def add_lighthouse():
        
        # Ask the user if they wish to continue
        response = LogHandler.confirmation('Would you like me to add a Lighthouse to the current build?')
        if not response:
            return False

        # Now get the provider from the user
        provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')
        while provider not in TerraformObject.get_terraform_mappings(simple_list=True):
            LogHandler.error(f'Invalid provider provided: {provider}. Please enter one of the following providers: {TerraformObject.get_terraform_mappings(simple_list=True)}', is_fatal=False)
            provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')

        from terry import server
        ctx.invoke(server, provider=provider, type='lighthouse')
    
        return True
        
    # Check with user if we want to build nebula when there are many servers in the build
    if len(lighthouses) == 0:
        if not ctx.obj['no_nebula']:
            LogHandler.warn('Nebula configured for this build, but no Lighthouses found. Either use the "-N" / "--no_nebula" flag or I can build one for you now.')
            result = add_lighthouse()
            if not result:
                LogHandler.warn('Opting out of Nebula for this build')
                ctx.obj['no_nebula'] = not ctx.obj['no_nebula']
            else:
                return prepare_lighthouse()
        
        if not ctx.obj['no_elastic']:
            LogHandler.warn('Elastic configured for this build, but no Lighthouses found. Either use the "-Ne" / "--no_elastic" flag or I can build one for you now.')
            result = add_lighthouse()
            if not result:
                LogHandler.warn('Opting out of Elastic for this build')
                ctx.obj['no_elastic'] = not ctx.obj['no_elastic']
            else:
                return prepare_lighthouse()
                
    if not ctx.obj['no_nebula']:
        LogHandler.debug('Nebula has been configured for this build')
        nebula_path = ctx.obj['config_contents']['global']['nebula_path']
        ctx.obj['nebula_handler'] = NebulaHandler(nebula_path, ctx.obj['config_contents']['global']['nebula_subnet'], Path(ctx.obj['op_directory']).joinpath('nebula'))
    else:
        LogHandler.warn('This build has opted out of Nebula')
        
    if not ctx.obj['no_elastic']:
        LogHandler.debug('Elastic has been configured for this build')
        server = check_for_required_value('elastic_server')
        if not len(server.get().split(':')) == 2: LogHandler.critical('Elastic server must be an IP address or FQDN and port (ex "elastic.example.com:9200")')
        check_for_required_value('elastic_api_key')
    else:
        LogHandler.warn('This build has opted out of Elastic')
        

@click.pass_obj
def configure_nebula(ctx_obj):
    """_summary_

    Args:
        ctx_obj (_type_): _description_
    """
    
    if ctx_obj['no_nebula']:
        LogHandler.info('Nebula not configured for this build, skipping setting up Nebula configurations and certificates')
        return
    

    LogHandler.info('Setting up Nebula configurations and certificates')
    ctx_obj['nebula_handler'].generate_ca_certs()
    
    # First loop over all resources to get all already assigned Nebula IPs
    already_assigned_ips = set()
    for resource in ctx_obj['resources']:
        if not isinstance(resource, Server): continue
        already_assigned_ips.add(resource.nebula_ip)
        
    # Tell the Nebula Handler what IPs have already been assigned
    ctx_obj['nebula_handler'].set_assigned_ips(already_assigned_ips)
    
    # Now loop over all resources and generate the client certs
    for resource in ctx_obj['resources']:
        if not isinstance(resource, Server): continue
        
        # Generate a certificate and if one is generated assign it, if not, there is likely an existing assigned IP / certificate
        assigned_nebula_ip = ctx_obj['nebula_handler'].generate_client_cert(resource.uuid)
        if assigned_nebula_ip:
            resource.nebula_ip = assigned_nebula_ip
        
        if isinstance(resource, Lighthouse):
            ctx_obj['lighthouse_public_ip'] = resource.public_ip
            ctx_obj['lighthouse_nebula_ip'] = resource.nebula_ip
            
    LogHandler.info('Nebula certificates created. Out of this world, huh?')
    
    
@click.pass_obj
def configure_redirectors(ctx_obj):
    """_summary_

    Args:
        ctx_obj (_type_): _description_
    """    
    
    LogHandler.info('Getting IPs for Redirector configurations')
    
    for resource in ctx_obj['resources']:
        if isinstance(resource, Redirector):
            if not resource.redirect_to: 
                LogHandler.warn(f'Unable to automatically configure redirector: redirect_to undefined for "{resource.name}"')
                continue
            
            redirect_to_server = get_server_from_uuid_or_name(resource.redirect_to)
            
            if redirect_to_server.nebula_ip:
                resource.redirect_to = redirect_to_server.nebula_ip
            else:
                resource.redirect_to = redirect_to_server.public_ip
        
    LogHandler.info('Redirectors configured')


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


@click.pass_context
def prepare_and_run_ansible(ctx):
    """Prepare all the Ansible handler object and run all playbooks (handler will be given to the Click Context Object at `ctx.obj['ansible_handler']`)

    Args:
        `None`
    Returns:
        `None`
    """

    # Create the Ansible Handler
    ansible_path = ctx.obj['config_contents']['global']['ansible_path']
    public_key, private_key = get_operation_ssh_key_pair()
    ctx.obj['ansible_handler'] = AnsibleHandler(ansible_path, Path(ctx.obj['op_directory']).joinpath('ansible'), private_key)
    
    # Build the Ansible Inventory
    build_ansible_inventory()

    # Run all the Prep playbooks
    root_playbook_location = '../../../playbooks'
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/wait-for-system-setup.yml')
    
    # Check if we need to clean up access from the systems
    if not ctx.command.name == 'create': ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/clean-all-systems.yml')
    
    # Prepare all the hosts
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/prep-all-systems.yml')

    # Run all the server-type specific playbooks
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-lighthouse.yml')
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-containers.yml')
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-redirector.yml')
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-categorization.yml')
    ctx.obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-mailserver.yml')
    
    # Check for additional playbooks
    extended_plays = ctx.obj['config_contents']['ansible_configuration'].get('extended_plays', None)
    if extended_plays:
        LogHandler.debug('Checking for extended_plays defined in the configuration file')
        extended_plays = extended_plays.get(ctx.command.name, None)
        
        # Loop over found plays
        for play in extended_plays:
            # Get the path and extra_vars
            play_path = play.get('path')
            play_vars = play.get('extra_vars')
            
            # Check if the play actually exists and if so, run it with extra_vars
            if play_path:
                if not Path(play_path).exists():
                    LogHandler.error(f'Found extended_play at {play_path} for "{ctx.command.name}", but that file was not found on the host')
                play_path = Path(play_path).absolute()
                LogHandler.debug(f'Found extended_play at {play_path} for "{ctx.command.name}"')
                ctx.obj['ansible_handler'].run_playbook(play_path, playbook_vars=play_vars)
    
    LogHandler.info('Ansible setup complete')


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
            'config': {
                'no_nebula': None,
                'lighthouse_nebula_ip': None,
                'lighthouse_public_ip': None,
                'no_elastic': None,
                'elastic_server': None  
            },
            'resources': []
        }
        build_manifest_yaml = yaml.safe_dump(build_manifest_contents, sort_keys=True)
        build_manifest_file.write_text(build_manifest_yaml)
        return build_manifest_contents


@click.pass_obj
def parse_build_manifest(ctx_obj, force=False):
    """Read the build manifest **and pass values into the Click Context**

    Args:
        `force (bool)`: Force reading the manifest and ignore all resources in manifest
    Returns:
        `build_manifest (dict)`: The build manifest contents
    """

    LogHandler.debug('Parsing the build manifest')

    # Read the manifest and pass in the top level items to click context
    build_manifest = read_build_manifest()
    ctx_obj['build_uuid'] = build_manifest['build_uuid']
    ctx_obj['operation'] = build_manifest['operation']
    
    # If we want to force replacement, return the build manifest without any additional config
    if force: return build_manifest
    
    build_config = build_manifest['config']
    ctx_obj['no_nebula'] = build_config.get('no_nebula', True)
    ctx_obj['lighthouse_public_ip'] = build_config.get('lighthouse_public_ip')
    ctx_obj['lighthouse_nebula_ip'] = build_config.get('lighthouse_nebula_ip')
    ctx_obj['no_elastic'] = build_config.get('no_elastic', True)
    ctx_obj['elastic_server'] = build_config.get('elastic_server')

    # Check if there are resources listed in the build manifest and append to all resources
    if build_manifest['resources'] and len(build_manifest['resources']) > 0:
        for resource in build_manifest['resources']:
            resource_type, resource = list(resource.items())[0]

            if resource_type == 'server':
                resource = Server.from_dict(resource)
                ctx_obj['existing_server_names'].add(resource.name)
            elif resource_type == 'domain':
                resource = Domain.from_dict(resource)
                domain_zone = f'{ resource.domain }'
                ctx_obj['required_domains'].add(domain_zone)
            elif resource_type == 'ssh_key':
                resource = SSHKey.from_dict(resource)
                ctx_obj['required_ssh_keys'].add(resource.provider)

            ctx_obj['required_providers'].add(resource.provider)
            ctx_obj['resources'].append(resource)

    return build_manifest


@click.pass_obj
def create_build_manifest(ctx_obj):
    """Create the build manifest with all the current build objects

    Args:
        `None`
    Returns:
        `new_build_manifest (dict)`: The newly created build manifest
    """

    LogHandler.debug('Creating the build manifest')

    # Read in the existing build manifest
    existing_build_manifest = read_build_manifest()

    # Get the items from the current build an create the new manifest
    added_manifest_items = [ { resource.resource_type: resource.to_dict() } for resource in ctx_obj['resources'] ]
    new_manifest = {
        **existing_build_manifest,
        'resources': added_manifest_items,
        'config': {
            'no_nebula': ctx_obj.get('no_nebula'),
            'lighthouse_nebula_ip': ctx_obj.get('lighthouse_nebula_ip'), 
            'lighthouse_public_ip': ctx_obj.get('lighthouse_public_ip'),
            'no_elastic': ctx_obj.get('no_elastic'),
            'elastic_server': ctx_obj.get('elastic_server') 
        }
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
def retrieve_remote_configurations(ctx_obj):
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
        LogHandler.critical(f'Unable to find one and exactly one matching server resource using the value "{ resource_uuid_or_name }", please check that the "--server_name / -sN" you are using exists (and is defined before the resource that references it)')

    return resource[0]


@click.pass_obj
def build_terraform_plan(ctx_obj, write_plan=False):
    """Build the Terraform plan.
    Takes the Click context object dictionary.
    Returns a complete Terraform plan as a string.
    Uses the utils.render_template function to render the Terraform plan based on
    provider and resource templates.
    """
    
    LogHandler.info('Building Terraform plan')

    plan = ''
    jinja_handler = JinjaHandler(".")

    # Start with adding the providers
    plan += jinja_handler.get_and_render_template('./templates/terraform/provider.tf.j2', {'required_providers' : ctx_obj['required_providers']})+ '\n\n'
    
    # Loop over the required providers and see if there is a _base.tf.j2 we need to load
    for provider in ctx_obj['required_providers']:
        base_template_path = f'./templates/terraform/resources/{ provider.name }/_base.tf.j2'
        
        if not Path(base_template_path).exists(): 
            LogHandler.debug(f'No _base.tf.j2 found for "{ provider.name }", skipping')
            continue
        
        LogHandler.debug(f'Found _base.tf.j2 found for "{ provider.name }", adding that to build')
        plan += jinja_handler.get_and_render_template(base_template_path, ctx_obj) + '\n\n'
        
    # Now prepare it all
    for resource in ctx_obj["resources"]:

        # Now prepare the resource
        jinja_vars = { **vars(resource), **ctx_obj }
        plan += jinja_handler.get_and_render_template(resource.terraform_resource_path, jinja_vars) + '\n\n'             

    if write_plan:
        plan_file = Path(ctx_obj['op_directory']).joinpath(f'terraform/{ ctx_obj["operation"] }_plan.tf')
        LogHandler.debug('Writing Terraform plan to disk')
        plan_file.write_text(plan)

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

    LogHandler.debug('Building Ansible inventory')

    server_types = get_implemented_server_types()
    inventory = {inventory: {'hosts': {}} for inventory in server_types}

    for resource in [ server for server in  ctx_obj['resources'] if isinstance(server, Server) ]:
        inventory[resource.server_type]['hosts'][resource.public_ip] = resource.prepare_object_for_ansible()
            
    # Ansible will lock this file at times, so we need to try to write the changes, but may not be able to
    try:
        # Create the Global Vars to pass to ansible
        global_vars = ctx_obj["config_contents"]["ansible_configuration"]["global"]
        global_vars["operation"] = str(ctx_obj["operation"])
        global_vars["op_directory"] = str(ctx_obj["op_directory"].resolve())
        global_vars["nebula"] = not ctx_obj['no_nebula']
        global_vars["elastic"] = not ctx_obj['no_elastic']
        # If installing Nebula, give the additional vars needed for configuring it on the hosts
        if global_vars["nebula"]:
            global_vars["lighthouse_public_ip"] = ctx_obj.get('lighthouse_public_ip')
            global_vars["lighthouse_nebula_ip"] = ctx_obj.get('lighthouse_nebula_ip')

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


@click.pass_context
def display_resources(ctx):
    """Prints out the resources in a neatly formatted way

    Args:
        ctx (_type_): _description_
    """
    
    server_table_headers = ['server_name', 'server_type', 'public_ip', 'nebula_ip', 'provider', 'domain']
    servers = [ server_table_headers ]
    
    domain_table_headers = ['domain', 'host', 'record_type', 'value']
    domains = [ domain_table_headers ]
    
    for resource in ctx.obj['resources']:
        if isinstance(resource, Server):
            server = [ resource.name, resource.server_type, resource.public_ip, resource.nebula_ip, resource.provider, resource.domain ]
            servers.append(server)
        elif isinstance(resource, Domain):
            for record in resource.domain_records:
                domain = [ resource.domain, record.subdomain, record.record_type, record.value ]
                domains.append(domain)
    
    print(f'\nServer Resources:\n')
    print(tabulate.tabulate(servers, headers='firstrow', tablefmt='fancy_grid'))
    
    print(f'\nDomain Resources:\n')
    print(tabulate.tabulate(domains, headers='firstrow', tablefmt='fancy_grid'))
    print()
    
    

@click.pass_obj
def map_domain_to_server_value(domain: Domain, server: Server):
    """"""


def generate_random_name():
    """Helper function to create 2 random words from the copy of `/usr/share/dict/words` in this repo to make a name (words limited to 8 characters each)
    
    Args:
        `None`
    Returns:
        `random_name (str)`: A random name consisting of `<word1>-<word2>`
    """

    word_file = Path("core/static/words")
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
        required_value.set(cli_value)
        ctx_obj[value_name.lower()] = cli_value
        return required_value
    else:
        LogHandler.debug(f'{value_name}: Value NOT FOUND in CLI arguments')

    # Second, check the env variable in case it was set manually
    if required_value.get(): 
        LogHandler.debug(f'{value_name}: Value FOUND in envionment variables')
        ctx_obj[value_name.lower()] = required_value.get()
        return required_value
    else: 
        LogHandler.debug(f'{value_name}: Value NOT FOUND in environment variables')
                
    # Third, check the config file for the argument needed for the provider
    config_values = ctx_obj.get('config_contents', {})
    config_value = find_dict_item(config_values, value_name)
    if config_value:
        LogHandler.debug(f'{value_name}: Value FOUND in config file')
        required_value.set(config_value)
        ctx_obj[value_name.lower()] = config_value
        return required_value
    else:
        LogHandler.debug(f'{value_name}: Value NOT FOUND in config file')
                
    # Lastly, prompt the user to give us the creds if not found
    if not required_value.get():
        returned_value = LogHandler.get_input(f'Enter the {value_name}', hide_input=hide_input)
        required_value.set(returned_value)
        ctx_obj[value_name.lower()] = returned_value
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
    # In some cases a "file" will not return True on path.is_file()
    # (Typically any ssh_key_data files from Ansible)
    # This is unexplainable, but catch-able using this block
    try:
        path.rmdir()
    except NotADirectoryError:
        path.unlink()


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

    server_types = ['bare', 'categorize', 'teamserver', 'lighthouse', 'redirector', 'mailserver']
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


