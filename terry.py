#!/usr/bin/python3
from asyncio.events import BaseDefaultEventLoopPolicy
from itertools import chain
import json
import logging
import os
import re
import sys
import click
import yaml
from pathlib import Path

# Local Imports
from core import *

#################################################################################################################
# Main Entrypoint for the CLI
#################################################################################################################    

@click.group(context_settings=dict(help_option_names=['-h', '--help', '--how-use', '--freaking-help-plz', '--stupid-terry']))
@click.option('-c', '--config', default="config.yml", type=click.Path(exists=True), help='''
    Path to configuration file in .yml format
    ''')
@click.option('-o', '--operation', required=True, help='''
    Name for project or operation
    ''')
@click.option('-a', '--auto_approve', is_flag=True, default=False, help='''
    Auto approve the Terraform apply commands (only works when building, destory will auto-approve by default)
    ''')
@click.option('-f', '--force', is_flag=True, default=False, help='''
    Force the build to go through, even if a deployment already exists with the opration name listed
    ''')
@click.option('-q', '--quiet', is_flag=True, default=False, help='''
    Don\'t send Slack messages to configuration-defined webhook url upon infrastructure creation
    ''')
@click.option('-v', '--verbose', is_flag=True, default=False, help='''
    Verbose output from Terry (does not change what is logged in the log file)
    ''')
@click.option('-l', '--log_file', default='./log_terry.log', type=Path, help='''
    Location to write log file to
    ''')
@click.option('-N', '--no_nebula', is_flag=True, default=False, help='''
    Skip setting up Nebula as a mesh vpn overlay on deployed resources
    ''')   
@click.option('-cR', '--container_registry', help='''
    Container registry to use for deploying containers (The URL for the registry)
    ''')
@click.option('-cRU', '--container_registry_username', help='''
    Username used to authenticate to the container registry (required if deploying containers)
    ''')
@click.option('-cRP', '--container_registry_password', help='''
    Password used to authenticate to the container registry (required if deploying containers)
    ''')
@click.option('-awsAK', '--aws_access_key_id', help='''
    AWS Access Key ID for AWS API
    ''')
@click.option('-awsSAK', '--aws_secret_access_key', help='''
    AWS Secret Access Key for AWS API
    ''')
@click.option('-awsR', '--aws_default_region', help='''
    AWS region
    ''')
@click.option('-doT', '--digital_ocean_token', help='''
    Token for Digital Ocean API
    ''')
@click.option('-ncU', '--namecheap_user_name', help='''
    Namecheap username for Namecheap API
    ''')
@click.option('-ncA', '--namecheap_api_user', help='''
    Namecheap API username for Namecheap API (Usually the same as username)
    ''')
@click.option('-ncK', '--namecheap_api_key', help='''
    Namecheap API Key for Namecheap API
    ''')
@click.option('-gdK', '--godaddy_api_key', help='''
    GoDaddy API Key for GoDaddy API
    ''')
@click.option('-gdS', '--godaddy_api_secret', help='''
    GoDaddy API Key Secret for GoDaddy API
    ''')
@click.option('-csP', '--cobaltstrike_password', help='''
    Password to use when connecting to teamserver
    ''')
@click.option('-csMC2', '--cobaltstrike_malleable_c2', type=click.Path(exists=True), help='''
    Path to malleable C2 profile to use when starting CobaltStrike
    ''')
@click.pass_context
def cli(ctx, config, operation, auto_approve, force, quiet, verbose, log_file, no_nebula,
    container_registry, container_registry_username, container_registry_password, 
    aws_access_key_id, aws_secret_access_key, aws_default_region, 
    digital_ocean_token, 
    namecheap_user_name, namecheap_api_user, namecheap_api_key,
    godaddy_api_key, godaddy_api_secret,
    cobaltstrike_password, cobaltstrike_malleable_c2):
    """Terry will help you with all of your red team infrastructure needs! He's not magic... he's Terry!"""

    # Configure logging and intial logging and time stamping
    logging.basicConfig(filename=log_file, filemode='a+', format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.DEBUG)
    command_run = ' '.join(sys.argv)
    LogHandler.info(f'Start of script run with command: "{command_run}"')

    # Open and parse the config file
    config_contents = Path(config).read_text()
    config_contents = yaml.safe_load(config_contents)

    # Get the operation directory
    project_directory = Path(config_contents['global']['project_directory'])

    # Create a context (ctx) object (obj) for Click to pass around that stores relevant information
    # Only add the things that come from the config file, all the other values will come from the params
    ctx.ensure_object(dict)
    ctx.obj['start_time'] = get_formatted_time()
    ctx.obj['command_run'] = command_run
    ctx.obj['project_directory'] = Path(config_contents['global']['project_directory'])
    ctx.obj['config'] = config  # Path to configuration file
    ctx.obj['config_contents'] = config_contents
    ctx.obj['safe_operation_name'] = re.sub(r'[^a-zA-Z]', '', operation) # Strip out only letters
    ctx.obj['op_directory'] = project_directory.joinpath(operation)
    ctx.obj['resources'] = []  # List of all resources 

    # Sets to track all the items we need one and only one of for each build / provider
    ctx.obj['required_providers'] = set()
    ctx.obj['required_ssh_keys'] = set()
    ctx.obj['required_domains'] = set()
    
    ctx.obj = {**ctx.obj, **ctx.params}


#################################################################################################################
# Main Commands & Callbacks
#################################################################################################################    


@cli.command(name='destroy')
@click.option('--recursive', '-r', is_flag=True, default=False, help='''
    Destroy all files and folders associated with the deployment as well
    ''')
@click.pass_obj
def destroy(ctx_obj, recursive):
    """Destroy the deployment"""

    LogHandler.info(f'Destroying the "{ ctx_obj["operation"] }" plan')

    # Check the operation exists
    check_for_operation_directory()

    # Prepare all required handlers
    prepare_core_handlers()

    # Read in the build config
    parse_build_manifest()

    # Validate our credentials
    validate_credentials(check_containers=False)

    success, stdout, stderr = ctx_obj['terraform_handler'].destroy_plan(auto_approve=ctx_obj['auto_approve'])

    if success or success is None:
        if success:
            LogHandler.info('Terraform resource destruction complete')
            ctx_obj['slack_handler'].send_destroy_success(ctx_obj)
        else:
            LogHandler.warn('No Terraform state was found, so no destruction to perform')
        if recursive:
            if Path(ctx_obj['op_directory']).exists():
                LogHandler.warn(f'Destroying all files associated with "{ ctx_obj["operation"] }"')
                remove_directory_recursively(ctx_obj["op_directory"])
                LogHandler.info('File destruction complete!')
            else:
                LogHandler.critical(f'No files or folder found for "{ ctx_obj["operation"] }"', True)
        else:
            LogHandler.warn('Leaving all build files intact. If you wish to destroy them, use the "-r" / "--recursive" flag')
    else:
        LogHandler.critical(f'Error when destroying "{ ctx_obj["operation"] }". Please try again.')
    
    LogHandler.info('Terry destroy complete!')


@cli.group(name='create', chain=True)
@click.pass_obj
def create(ctx_obj):
    """Create a new deployment"""

    LogHandler.info(f'Creating the "{ ctx_obj["operation"] }" plan')

    # Prepare all required handlers
    prepare_core_handlers()

    operation_name = ctx_obj["operation"]
    ctx_obj['build_uuid'] = str(uuid4())

    # Check for certificates directory
    certificates_directory = Path(ctx_obj['project_directory']).joinpath('.certificates')
    if not certificates_directory.exists():
        LogHandler.warn('Certificates directory not found in project directory, creating that now...')
        certificates_directory.mkdir(parents=True)

    # If the operation directory doesn't exist, create the skeleton for it as well as all other resources required
    if not Path(ctx_obj['op_directory']).exists():
        LogHandler.info('Building operation directory structure, ssh keys, and remote configuration (if applicable)')
        Path(ctx_obj['op_directory']).mkdir()
        # Does not account for situations where op_directory exists but these children do not
        for path in ['.terry', 'terraform/', 'ansible/inventory/', 'ansible/extra_vars', 'ansible/extra_tasks', 'nebula/']:
            Path(ctx_obj['op_directory']).joinpath(path).mkdir(parents=True)

        # Generate the SSH Keys and write them to disk
        public_key, private_key = generate_ssh_key()
        key_file = Path(ctx_obj['op_directory']).joinpath(f'{operation_name}_key')
        pub_key_file = Path(ctx_obj['op_directory']).joinpath(f'{operation_name}_key.pub')
        pub_key_file.write_bytes(public_key)
        key_file.write_bytes(private_key)
        os.chmod(str(key_file), 0o700)

        retreive_remote_configurations()
        create_build_manifest()

    # If the directory exists, we must check the flags supplied to see what Terry should do
    else: 
        LogHandler.warn(f'A plan with the name "{ operation_name }" already exists in "{ ctx_obj["op_directory"] }"')
        if not Path(ctx_obj["op_directory"]).joinpath('terraform/terraform.tfstate').exists():
            LogHandler.warn(f'No terraform state found for "{ operation_name }", continuing with build regardless of "-f" / "--force" flag.')
        elif not ctx_obj['force']:
            LogHandler.critical(f'Terraform state found for "{ operation_name }". Please choose a new operation name, new deployment path, or use the "-f" / "--force" flag. Just note that when using the force flag you may overwrite existing Terraform resources.')
        else:
            LogHandler.warn('Continuing since "-f" / "--force" was supplied.')
    
    # Load the public key so we can build the ssh key resources later
    public_key, private_key = get_operation_ssh_key_pair()
    ctx_obj['ssh_pub_key'] = public_key
    

@create.result_callback()
@click.pass_obj
def build_infrastructure(ctx_obj, resources):
    # Make sure we have credentials for each of the providers
    validate_credentials(check_containers=True)

    prepare_nebula_handler()

    LogHandler.debug('Build looks good! Terry, take it away!')

    # Create the terraform plan and build it 
    LogHandler.info('Building Terraform plan')
    plan = build_terraform_plan()
    plan_file = Path(ctx_obj['op_directory']).joinpath(f'terraform/{ ctx_obj["operation"] }_plan.tf')
    LogHandler.debug('Writing Terrafom plan to disk')
    plan_file.write_text(plan)

    # Apply the plan and map results back
    ctx_obj['terraform_handler'].apply_plan(auto_approve=ctx_obj['auto_approve'])
    LogHandler.info('Terraform apply successful!')
    return_code, stdout, stderr = ctx_obj['terraform_handler'].show_state(json=True)
    results = json.loads(stdout)['values']['root_module']['resources']
    map_terraform_values_to_resources(results)

    # Configure Nebula
    if not ctx_obj['no_nebula']:
        LogHandler.info('Setting up Nebula configurations and certificates')
        ctx_obj['nebula_handler'].generate_ca_certs()
        for resource in [ server for server in  ctx_obj['resources'] if isinstance(server, Server) ]:
            assigned_nebula_ip = ctx_obj['nebula_handler'].generate_client_cert(resource.uuid)
            resource.nebula_ip = assigned_nebula_ip
        extract_nebula_config()
    else:
        LogHandler.info('Skipping setting up Nebula configurations and certificates')

    create_build_manifest()
    prepare_and_run_ansible()

    LogHandler.info('Ansible setup complete')
    ctx_obj['end_time'] = get_formatted_time()
    ctx_obj['slack_handler'].send_success(ctx_obj)

    LogHandler.info('Terry building complete! Enjoy the tools you tool!')


@cli.group(name='add', chain=True)
@click.pass_obj
def add(ctx_obj):
    """Add to an existing deployment"""

    LogHandler.info(f'Adding to the "{ ctx_obj["operation"] }" deployment')

    # Check the operation exists
    check_for_operation_directory()

    # Read in the existing build manifest
    parse_build_manifest()

    # Prepare the core handlers
    prepare_core_handlers()

    # Load the public key so we can build the ssh key resources later
    public_key, private_key = get_operation_ssh_key_pair()
    ctx_obj['ssh_pub_key'] = public_key
    

@add.result_callback()
def add_infrstructure(resources):
    build_infrastructure(resources)


@cli.command(name='refresh')
@click.pass_obj
def refresh(ctx_obj):
    """Refresh the deployment state and map results back to an updated build manifest"""

    LogHandler.info(f'Refreshing the "{ ctx_obj["operation"] }" plan')

    # Check the operation exists
    check_for_operation_directory()

    # Read in the existing build manifest
    parse_build_manifest()

    # Prepare the core handlers
    prepare_core_handlers()

    # Validate our credentials
    validate_credentials(check_containers=False)

    return_code, stdout, stderr = ctx_obj['terraform_handler'].show_state(json=True)
    results = json.loads(stdout)['values']['root_module']['resources']

    # Map the results from terraform.show() results back into the resource objects
    map_terraform_values_to_resources(results)

    # Write the refreshed data back to the manifest
    create_build_manifest(full_replace=True)

    ctx_obj['slack_handler'].send_success(ctx_obj)

    LogHandler.info('Terry refresh complete! Refreshing, huh?')
    

@cli.command(name='reconfigure')
@click.pass_obj
def reconfigure(ctx_obj):
    """Reconfigure a deployment by refreshing deployment state, getting updated remote configurations, and re-running playbooks against each host"""

    LogHandler.info(f'Reconfiguring the "{ ctx_obj["operation"] }" plan')

    # Check the operation exists
    check_for_operation_directory()

    # Read in the existing build manifest
    parse_build_manifest()

    # Prepare the core handlers
    prepare_core_handlers()

    # Validate our credentials
    validate_credentials(check_containers=True)

    # Retrieve any remote configuration files
    retreive_remote_configurations()

    # Prepare the Inventory file and run Ansible
    prepare_and_run_ansible()

    LogHandler.info('Terry reconfiguring complete!')


#################################################################################################################
# Subcommands 
#################################################################################################################   


@click.command(name='server')
@click.option('--provider', '-p', required=True, type=click.Choice(TerraformObject.get_terraform_mappings(simple_list=True, type='server')), help='''
    The cloud provider to use when creating the server
    ''')
@click.option('--type', '-t', required=True, type=click.Choice(get_implemented_server_types()), help='''
    The type of server to create
    ''')
@click.option('--name', '-sN', required=False, type=str, help='''
    Name of the server (used for creating corresponding DNS records if you use the "domain" command)
    ''')
@click.option('--container', '-cT', type=str, multiple=True, help='''
    Containers to install onto the server
    ''')
@click.option('--redirector_type', '-rT', type=click.Choice(get_implemented_redirector_types()), help='''
    Type redirector to build, with optional domain specified for that redirector formatted as "<provider>:<protocol>:<domain>:<registrar>" 
    (Example: https redirector in AWS at domain example.com with registrar AWS should be "aws:https:example.com:aws)"
    ''')
@click.option('--redirect_to', '-r2', type=str, help='''
    Domain to redirect to / impersonate (only deployed with categorize servers)
    ''')
@click.option('--fqdn', '-d', multiple=True, type=str, help='''
    Domain and registrar to use in creation of an A record for the resource formatted as "<domain>:<registrar>" (Example: domain example.com with registrar aws should be "example.com:aws)"
    ''')
@click.pass_context
def server(ctx, provider, type, name, redirector_type, redirect_to, fqdn, container):
    """Create a server resource"""

    if not name:
        name = generate_random_name()
    else:
        """"""
        # TODO check for name already existing

    # Check if we have an SSH Key for that provider provisioned
    if provider not in ctx.obj['required_ssh_keys']:
        LogHandler.debug(f'No SSH Key not found for "{ provider }", I will add one to the build for you')
        ssh_key_name = f'{ ctx.obj["operation"] }_{ provider }_key'
        ssh_key = SSHKey(provider, ssh_key_name, ctx.obj['ssh_pub_key'])
        ctx.obj['required_ssh_keys'].add(provider)
        ctx.obj['resources'].append(ssh_key)

    # Parse the domain strings for later processing
    domains = [ *list(fqdn) ]
    for domain_index, domain_record in enumerate(domains):
        domains[domain_index] = domain_record.split(':')
        if len(domains[domain_index]) != 2: 
            LogHandler.critical(f'Domain expects be formated as "<domain>:<registrar>" (example: "example.com:aws")')

    # Build the container objects & priority domain
    containers = [Container(x) for x in list(container)]
    try: priority_domain = domains[0][0] 
    except IndexError: priority_domain = None

    # Build the server object
    if type == 'bare':
        server = Bare(name, provider, priority_domain, containers)
        ctx.obj['resources'].append(server)
    elif type == 'teamserver':
        server = Teamserver(name, provider, priority_domain, containers)
        ctx.obj['resources'].append(server)
    elif type == 'categorize':
        server = Categorize(name, provider, priority_domain, redirect_to)
        ctx.obj['resources'].append(server)
    elif type == 'lighthouse':
        server = Lighthouse(name, provider, priority_domain)
        ctx.obj['resources'].append(server)
    elif type == 'redirector':
        server = Redirector(name, provider, priority_domain, redirector_type, redirect_to)
        # Check how many domains we have set
        if len(domains) == 0:
            LogHandler.error('No domains provided for redirector, this may cause issues with your redirector (depending on the protocol)')
        elif redirector_type == 'dns':
            # Get the domain record and edit the server object
            main_domain = domains.pop(0)
            base_domain = Domain.get_domain(main_domain[0])
            ns_domain_value = f'ns1.{base_domain}'
            server.domain = ns_domain_value
            ctx.obj['resources'].append(server)

            # Build the Domain objects
            ctx.invoke(domain, provider=main_domain[1], domain=main_domain[0], type='NS', value=ns_domain_value)
            ctx.invoke(domain, provider=main_domain[1], domain=ns_domain_value, type='A', server_name=server.uuid)
        else:
            ctx.obj['resources'].append(server)
    else:
        LogHandler.critical(f'Got unknown server type: "{type}"')

    # Check if we were given a domain
    for domain_record in domains:
        ctx.invoke(domain, provider=domain_record[1], domain=domain_record[0], type='A', server_name=server.uuid)


@click.command(name='domain')
@click.option('--provider', '-p', required=True, type=click.Choice(TerraformObject.get_terraform_mappings(simple_list=True, type='domain')), help='''
    The cloud/infrastructure provider to use when creating the server
    ''')
@click.option('--domain', '-d', required=True, type=str, help='''
    FQDN to use in creation of an record type "<type>" (if no subdomain provided, the root will be used)
    ''')
@click.option('--type', '-t', type=str, default='A', help='''
    The type of record to create
    ''')
@click.option('--value', '-v', required=False, type=str, help='''
    Value of the record (use this if you have a STATIC DNS record that doesn't depend on dynamic data returned from Terraform)
    ''')
@click.option('--server_name', '-sN', required=False, type=str, help='''
    Name / UUID of the server resource whose public IP that you want to populate the value of the record (a resource with this name / uuid must exist in the build)
    ''')
@click.pass_obj
def domain(ctx_obj, provider, domain, type, value, server_name):
    """Create a domain resource"""

    # Build a domain object so it get's parsed properly
    domain_obj = Domain(domain, provider)

    # Check if we have this domain already
    domain_zone = f'{ domain_obj.domain }'
    if domain_zone not in ctx_obj['required_domains']:
        LogHandler.debug(f'Domain zone not found for { provider }, I will add one to the build for you')
        ctx_obj['required_domains'].add(domain_zone)
        ctx_obj['resources'].append(domain_obj)
    
    domain_obj_index = get_domain_zone_index_from_build(domain_zone)

    # Check that we have at least the value OR server_name
    if not value and server_name:
        server = get_server_from_uuid_or_name(server_name)
        value = f'{ server.terraform_resource_name }.{ server.uuid }.{ server.terraform_ip_reference }'
    elif value and server_name:
        LogHandler.critical(f'Domain expects to have either "-v" / "--value" OR "-sN" / "--server_name" to be set. Make sure one or the other is set when building a domain')
    else:
        # Wrap the value in double quotes (if it is not a dynamic terraform reference, it should be represented as a string in the plan)
        value = f'"{ value }"'

    # Add the domain record to the domain object
    subdomain = Domain.get_subdomain(domain)
    ctx_obj['resources'][domain_obj_index].add_record(subdomain, type, value)


if __name__ == "__main__":
    # Add the server subcommands to create and add groups
    create.add_command(server)
    create.add_command(domain)
    add.add_command(server)
    add.add_command(domain)

    # Run the CLI entrypoint
    cli()