#!/usr/bin/python3
from email.policy import default
import json
import logging
import os
import re
import sys
import click
import yaml
import traceback
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
    ctx.obj['required_providers'] = set()
    ctx.obj['server_resources'] = []  # List of resources (teamservers, redirectors) constituting the infrastructure
    ctx.obj['all_resources'] = []  # List of resources (teamservers, redirectors), including redirectors (which are children objects of a resource)
    
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
    """Destroy the infrastructure built by terraform"""

    LogHandler.info(f'Destroying the "{ ctx_obj["operation"] }" plan')

    # Prepare all required handlers
    prepare_handlers()

    # Read in the build config
    # TODO
    validate_credentials(check_containers=False)

    success, stdout, stderr = ctx_obj['terraform_handler'].destroy_plan()

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
                LogHandler.info('File destruction complete')
            else:
                LogHandler.critical(f'No files or folder found for "{ ctx_obj["operation"] }"', True)
    else:
        LogHandler.critical(f'Error when destroying "{ ctx_obj["operation"] }"\r\nSTDOUT: {stdout}\r\nSTDERR: {stderr}', True)


@cli.group(name='create', chain=True)
@click.pass_context
def create(ctx):
    """Create a new deployment"""

    LogHandler.info(f'Creating the "{ ctx.obj["operation"] }" plan')

    # Prepare all required handlers
    prepare_handlers()

    operation_name = ctx.obj["operation"]
    build_config_file = Path(ctx.obj['op_directory']).joinpath('.terry/build_config.yml')
    build_uuid = ''

    # Check for certificates directory
    certificates_directory = Path(ctx.obj['project_directory']).joinpath('.certificates')
    if not certificates_directory.exists():
        LogHandler.warn('Certificates directory not found in project directory, creating that now...')
        certificates_directory.mkdir(parents=True)

    # If the operation directory doesn't exist, create the skeleton for it as well as all other resources required
    if not Path(ctx.obj['op_directory']).exists():
        LogHandler.info('Building operation directory structure, ssh keys, and remote configuration (if applicable)')
        Path(ctx.obj['op_directory']).mkdir()
        # Does not account for situations where op_directory exists but these children do not
        for path in ['terraform/', 'ansible/inventory/', 'ansible/extra_vars', 'nebula/']:
            Path(ctx.obj['op_directory']).joinpath(path).mkdir(parents=True)

        # Generate the SSH Keys and write them to disk
        public_key, private_key = generate_ssh_key()
        key_file = Path(ctx.obj['op_directory']).joinpath(f'{operation_name}_key')
        pub_key_file = Path(ctx.obj['op_directory']).joinpath(f'{operation_name}_key.pub')
        pub_key_file.write_bytes(public_key)
        key_file.write_bytes(private_key)
        os.chmod(str(key_file), 0o700)

        # Check to see if any remote configurations were defined
        for remote_config in ctx.obj["ansible_configuration"]["remote"]:
            if not remote_config["name"] or len(remote_config["name"]) == 0:
                LogHandler.error('Found blank entry for a remote configuration in the config file, skipping blank entry...')
                continue

            LogHandler.info(f'Found name of "{ remote_config["name"] }" for a remote configuration, loading it now...')
            remote_config = RemoteConfigurationHandler(remote_config["name"], remote_config["repo_url"], remote_config["username"], remote_config["personal_access_token"])

            # Write out the configuration to the op_directory
            configuration_location = Path(ctx.obj['op_directory']).joinpath(f'ansible/extra_vars/{ remote_config.configuration_name }.yml')
            LogHandler.debug(f'Writing out "{ remote_config.configuration_name }" remote configuration to "{ configuration_location }"')
            yaml_contents = yaml.dump(remote_config.configuration)
            configuration_location.write_text(yaml_contents)

    # If the directory exists, we must check the flags supplied to see what Terry should do
    else: 
        LogHandler.warn(f'A plan with the name "{ operation_name }" already exists in "{ ctx.obj["op_directory"] }"')
        if not Path(ctx.obj["op_directory"]).joinpath('terraform/terraform.tfstate').exists():
            LogHandler.warn(f'No terraform state found for "{ operation_name }", continuing with build regardless of "-f" / "--force" flag.')
        elif not ctx.obj['force']:
            LogHandler.critical('Please choose a new operation name, new deployment path, or use the "-f" / "--force" flag. Just note that when using the force flag you may overwrite existing Terraform resources.')
        else:
            LogHandler.warn('Continuing since "-f" / "--force" was supplied.')
        
    # Load the build config
    if build_config_file.exists():
        build_config = build_config_file.read_text()
        build_config_yaml = yaml.safe_load(build_config)
        build_uuid = build_config_yaml['uuid']
    else:
        LogHandler.warn(f'No build configuration found for "{operation_name}", it was likely built with an older version of Terry. Some features may not be available due to this.')


@create.result_callback()
@click.pass_obj
def build_infrastructure(ctx_obj, resources):
    # Make sure we have credentials for each of the providers
    validate_credentials(check_containers=True)

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
    
    # Check if we said to have no nebula, but manually built a lighthouse
    if ctx_obj['no_nebula'] and len(lighthouses) > 0:
        LogHandler.warn('Lighthouse found in build along with "-N / --no_nebula"')
        response = LogHandler.confirmation('Did you want to use Nebula for this build?')
        if response:
            ctx_obj['no_nebula'] = not ctx_obj['no_nebula']

    LogHandler.debug('Build looks good! Terry, take it away!')

    # Load the public key so we can build the ssh key resources later
    public_key, private_key = get_operation_ssh_key_pair(ctx_obj)
    ctx_obj['ssh_pub_key'] = public_key

    # Create the terraform plan and build it 
    LogHandler.info('Building Terraform plan')
    plan = TerraformHandler.build_plan(ctx_obj)
    plan_file = Path(ctx_obj['op_directory']).joinpath(f'terraform/{ ctx_obj["operation"] }_plan.tf')
    LogHandler.debug('Writing Terrafom plan to disk')
    plan_file.write_text(plan)
    LogHandler.info('Applying Terrafom plan')
    return_code, stdout, stderr, terraform_plan = ctx_obj['terraform_handler'].apply_plan(auto_approve=ctx_obj['auto_approve'])

    if str(return_code) == '1':
        base_message = 'Terraform returned an error:'
        if terraform_plan is None:
            LogHandler.critical(f'{base_message} {stderr}', True)
        else:
            LogHandler.critical(f'{base_message} No stderr was returned, this is likely a logic issue or partial error within the plan. (Example: if AWS, a bad AMI given the region)', True)
    else:
        LogHandler.info('Terraform apply successful!')
        if str(return_code) == '0':
            LogHandler.debug('Terraform returned "0", thus Terraform may not have actually made any changes')
        # Create a json of the results from the Terraform state
        results = json.loads(stdout)['values']['root_module']['resources']

    # Map the results from terraform.show() results back into the resource objects
    TerraformHandler.map_values(ctx_obj, results)

    # Configure Nebula
    if not ctx_obj['no_nebula']:
        LogHandler.info('Setting up Nebula configurations and certificates')
        ctx_obj['nebula_handler'].generate_ca_certs()
        for resource in ctx_obj['all_resources']:
            assigned_nebula_ip = ctx_obj['nebula_handler'].generate_client_cert(resource.name)
            resource.nebula_ip = assigned_nebula_ip
            # Assign the lighthouse values so they can go into the config
            if isinstance(resource, Lighthouse):
                ctx_obj['lighthouse_nebula_ip'] = assigned_nebula_ip
                ctx_obj['lighthouse_public_ip'] = resource.public_ip
    else:
        LogHandler.info('Skipping setting up Nebula configurations and certificates')

    # Create the pickle file for the built resources
    LogHandler.debug('Building Ansible inventory')  
    AnsibleHandler.build_ansible_inventory(ctx_obj)

    # Run all the Prep playbooks
    root_playbook_location = '../../../playbooks'
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/wait-for-system-setup.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/prep-all-systems.yml')

    # Run all the server-type specific playbooks
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-containers.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-redirector.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-categorization.yml')
    ctx_obj['ansible_handler'].run_playbook(f'{ root_playbook_location }/setup-mailserver.yml')
    
    LogHandler.info('Ansible setup complete')
    ctx_obj['end_time'] = get_formatted_time()
    ctx_obj['slack_handler'].send_success(ctx_obj)


@cli.group(name='add')
@click.pass_obj
def add():
    """Add to an existing deployment"""
    pass


@cli.group(name='reconfigure')
@click.pass_obj
def reconfigure():
    """Reconfigure a deployment by refreshing Terraform state and re-running playbooks against each host"""
    pass


#################################################################################################################
# Subcommands 
#################################################################################################################   


@click.command(name='server')
@click.option('--provider', '-p', required=True, type=click.Choice(TerraformObject.get_terraform_mappings(simple_list=True)), help='''
    The cloud/infrastructure provider to use when creating the server
    ''')
@click.option('--type', '-t', required=True, type=click.Choice(get_implemented_server_types()), help='''
    The type of server to create
    ''')
@click.option('--name', '-n', required=True, type=str, default=generate_random_name(), help='''
    Name of the server (used for creating corresponding DNS records if you use the "domain" command)
    ''')
@click.option('--container', '-cT', type=str, multiple=True, help='''
    Containers to install onto the server
    ''')
@click.option('--redirector_type', '-rT', type=str, multiple=True, help='''
    Type redirector to build, with optional domain specified for that redirector formatted as "<provider>:<protocol>:<domain>:<registrar>" 
    (Example: https redirector in AWS at domain example.com with registrar AWS should be "aws:https:example.com:aws)"
    ''')
@click.option('--redirect_to', '-r2', type=str, help='''
    Domain to redirect to / impersonate (only deployed with categorize servers)
    ''')
@click.option('--domain', '-d', multiple=True, type=str, help='''
    Domain and registrar to use in creation of an A record for the resource formatted as "<domain>:<registrar>" (Example: domain example.com with registrar aws should be "example.com:aws)"
    ''')
@click.pass_obj
def server(ctx_obj, provider, type, name, redirector_type, redirect_to, domain, container):
    """Create a server resource"""

    resources = []

    # Build the redirector objects
    for redirector in redirector_type:
        # Parse out the defined types
        redirector = Redirector.from_shorthand_notation(redirector)
        resources.append(redirector)
        
    # Build the domain object
    domain_map = []
    for item in domain:
        item = item.split(':')
        if len(item) != 2: 
            LogHandler.critical(f'Domain expects be formated as "<domain>:<registrar>" (example: "example.com:aws")')
        domain = Domain(item[0], item[1])
        domain_map.append(domain)

    # Build the container objects
    containers = [Container(x) for x in list(container)]

    # Build the server object
    if type == 'teamserver':
        server = Teamserver(name, provider, domain_map, containers)
    elif type == 'redirector':
        server = Redirector(name, provider, domain_map, redirector_type, redirect_to)
    elif type == 'categorize':
        server = Categorize(name, provider, domain_map, redirect_to)
    elif type == 'bare':
        server = Bare(name, provider, domain_map, containers)
    elif type == 'lighthouse':
        server = Lighthouse(name, provider, domain_map)
    else:
        LogHandler.critical(f'Got unknown server type: "{type}"')

    # Provide the server with the redirectors and append to build
    resources.append(server)
    ctx_obj['server_resources'] += resources
    ctx_obj['all_resources'] += resources

    return


@click.command(name='domain')
@click.option('--provider', '-p', required=True, type=click.Choice(TerraformObject.get_terraform_mappings(simple_list=True)), help='''
    The cloud/infrastructure provider to use when creating the server
    ''')
@click.option('--domain', '-d', required=True, type=str, help='''
    FQDN to use in creation of an record type <type>"
    ''')
@click.option('--type', '-t', type=str, default='A', help='''
    The type of record to create
    ''')
@click.option('--value', '-v', required=True, type=str, help='''
    Value of the record (use this if you have a STATIC DNS record that doesn't depend on dynamic data returned from Terraform)
    ''')
@click.option('--points_to', '-p2', required=True, type=str, help='''
    Name of the resource's public IP that you want to populate the value of the record (a resource with this name must exist in the build)
    ''')
@click.pass_obj
def domain(ctx_obj, provider, type, redirector_type, redirect_to, domain, container):
    """Create a domain record"""

    


if __name__ == "__main__":
    # Add the server subcommands to create and add groups
    create.add_command(server)
    create.add_command(domain)
    add.add_command(server)
    add.add_command(domain)

    # Run the CLI entrypoint
    cli()

    # Log the completion
    LogHandler.info('Terry run complete! Enjoy the tools you tool!')