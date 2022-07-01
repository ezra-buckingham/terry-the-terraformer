#!/usr/bin/python3
import json
import logging
import re
import sys
import uuid
import click
import yaml
import traceback
from pathlib import Path

# Local Imports
from core import *
import utils


def build_infrastructure(ctx_obj):
    """This is the main body.
    After click is complete, come here and work through the other steps.
    Easier to follow execution flow from a main function than it is to jump
    from function to function.
    """

    operation_name = ctx_obj["operation"]
    build_config_file = Path(ctx_obj['op_directory'].joinpath('.terry/build_config.yml'))
    build_uuid = ''

    # Check for project directory
    if not ctx_obj['project_directory'].exists():
        LogHandler.warn('Project directory not found, creating that now...')
        ctx_obj['project_directory'].mkdir()

    # Check for certificates directory
    if not ctx_obj['certificates_directory'].exists():
        LogHandler.warn('Certificates directory not found in project directory, creating that now...')
        ctx_obj['certificates_directory'].mkdir()

    # Check that the Operation Directory exists, along with all required other files
    if not ctx_obj['op_directory'].exists():
        LogHandler.info('Building operation directory structure, ssh keys, and remote configuration (if applicable) now...')
        ctx_obj['op_directory'].mkdir()
        # Does not account for situations where op_directory exists but these children do not
        for path in ['.terry', 'terraform/', 'ansible/inventory/', 'ansible/extra_vars', 'nebula/']:
            ctx_obj['op_directory'].joinpath(path).mkdir(parents=True)

        # Generate the SSH Keys and write them to disk
        public_key, private_key = utils.generate_ssh_key()

        # Write the private ssh key to the folder
        file_path = operation_name + '_key'
        key_file = Path(ctx_obj['op_directory'].joinpath(file_path))
        pub_key_file = Path(ctx_obj['op_directory'].joinpath(file_path + '.pub'))

        # Write the keys and change perms
        pub_key_file.write_bytes(public_key)
        key_file.write_bytes(private_key)
        os.chmod(str(key_file), 0o700)

        # Create the config for the build
        config = { 'uuid': str(uuid.uuid4()) }
        build_config_yaml = yaml.safe_dump(config)
        build_config_file.write_text(build_config_yaml)

        # Check to see if any remote configurations were defined
        for remote_config in ctx_obj["ansible_configuration"]["remote"]:
            LogHandler.info(f'Found name of "{ remote_config["name"] }" for a remote configuration, loading it now...')
            remote_config = RemoteConfigurationHandler(remote_config["name"], remote_config["repo_url"], remote_config["username"], remote_config["personal_access_token"])

            # Write out the configuration to the op_directory
            configuration_location = ctx_obj['op_directory'].joinpath(f'ansible/extra_vars/{ remote_config.configuration_name }.yml')
            LogHandler.debug(f'Writing out "{ remote_config.configuration_name }" remote configuration to "{ configuration_location }"')
            yaml_contents = yaml.dump(remote_config.configuration)
            configuration_location.write_text(yaml_contents)

    # If the directory exists, we must check the flags supplied to see what Terry should do
    else: 
        base_message = f'A plan with the name "{ operation_name }" already exists in "{ ctx_obj["op_directory"] }"'
        if ctx_obj['force']:
            LogHandler.warn(f'{base_message}. Continuing since "-f" / "--force" was supplied.')
        elif ctx_obj['modify']:
            # TODO Add logic to modify a deployment
            raise NotImplementedError
        else:
            LogHandler.critical(f'{base_message}. Please choose a new operation name, new deployment path, or use the "-f" / "--force" flag.')
    
    # Load the build config
    if build_config_file.exists():
        build_config = build_config_file.read_text()
        build_config_yaml = yaml.safe_load(build_config)
        build_uuid = build_config_yaml['uuid']
    else:
        LogHandler.warn(f'No build configuration found for "{operation_name}", it was likely built with an older version of Terry. Some features may not be available due to this.')

    # Load the public key so we can build the ssh key resources later
    public_key, private_key = utils.get_operation_ssh_key_pair(ctx_obj)
    ctx_obj['ssh_pub_key'] = public_key

    # Read in the Terraform mapping and give it to the click object
    ctx_obj['terraform_mappings'] = utils.get_terraform_mappings()

    


    utils.build_ansible_inventory(ctx_obj)

    # Create the terraform handler object and build plan
    LogHandler.info('Building Terraform plan')
    terraform_handler = TerraformHandler(ctx_obj['binaries']['terraform'].path, ctx_obj['op_directory'])
    plan = utils.build_plan(ctx_obj)

    # Write the plan to a file
    file_path = 'terraform/' + ctx_obj['operation'] + '_plan.tf'
    plan_file = ctx_obj['op_directory'].joinpath(file_path)
    LogHandler.debug('Writing Terrafom plan to disk')
    plan_file.write_text(plan)
        
    # Apply plan
    LogHandler.info('Applying Terrafom plan')
    return_code, stdout, stderr, terraform_plan = terraform_handler.apply_plan(auto_approve=ctx_obj['auto_approve'])

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
    utils.map_values(ctx_obj, results)

    # Configure Nebula
    if not ctx_obj['no_nebula']:
        LogHandler.info('Setting up Nebula configurations and certificates')
        nebula_handler = NebulaHandler(ctx_obj['binaries']['nebula'].path, ctx_obj['nebula_subnet'], ctx_obj['op_directory'])
        # Check if we have a root cert yet
        if ctx_obj['op_directory'].joinpath('nebula/ca.crt').exists():
            LogHandler.info('Nebula root certificate found, skipping generating new certificate')
        else:
            nebula_handler.generate_ca_certs()
        for resource in ctx_obj['all_resources']:
            # Check if we have a host certificate, if so, delete it
            if ctx_obj['op_directory'].joinpath(f'nebula/{resource.name}.crt').exists():
                LogHandler.info(f'Nebula host certificate found for "{resource.name}", deleting existing and generating new certificate key pair')
                ctx_obj['op_directory'].joinpath(f'nebula/{resource.name}.crt').unlink()
                ctx_obj['op_directory'].joinpath(f'nebula/{resource.name}.key').unlink()
            # Generate the new certificate
            assigned_nebula_ip = nebula_handler.generate_client_cert(resource.name)
            resource.nebula_ip = assigned_nebula_ip
            # Assign the lighthouse values so they can go into the config
            if isinstance(resource, Lighthouse):
                ctx_obj['lighthouse_nebula_ip'] = assigned_nebula_ip
                ctx_obj['lighthouse_public_ip'] = resource.public_ip
    else:
        LogHandler.info('Skipping setting up Nebula configurations and certificates')

    # Create the pickle file for the built resources
    LogHandler.debug('Building a pickle of the current resources and Ansible inventory')
    #utils.build_resource_pickle(ctx_obj)    
    utils.build_ansible_inventory(ctx_obj)

    # Configure Ansible
    LogHandler.debug('Setting up Ansible environment')
    ansible_working_dir = ctx_obj['op_directory'].joinpath('ansible')
    ansible_handler = AnsibleHandler(ssh_key=private_key, working_dir=ansible_working_dir)

    # Run all the Prep playbooks
    root_playbook_location = '../../../playbooks'
    ansible_handler.run_playbook(f'{ root_playbook_location }/wait-for-system-setup.yml')
    ansible_handler.run_playbook(f'{ root_playbook_location }/prep-all-systems.yml')

    # Run all the server-type specific playbooks
    ansible_handler.run_playbook(f'{ root_playbook_location }/setup-containers.yml')
    ansible_handler.run_playbook(f'{ root_playbook_location }/setup-redirector.yml')
    ansible_handler.run_playbook(f'{ root_playbook_location }/setup-categorization.yml')
    ansible_handler.run_playbook(f'{ root_playbook_location }/setup-mailserver.yml')
    
    LogHandler.info('Ansible setup complete')
    ctx_obj['end_time'] = utils.get_formatted_time()

    # Let the team know its ready to go
    if not ctx_obj['quiet'] and ctx_obj['slack_webhook_url']:
        slack_handler = SlackHandler(ctx_obj['slack_webhook_url'])
        slack_handler.send_success(ctx_obj)

    LogHandler.info('Script complete! Enjoy the tools you tool!')


@click.pass_context
def validate_build_request(ctx):
    """Validates the build and accessibility to required binaries to run"""
    
    # Validate some of the options
    if not ctx.obj['quiet'] and not ctx.obj['slack_webhook_url']:
        LogHandler.warn(f'Quiet field "--quiet" not supplied, but no notification webhooks were found in the configuration file. Terry will be quiet :)')

    # If running destroy as one of the commands, that can be the only command present
    if ('destroy' in ctx.obj['commands'] and len(ctx.obj['commands']) > 1):
        LogHandler.critical(f'Other commands found along with the "destroy" command. If using "destroy," you can only use it as a standalone command.')
        
    # If there is a Categorization server being built, it must be the only resource
    if len([ x for x in ctx.obj["all_resources"] if isinstance(x, Categorize) ]) >= 1 and len(ctx.obj["resources"]) > 1:
        LogHandler.critical(f'Ensure the categorization server is the only resource being made in a single deployment')

    
    # If using Nebula, check we have everything needed for the build
    lighthouses = [ x for x in ctx.obj["all_resources"] if isinstance(x, Lighthouse) ]
    # Check if we want to build nebula and if destory is not the command
    if not ctx.obj['no_nebula'] and 'destroy' not in ctx.obj['commands']:
        # Check to make sure we only have one lighthouse in the build
        if len(lighthouses) > 1:
            LogHandler.critical('Multiple Lighthouses found in build, Terry can only handle building one per deployment')
    
        if len(lighthouses) == 0:
            LogHandler.warn('Nebula configured for this build, but no Lighthouses found. Either use the "-N" / "--no_nebula" flag or I can build one for you now.')
            response = LogHandler.confirmation('Would you like me to add a Lighthouse to the current build?')
            if response:
                lighthouse_name = create_resource_name('lighthouse')

                # Now get the provider from the user
                provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')
                while provider not in utils.get_implemented_providers(simple_list=True):
                    LogHandler.error(f'Invalid provider provided: {provider}. Please enter one of the following providers: {utils.get_implemented_providers(simple_list=True)}', is_fatal=False)
                    provider = LogHandler.get_input('What provider do you want the build the lighthouse with?')

                lighthouse = Lighthouse(lighthouse_name, provider, None)
                ctx.obj["resources"].insert(0, lighthouse)
                ctx.obj["all_resources"].insert(0, lighthouse)
            else:
                LogHandler.warn('Opting out of Nebula for this build')
                ctx.obj['no_nebula'] = not ctx.obj['no_nebula']

        # Need to check we have enough IPs in the IP space
        # TODO
    

    # Check if we said to have no nebula, but manually built a lighthouse
    if ctx.obj['no_nebula'] and len(lighthouses) > 0:
        LogHandler.warn('Lighthouse found in build along with "-N / --no_nebula"')
        response = LogHandler.confirmation('Did you want to use Nebula for this build?')
        if response:
            ctx.obj['no_nebula'] = not ctx.obj['no_nebula']


    # Make sure we have a unique list of providers and registrars so we can validate we have credentials for each of the providers
    required_providers = set()
    container_registry_credentials_checked = False

    for resource in ctx.obj['all_resources']:
        required_providers.add(resource.provider)

        # Check to see if we have a domain map and that we have valid registars
        if resource.domain_map:
            for domain in resource.domain_map:
                registrars = utils.get_implemented_providers(simple_list=True, is_registrar=True)
                if not domain.provider in registrars:
                    LogHandler.critical(f'Registrar of {domain.provider} not implemented. Please implement it and rerun or change the registrar.')
                else: 
                    required_providers.add(domain.provider)
        
        # Check the containers of the resources
        if hasattr(resource, 'containers') and len(resource.containers):
            for container in resource.containers:
                # Check if we have already looked for container registry creds
                if not container_registry_credentials_checked:
                    LogHandler.debug('Containers found in build, checking for container registry credentials now')
                    # First Validate we were given registry creds
                    utils.check_for_required_value(ctx.obj, 'container_registry')
                    utils.check_for_required_value(ctx.obj, 'container_registry_username')
                    utils.check_for_required_value(ctx.obj, 'container_registry_password')
                    container_registry_credentials_checked = True
                # Now validate the actual container runtime args needed
                container.validate(ctx.obj)

    
    ctx.obj['required_providers'] = [ Provider(provider) for provider in required_providers ]

    LogHandler.debug('Build looks good! Terry, take it away!')

@click.pass_context
def create_resource_name(ctx, type):
    """Helper function to create a resource name"""
    return type + (str([x.server_type for x in ctx.obj['all_resources']].count(type) + 1))


@click.group(chain=True, context_settings=dict(help_option_names=['-h', '--help', '--how-use', '--freaking-help-plz', '--stupid-terry']))
@click.option('-c', '--config', default="config.yml", type=click.Path(exists=True), help='''
    Path to configuration file in .yml format
    ''')
@click.option('-o', '--operation', required=True, help='''
    Name for project or operation
    ''')
@click.option('-a', '--auto_approve', is_flag=True, default=False, help='''
    Auto approve the Terraform apply commands (only works when building, destory will auto-approve by default)
    ''')
@click.option('-m', '--modify', is_flag=True, default=False, help='''
    Instead of creating a whole new deployment, modify an existing one with the same operation name
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
@click.option('-l', '--log_file', default='./log_terry.log', help='''
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
def cli(ctx, config, operation, auto_approve, modify, force, quiet, verbose, log_file, no_nebula,
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

    # Change verbosity level
    if verbose: """"""

    # Build list of possible commands (e.g. teamserver, redirector) based on Click context
    command_list = list(ctx.to_info_dict()['command']['commands'].keys())
    commands = [c for c in sys.argv[1:] if c in command_list]

    # Open and parse the config file
    with open(config, 'r') as config_file:
        conf_dict = yaml.safe_load(config_file.read())

    # Get each section values from config file
    global_conf = conf_dict.get('global', {})
    ansible_configurations = conf_dict.get('ansible_configuration', [])
    slack_conf = conf_dict.get('slack', {})
    
    # Parse through the global values
    project_directory = global_conf.get('project_directory')
    terraform_path = global_conf.get('terraform_path')
    ansible_path = global_conf.get('ansible_path')
    nebula_path = global_conf.get('nebula_path')
    nebula_subnet = global_conf.get('nebula_subnet')

    # Slack Values
    slack_webhook_url = slack_conf.get('webhook_url')

    # Get the operation directory
    op_directory = Path(project_directory).joinpath(operation)

    # Create a context (ctx) object (obj) for Click to pass around that stores relevant information
    # Only add the things that come from the config file, all the other values will come from the params
    ctx.ensure_object(dict)
    ctx.obj['start_time'] = utils.get_formatted_time()
    ctx.obj['command_run'] = command_run
    ctx.obj['project_directory'] = Path(project_directory)
    ctx.obj['certificates_directory'] = Path(project_directory).joinpath('.certificates')
    ctx.obj['commands'] = commands  # The list of commands (e.g. teamserver, redirector) passed to infrared.py
    ctx.obj['config_location'] = config  # Path to configuration file
    ctx.obj['config_values'] = conf_dict
    ctx.obj['nebula_subnet'] = nebula_subnet
    ctx.obj['safe_operation_name'] = re.sub(r'[^a-zA-Z]', '', operation) # Strip out only letters
    ctx.obj['op_directory'] = op_directory
    ctx.obj['ansible_configuration'] = ansible_configurations
    ctx.obj['implemented_providers'] = utils.get_implemented_providers() 
    ctx.obj['resources'] = []  # List of resources (teamservers, redirectors) constituting the infrastructure
    ctx.obj['all_resources'] = []  # List of resources (teamservers, redirectors), including redirectors (which are children objects of a resource)
    ctx.obj['slack_webhook_url'] = slack_webhook_url
    ctx.obj['binaries'] = {
        'terraform': BinaryExecutableHandler('terraform', terraform_path),
        'ansible': BinaryExecutableHandler('ansible', ansible_path)
    }
    if not no_nebula: ctx.obj['binaries']['nebula'] = BinaryExecutableHandler('nebula', nebula_path)

    ctx.obj = {**ctx.obj, **ctx.params}

@cli.command(name='server')
@click.option('--provider', '-p', required=True, type=click.Choice(utils.get_implemented_providers(simple_list=True)), help='''
    The cloud/infrastructure provider to use when creating the server
    ''')
@click.option('--type', '-t', required=True, type=click.Choice(utils.get_implemented_server_types()), help='''
    The type of server to create
    ''')
@click.option('--container', '-cT', type=str, multiple=True, help='''
    Containers to install onto the server
    ''')
@click.option('--redirector_type', '-rT', type=str, multiple=True, help='''
    Type redirector to build, with optional domain specified for that redirector formatted as "<provider>:<protocol>:<domain>:<registrar>" 
    (Example: https redirector in AWS at domain example.com with registrar AWS should be "aws:https:example.com:aws)"
    ''')
@click.option('--redirect_to', '-r2', type=str, help='''
    Domain to redirect to / impersonate (for categorization usually)
    ''')
@click.option('--domain', '-d', multiple=True, type=str, help='''
    Domain and registrar to use in creation of an A record for the resource formatted as "<domain>:<registrar>" (Example: domain example.com with registrar aws should be "example.com:aws)"
    ''')
@click.pass_context
def server(ctx, provider, type, redirector_type, redirect_to, domain, container):
    """Create a server resource"""

    # The name is operationname_lighthouseN, where N is number of existing redirectors + 1 and it must be unique across all deployments since some APIs will error out if they aren't unique (even in different deployments)
    name = create_resource_name(type)
    resources = []

    # Build the redirector objects
    redirectors = []
    for redirector in redirector_type:
        # Parse out the defined types
        redirector_definition = redirector.split(':')

        # Check provided length
        if len(redirector_definition) < 2:
            LogHandler.critical(f'Invalid redirector definition provider provided: "{redirector}". Please use one of the proper format of "<provider>:<protocol>:<domain>:<registrar>" for the redirector.')

        redirector_provider = redirector_definition[0]

        # Check if provider is in our list of implemented providers
        if redirector_provider not in utils.get_implemented_providers(simple_list=True):
            LogHandler.critical(f'Invalid redirector provider provided: "{provider}". Please use one of the implemented redirectors: {utils.get_implemented_providers(simple_list=True)}')

        proto = redirector_definition[1]
        redirector_name = f'{name}-{proto}-{create_resource_name("redir")}'
        
        # Check if protocol supported as given by the user
        if proto not in utils.get_implemented_redirectors():
            LogHandler.critical(f'Invalid redirector type provided: "{proto}". Please use one of the implemented redirectors: {utils.get_implemented_redirectors()}')

        # Try parsing out a domain as provided
        redirector_domain_map = []
        if len(redirector_definition) >= 3:
            redirector_domain = Domain(redirector_definition[2], redirector_definition[3])
            redirector_domain = utils.build_resource_domain_map(proto, redirector_domain)
            redirector_domain_map.append(redirector_domain)
        else:
            if len(redirector_definition) == 2:
                LogHandler.warn(f'Redirector provided without domain: "{redirector}". Building without any domain.')
            else:
                LogHandler.error(f'Invalid redirector provided: "{redirector}". Please make sure you define EITHER only the "<provider>:<protocol>" OR the "<provider>:<protocol>:<domain>:<registrar>"')

        redirector = Redirector(redirector_name, redirector_provider, redirector_domain_map, proto, None)
        redirectors.append(redirector)
        
    # Build the domain object
    domain_map = []
    if domain:
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
        if domain:
            LogHandler.warn('Domain provided for a Teamserver without any redirectors specified')
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
    server.redirectors = redirectors
    resources.append(server)
    ctx.obj['resources'] += resources
    ctx.obj['all_resources'] += resources + redirectors

    # If we have processed all the commands, pass along to next function
    ctx.obj['commands'].pop()
    if not ctx.obj['commands']:
        try:
            validate_build_request()
            build_infrastructure(ctx.obj)
        except Exception as e:
            message = f"Some exception occurred in the execution of Terry. Please review the logs."
            if not ctx.obj['quiet'] and ctx.obj['slack_webhook_url']:
                slack_handler = SlackHandler(ctx.obj['slack_webhook_url'])
                slack_handler.send_error(message)
            message += '\n' + traceback.format_exc()
            LogHandler.critical(message)


@cli.command(name='destroy')
@click.option('--recursive', '-r', is_flag=True, default=False, help='''
    Destroy all files and folders associated with the deployment as well
    ''')
@click.pass_context
def destroy(ctx, recursive):
    """ Destroy the infrastructure built by terraform"""

    LogHandler.info(f'Destroying the "{ ctx.obj["operation"] }" plan')
    # First validate the request, as we may be missing dependencies
    validate_build_request()
    tf_path = ctx.obj['binaries']['terraform']
    terraform_handler = TerraformHandler(tf_path.path, ctx.obj['op_directory'])
    success, stdout, stderr = terraform_handler.destroy_plan()

    if success or success is None:
        if success:
            LogHandler.info('Terraform resource destruction complete')
            # Let the team know its ready to go
            if not ctx.obj['quiet'] and ctx.obj['slack_webhook_url']:
                slack_handler = SlackHandler(ctx.obj['slack_webhook_url'])
                slack_handler.send_destroy_success(ctx.obj)
        else:
            LogHandler.warn('No Terraform state was found, so no destruction to perform')
        if recursive:
            if ctx.obj['op_directory'].exists():
                LogHandler.warn(f'Destroying all files associated with "{ ctx.obj["operation"] }"')
                utils.remove_directory_recursively(ctx.obj["op_directory"])
                LogHandler.info('File destruction complete')
            else:
                LogHandler.critical(f'No files or folder found for "{ ctx.obj["operation"] }"', True)
    else:
        LogHandler.critical(f'Error when destroying "{ ctx.obj["operation"] }"\r\nSTDOUT: {stdout}\r\nSTDERR: {stderr}', True)
    

if __name__ == "__main__":
    cli()
