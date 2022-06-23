# Terry the Terraformer

Python CLI tool to to build red team infrastructure using Terraform, Ansible, and Docker. Once deployed, all resources can be integrated into a [Nebula](https://github.com/slackhq/nebula) network for secure communications across nodes.

## Documentation

Most documentation can be found in the [Wiki](https://github.com/ezra-buckingham/terry-the-terraformer/wiki). If there is missing documentation or unclear documentation, please create an issue.

## Getting Started

Getting started is relatively easy. Follow the [Getting Started](https://github.com/ezra-buckingham/terry-the-terraformer/wiki/Getting-Started) instructions to begin using Terry.

## Usage



Terry was built to ensure a Red Team can deploy complex infrastructure in a cloud-agnostic way without needing to understand the intricacies of all the various tools like Ansible, Terraform, or Docker. The intended way to use Terry is to use the `terry.py` file, but since at the core Terry uses third-party / open source tools, an operator may choose to also use Terry just to create a terraform plan or just to run ansible playbooks (which can be run independently and documentation on how to do so is below).

```
Usage: terry.py [OPTIONS] COMMAND1 [ARGS]... [COMMAND2 [ARGS]...]...

  Terry will help you with all of your red team infrastructure needs! He's not
  magic... he's Terry!

Options:
  -c, --config PATH               Path to configuration file in .yml format
  -o, --operation TEXT            Name for project or operation  [required]
  -a, --auto_approve              Auto approve the Terraform apply commands (only works when building, destory will auto-approve by default)
  -m, --modify                    Instead of creating a whole new deployment, modify an existing one with the same operation name
  -f, --force                     Force the build to go through, even if a deployment already exists with the opration name listed
  -q, --quiet                     Don't send Slack messages to configuration-defined webhook url upon infrastructurecreation
  -v, --verbose                   Verbose output from Terry (does not change what is logged in the log file)
  -l, --log_file TEXT             Location to write log file to
  -cR, --container_registry TEXT  Container registry to use for deploying
                                  containers (The URL for the registry)
  -cRU, --container_registry_username TEXT
                                  Username used to authenticate to the container registry (required if deploying containers)
  -cRP, --container_registry_password TEXT
                                  Password used to authenticate to the container registry (required if deploying containers)
  -awsAK, --aws_access_key_id TEXT
                                  AWS Access Key ID for AWS API
  -awsSAK, --aws_secret_access_key TEXT
                                  AWS Secret Access Key for AWS API
  -awsR, --aws_default_region TEXT
                                  AWS region
  -doT, --digital_ocean_token TEXT
                                  Token for Digital Ocean API
  -ncU, --namecheap_user_name TEXT
                                  Namecheap username for Namecheap API
  -ncA, --namecheap_api_user TEXT
                                  Namecheap API username for Namecheap API (Usually the same as username)
  -ncK, --namecheap_api_key TEXT  Namecheap API Key for Namecheap API
  -gdK, --godaddy_api_key TEXT    GoDaddy API Key for GoDaddy API
  -gdS, --godaddy_api_secret TEXT GoDaddy API Key Secret for GoDaddy API
  -csP, --cobaltstrike_password TEXT
                                  Password to use when connecting to teamserver
  -csMC2, --cobaltstrike_malleable_c2 PATH
                                  Path to malleable C2 profile to use when starting CobaltStrike
  -h, --stupid-terry, --help, --how-use, --freaking-help-plz
                                  Show this message and exit.

Commands:
  destroy  Destroy the infrastructure built by terraform
  server   Create a server resource
```

### Destroy Options

When destroying infrastructure, there are a few options that might help:

```
Usage: terry.py destroy [OPTIONS]

  Destroy the infrastructure built by terraform

Options:
  -r, --recursive                 Destroy all files and folders associated with the deployment as well
  -h, --how-use, --stupid-terry, --freaking-help-plz, --help
                                  Show this message and exit.
```

### Server Options

There are many options you can use when building a server, all the options are below:

```
Usage: terry.py server [OPTIONS]

  Create a server resource

Options:
  -p, --provider [aws|digitalocean|namecheap|godaddy]
                                  The cloud/infrastructure provider to use when creating the server  [required]
  -t, --type [bare|categorize|teamserver|lighthouse|redirector]
                                  The type of server to create  [required]
  -cT, --container TEXT           Containers to install onto the server
  -rT, --redirector_type TEXT     Type redirector to build, with optional domain specified for that redirector formatted as "<protocol>:<domain>:<registrar>"  (Example: https redirector at domain example.com with registrar aws should be "https:example.com:aws"
  -r2, --redirect_to TEXT         Domain to redirect to / impersonate (for categorization usually)
  -d, --domain TEXT               Domain and registrar to use in creation of an A record for the resource formatted as "<domain>:<registrar>" (Example: domain example.com with registrar aws should be "example.com:aws"
  -h, --freaking-help-plz, --stupid-terry, --how-use, --help
                                  Show this message and exit.
```

## Examples

Some example build commands can be found below and documentation on the specific types of servers is below

### Build a Categorization Server

To build a categorization server hosted on AWS with the registar being AWS, the command would be:

```bash
./terry.py -o categorization_server -c config.yml server -p aws -t categorize -r2 techelevator.com -d focusfireandsecuity.net:aws
```

### Build a Teamserver

To build a standalone teamserver hosted on DigitalOcean with CobaltStrike, but no redirectors, the command would be:

```bash
./terry.py -o standalone_teamserver -c config.yml server -p digitalocean -t teamserver -cT cobaltstrike
```

And if you wanted to build CobaltStrike with a HTTPS redirector, the command would be:

```
./terry.py -o standalone_teamserver -c config.yml server -p digitalocean -t teamserver -cT cobaltstrike -rT https:example.com:aws
```

## Expanding the Capabilities

Terry was intended to be built off of by modifying/adding. Before building ontop of Terry, there are some design paradigms that must be considered:

1. Variables/naming of files **must be consistent across the entire project**. 

2. Terraform **should not** do any host configuration. The purpose of Terraform is to build a specific resource using a provider (of which can be an ssh key, domain record, serverless function, server, etc). 

3. Terry can and should be able to read sensitive values from **either** the configuration file, command line arguments, environment variables, **or** from standard input, the choice of which to use should be up to the operator.

4. Since all cloud providers have similar offerings, resources **should be abstracted** from the provider. 
>For example, AWS has EC2 for creating virtual machines in the cloud, but at the core, it is just a server. Terry will expect that you call it a `server` and not a `ec2` when creating the resource file for that provider.

5. Each class that is instantiated should validate itself.
>For Example, a Terraform object should validate that it has a Terraform template to render

### Adding a Provider

Following the design paradigms above, to add a provider follow these steps:

1. Inside the [Terraform mappings file template folder](./configurations/terraform_mappings.yml) add the provider with the following format:

```yaml
<provider_name>:
  provider:
    source: <terraform_provider_source>
    version: <terraform_provider_version>
    default_arguments:
      - <1_required_credentials_to_authenticate>
      - <2_required_credentials_to_authenticate>
      - ...
```

**Note:** The `default_arguments` MUST have the same names as the envionment variables required to be set to authenticate with that provider as they get set as environment variables so that Ansible can access them at runtime

2. Find the provider documentation on the Terraform website and create the provider block needed for the specific provider.

3. In the newly created provider file and inside the provider block that was just created, add jinja variables that have t.

And that is all you need to add a new provider, but that is useless without resources, so let's walk through creating a new resource.

### Adding a Resource

Following the design paradigms above, to add a resource **after adding the provider block** follow these steps:

1. If a folder for the provider doesn't exist, create a folder for the provider using the same name as the `<provider>` as named in the terraform mappings file (lowercase and no spaces)

2. Inside that folder, create the resource type you want to add using the naming scheme `<resource_type>.tf.j2` where the resource type is abstracted away from the provider naming scheme (for example an AWS EC2 instance is just a server).

3. Using the variables that will be passed from the click context, add the jinja variables where needed.

And that is all, now you can use your new provider with Terry!

## Types of Servers Built

Terry can build all types of servers. At runtime, Terry will dynamically generate an Ansible inventory file which will then be used to populate the playbook varaibles. The stucture of the inventory is as follows:

```yaml
bare?:
  hosts?: {}
categorize:
  hosts?: {}
lighthouse?:
  hosts?: 
    1.1.1.1:
      ansible_user: <ssh_user>
      provider: <cloud_provider>
redirector?:
  hosts?: 
    1.1.1.1:
      ansible_user: <ssh_user>
      provider: <cloud_provider>
      http_redirector?: 
      dns_redirector?: 
teamserver?:
  hosts?:
    1.1.1.1:
      ansible_user: <ssh_user>
      provider: <cloud_provider>
```

**NOTE:**

A question mark after a varaible name in the example above denotes that it is **not** required.

Using the inventory structure above, all servers are configured using Ansible and assume the host has SSH available, is running Debian, and is internet connected. In order to configure a "base" server with all the "base" configuration needed for all the other scripts to run, you can run the command below:

```bash
ansible-playbook ./core/playbooks/prep-all-systems.yml -i ./path/to/inventory_file
```

Additional configuration is made to each of the specific types of servers. Below are all the different types of servers as well as the ansible playbooks used to configure each type.

### Categorization

Lorem

### Teamserver

Lorem

### Redirector

Since the redirectors are very commonly used tools that have been adapted to fit our needs, there is additional information that is needed when configuring and setting up a DNS redirector.

#### HTTP(S) Redirector

Lorem

#### DNS Redirector

Inside of the `setup-redirector.yml` file are variables that are used to tell the script what kind of redirectors to install. Once installed, the redirector will be installed as a service named `dns-redirector.service` and will be started automatically. In order to change the IP and port to redirect, change the `/opt/socat/dns-redirector.conf` file and then restart the `dns-redirector.service` service.

```bash
systemctl restart dns-redirector.service
```

## Deploying Containers

Each server deployed has the option to deploy an arbitrary number of containers to it. The containers that are available to be deployed are defined in the [container mappings file](./configurations/container_mappings.yml). This file is a valid `docker-compose.yml` file (please review Docker's documentation to learn more about Docker Compose), but with a few exceptions:

* The presence of with the following properties: `required_args`, `pre_run_commands`, and `post_run_commands`
* The use of "[[ <name> ]]" inside of the file

### `required_args`

These are arguments that must exist from **either** the configuration file, command line arguments, **or** environment variables. If they do not, Terry will ask you to input the value into standard input.

### `pre_run_commands` & `post_run_commands`

These are valid Ansible tasks that will run just before and just after spinning up the container. Some containers may require reading files from specific locations at runtime, so having these properties in the container mappings file allows the flexibility to run arbitrary Ansible tasks before and after starting a container.

### `[[ <name> ]]`

Becuase some of the containers require dynamic runtime arguments when started, there had to be a way to allow for Jinja templating inside of the docker compose. However, if we use Jinja tamplates for variables that don't exist when the template is loaded, Ansible will throw an error. To alleviate that, every valid Jija template has been replaced with quare brackets and then will be replaced with valid Jinja templates and loaded once they are required.


## Known Limitations / Issues

Lorem

## Known Quirks

* Loggin erros will NOT print the stack trace

There are known quirks to Terry. The main one bing that he uses `ufw` to manage the firewall. Since this is the case, `docker` and `ufw` do not get along well. To alleviate that, I used a bypass where there are rules set in the `/etc/ufw/after.rules` file to force `ufw` to manage the `docker` ports.

* When a container is in a state where we finish an operation, we can commit that image and push it to a registry

