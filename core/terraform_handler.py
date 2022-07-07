from json import JSONDecodeError
from pathlib import Path
from python_terraform import *

from core.binary_handler import BinaryHandler
from core.jinja_handler import JinjaHandler
from core.log_handler import LogHandler
from core.terry_classes import SSHKey, TerraformObject


class TerraformHandler:
    """
    A Class used for handling all interactions with Terraform.
    """

    def __init__(self, terraform_path, working_dir):
        self.terraform_binary = BinaryHandler('terraform', terraform_path)
        self.working_dir = Path(working_dir).joinpath('terraform')
        try:
            self.terraform = Terraform(working_dir=self.working_dir, terraform_bin_path=self.terraform_binary.path)
        except JSONDecodeError as e:
            message = 'Terraform Error: There was a JSON error with the Terraform Handler, there may be a lock file that cannot be read.'
            LogHandler.critical(message)

    @classmethod
    def build_plan(self, ctx_obj):
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
            
            
    def apply_plan(self, auto_approve=False):
        """Applies the Terraform plan.
        Takes the Click context object dictionary.
        Returns return_code, stdout, stderr, and terraform_plan string of executed Terraform functions.
        """

        # Check whether Terraform needs to be initialized
        if not self.working_dir.joinpath('terraform/.terraform.lock.hcl').exists():
            return_code, stdout, stderr = self.terraform.init()

        return_code, stdout, stderr = self.terraform.plan()
        terraform_plan = stdout

        # Terraform exit codes:
        # 0 = Succeed with empty diff (no changes)
        # 1 = Error
        # 2 = Succeeded with non-empty diff (changes present)

        # Handle the PLAN Return codes
        if return_code == 0:
            # Get the created resource details from the terraform show command
            return_code, stdout, stderr = self.terraform.show(json=IsFlagged)
            return return_code, stdout, stderr, terraform_plan
        elif return_code == 1:
            return return_code, stdout, stderr, None
        elif return_code == 2:  # Changes to be made
            # The `skip_plan` seems to be the option we need to send for auto_approve, which is a bug in the library
            return_code, stdout, stderr = self.terraform.apply(capture_output=False, skip_plan=auto_approve)
            # Handle the APPLY Return codes
            if return_code == 0:
                # Get the created resource details from the terraform show command
                return_code, stdout, stderr = self.terraform.show(json=IsFlagged)
                return return_code, stdout, stderr, terraform_plan
            elif return_code == 1:
                return return_code, stdout, stderr, terraform_plan
        
        # Non-reachable code
        return return_code, stdout, stderr, terraform_plan

    def destroy_plan(self):
        """Destroys the Terraform plan.
        Returns success (bool), stdout, stderr
        """

        # Check for an existing TF State
        if not self.working_dir.joinpath('terraform.tfstate').exists():
            return None, None, None
        
        return_code, stdout, stderr = self.terraform.destroy(force=IsNotFlagged, auto_approve=True)

        # Terraform exit codes:
        # 0 = Succeed with empty diff (no changes)
        # 1 = Error
        # 2 = Succeeded with non-empty diff (changes present)

        # Handle the DESTROY Return codes
        if return_code == 0:
            return True, stdout, stderr
        elif return_code == 1:
            return False, stdout, stderr
        elif return_code == 2:  # Changes to be made
            return True, stdout, stderr


    @classmethod
    def map_values(self, ctx_obj, json_data):
        """Map results from Terraform plan application back to class instances.
        Takes the click context object dictionary and JSONified terraform.show() results.
        Returns nothing (updates resource classes in place).
        """

        LogHandler.debug('Mapping Terraform state')

        # Sort both lists by name to ensure same order
        terraform_resources = sorted(json_data, key=lambda x: x['name']) 

        # Get the terraform mappings so we know what keys to search for
        terraform_mappings = TerraformObject.get_terraform_mappings()

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