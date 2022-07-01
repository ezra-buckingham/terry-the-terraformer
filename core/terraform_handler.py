from json import JSONDecodeError
from python_terraform import *
from dataclasses import dataclass
from hashlib import sha256
from shutil import which

from core.log_handler import LogHandler


class TerraformHandler:
    """
    A Class used for handling all interactions with Terraform.
    """

    def __init__(self, terraform_path, working_dir):
        self.terraform_path = terraform_path
        self.working_dir = working_dir.joinpath('terraform')
        if self.terraform_path:
            self.terraform = Terraform(working_dir=self.working_dir, terraform_bin_path=self.terraform_path)
        else:
            try:
                self.terraform = Terraform(working_dir=self.working_dir)
            except JSONDecodeError as e:
                message = 'There was a JSON error with the Terraform Handler, there may be a lock file that cannot be read.'
                LogHandler.error(message)
                print(message)
                exit(code=1)
            
            
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

