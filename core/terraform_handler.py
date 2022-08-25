from json import JSONDecodeError
from pathlib import Path
from python_terraform import *

from core.binary_handler import BinaryHandler
from core.log_handler import LogHandler


class TerraformHandler:
    """
    A Class used for handling all interactions with Terraform.
    """

    def __init__(self, terraform_path, working_dir):
        self.terraform_binary = BinaryHandler('terraform', terraform_path)
        self.working_dir = Path(working_dir).joinpath('terraform')
        try:
            self.terraform = Terraform(working_dir=str(self.working_dir.absolute()), terraform_bin_path=str(self.terraform_binary.path))
        except JSONDecodeError as e:
            message = 'Terraform Error: There was a JSON error with the Terraform Handler, there may be a lock file that cannot be read.'
            LogHandler.critical(message)
    

    def show_state(self, json=True):
        """"""

        LogHandler.info('Getting Terraform state')

        if json:
            return_code, stdout, stderr = self.terraform.show(json=IsFlagged)
        else:
            return_code, stdout, stderr = self.terraform.show()   
        return return_code, stdout, stderr

            
    def apply_plan(self, auto_approve=False):
        """Applies the Terraform plan.
        Takes the Click context object dictionary.
        Returns return_code, stdout, stderr, and terraform_plan string of executed Terraform functions.
        """

        LogHandler.info('Applying Terraform plan')

        # Check whether Terraform needs to be initialized
        if not self.working_dir.joinpath('terraform/.terraform.lock.hcl').exists():
            LogHandler.debug('Terraform not initialized, running "terraform init" now...')
            return_code, stdout, stderr = self.terraform.init()
            LogHandler.debug('Terraform successfully initialized!')

        LogHandler.debug('Terraform not planned, running "terraform plan" now...')
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
            LogHandler.critical(f'Terraform Plan returned an error: {stderr}')
        elif return_code == 2:  # Changes to be made
            # The `skip_plan` seems to be the option we need to send for auto_approve, which is a bug in the library
            return_code, stdout, stderr = self.terraform.apply(capture_output=False, skip_plan=auto_approve)
            # Handle the APPLY Return codes
            if return_code == 0:
                # Get the created resource details from the terraform show command
                LogHandler.debug('Terraform returned "0", thus Terraform may not have actually made any changes')
                return return_code, stdout, stderr, terraform_plan
            elif return_code == 1:
                base_message = 'Terraform returned an error:'
                if not terraform_plan:
                    LogHandler.critical(f'{base_message} {stderr}')
                LogHandler.critical(f'{base_message} No stderr was returned, this is likely a logic issue or partial error within the plan. (Example: if AWS, a bad AMI given the region)')
        else:
            return return_code, stdout, stderr, terraform_plan
        
        # Non-reachable code
        return return_code, stdout, stderr, terraform_plan

    def destroy_plan(self, auto_approve=False):
        """Destroys the Terraform plan.
        Returns success (bool), stdout, stderr
        """

        LogHandler.info('Destroying Terraform plan')

        # Check for an existing TF State
        if not self.working_dir.joinpath('terraform.tfstate').exists():
            return None, None, None
        
        return_code, stdout, stderr = self.terraform.destroy(force=IsNotFlagged, auto_approve=auto_approve, capture_output=False)

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

    def __handle_return(return_tuple):
        """Returns the

        Args:
            `return_tuple (tuple)`: _description_
        """
        
        return_code = return_tuple[0]
        stdout = return_tuple[1]
        stderr = return_tuple[2]
        
        if return_code == 0:
            return True, stdout, stderr
        elif return_code == 1:
            LogHandler.critical(f'Terraform returned an error: {stderr}')
            return False, stdout, stderr
        elif return_code == 2:  # Changes to be made
            return True, stdout, stderr
