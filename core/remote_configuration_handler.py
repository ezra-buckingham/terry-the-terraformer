
from dataclasses import dataclass
import json
from pathlib import Path
import uuid
import yaml

from core.log_handler import LogHandler
from core.shell_handler import ShellHandler
from core.binary_handler import BinaryHandler


@dataclass
class RemoteConfigurationHandler:
    """Class to represent a remote configuration that may can be loaded by Terry"""

    configuration_name: str 
    repository_url: str
    username: str
    personal_access_token: str
    # Default
    repo_uuid = uuid.uuid4()
    repo_folder_on_disk : Path = Path('/tmp')
    git_executable_path : str = ''
    configuration = dict()


    def __post_init__(self):
        base_message = f'Remote Configuration Error:'

        # Generate path to where we will clone the repo
        self.repo_folder_on_disk = self.repo_folder_on_disk.joinpath(str(self.repo_uuid))

        # Check if we have Git installed
        self.git_executable_path = BinaryHandler('git', self.git_executable_path)

        # TODO Check if we were given a valid git repo URL

        try:
            LogHandler.debug(f'Attempting to clone "{self.repository_url}" to "{self.repo_folder_on_disk}" using username "{self.username}"')
            self.__clone_repo()
            LogHandler.debug(f'Clone of "{self.repository_url}" successfully written to "{self.repo_folder_on_disk}"')
        except Exception as e:
            message = f'{base_message} There was an error cloning "{self.repository_url}" using provided credentials. Please make sure you have the right URL and credentials.'
            LogHandler.error(message) 

        # Now let's loop over what we got back from the remote
        try:
            LogHandler.debug(f'Attempting to parse the contents of "{self.repo_folder_on_disk}"')
            self.__parse_contents()
            LogHandler.debug(f'Parsing of "{self.repo_folder_on_disk}" was successful')
        except Exception as e:
            message = f'{base_message} There was an error parsing the contents of "{self.repository_url}". Please make sure the contents are actual configuration files.'
            LogHandler.error(message) 
            

    def __clone_repo(self):
        # Create the command
        command = f"git clone https://{self.username}:{self.personal_access_token}@{self.repository_url} {self.repo_folder_on_disk}"
        ShellHandler.run(command.split(' '), check=True)


    def __parse_contents(self):
        # Get all JSON files from the cloned repo
        LogHandler.debug(f'Pulling json and yaml files out of "{self.repo_folder_on_disk}"')
        json_files = list(self.repo_folder_on_disk.glob('**/*.json'))
        yml_files = list(self.repo_folder_on_disk.glob('**/*.yml'))
        yaml_files = list(self.repo_folder_on_disk.glob('**/*.yaml'))

        self.configuration = { self.configuration_name: {}}

        # Loop over the json_files, parse them and place them into the dict
        for file in [ *json_files, *yml_files, *yaml_files ]:
            LogHandler.debug(f'Parsing "{self.repo_folder_on_disk}{file}"')

            file_contents = file.read_text()

            if file.suffix == '.json':
                file_contents = json.loads(file_contents)

            elif file.suffix == '.yml' or file.suffix == '.yaml':
                file_contents = yaml.safe_load(file_contents)

            self.configuration[self.configuration_name][file.stem] = file_contents