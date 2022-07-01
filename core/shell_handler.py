import os
import subprocess


class ShellHandler:
    """Class for simplifying the way we call Shell functions"""

    @classmethod
    def run(self, command, working_directory=None):

        if isinstance(command, str):
            command = command.split(' ')

        cwd = os.getcwd()
        if working_directory:
            os.chdir(working_directory)

        # Run the command, catch the error so that we can still change directory, and then raise that error back up
        try:
            output = subprocess.run(command.split(' '), check=True)
        except subprocess.CalledProcessError as e:
            os.chdir(cwd)
            raise e

        # Change back the OG directory
        os.chdir(cwd)