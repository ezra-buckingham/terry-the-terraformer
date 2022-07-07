from shutil import which
from pathlib import Path

from core.log_handler import LogHandler


class BinaryHandler:
    """Class to represent binaries that may be required for Terry to run"""

    def __init__(self, name, path):
        self.name = name
        self.path = path

        # Check if a path was given in config and if it doesn't exist
        if self.path and Path(self.path).exists():
            LogHandler.debug(f'Found the "{self.name}" binary, from provided path')
        # If not, check to see if it is in the PATH
        elif which(self.name):
            self.path = Path(which(self.name))
        else:
            LogHandler.critical(f'Binary Error ({self.name}): unable to find "{self.name}" binary in your path or using path provided in the config file')

        # If we make it here, we were successfull in finding the binary
        LogHandler.debug(f'Succesfully found "{self.name}" binary')