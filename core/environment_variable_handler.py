from dataclasses import dataclass
from os import getenv, environ


@dataclass
class EnvironmentVariableHandler:
    """
    A class to help with changing environment variables
    """

    name: str
    __value: str = None

    def __post_init__(self):
        self.name = self.name.upper()

    def get(self):
        if not self.__value: 
            self.__value= getenv(self.name)
        return self.__value

    def set(self, value):
        self.__value = value
        environ[self.name] = value
        return self.__value