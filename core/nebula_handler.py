import ipaddress
from pathlib import Path
from subprocess import CalledProcessError

from core.log_handler import LogHandler
from core.shell_handler import ShellHandler


class NebulaHandler:
    """
    A Class used for handling all interactions with Nebula.
    """

    def __init__(self, nebula_path, nebula_subnet, working_dir):
        self.nebula_path = nebula_path
        self.nebula_ca_binary = Path(self.nebula_path).joinpath('nebula-cert')
        self.working_dir = working_dir.joinpath('nebula')
        self.nebula_subnet = ipaddress.IPv4Network(nebula_subnet)
        self.__assigned_ips = set()

    def __get_new_ip(self):
        for address in self.nebula_subnet:
            # If any of the bits not set, don't use it
            if len([add for add in str(address).split('.') if add == '0']) > 0:
                self.__assigned_ips.add(address)
            # If the address not in assinged IP space, give it out
            if address not in self.__assigned_ips:
                self.__assigned_ips.add(address)
                return address
        
        raise ipaddress.AddressValueError('No more IP addresses available in the subnet')
        

    def generate_ca_certs(self):
        
        # Create the command and run it
        generate_command = f'{ str(self.nebula_ca_binary) } ca -name 5TAG3'

        LogHandler.info('Generating Nebula CA Root certificate and key')
        try:
            ShellHandler.run(generate_command, str(self.working_dir))
        except CalledProcessError as e:
            LogHandler.error('There was an error generating the Nebula CA Root:')
            LogHandler.error(f'Nebula Error: { e.stderr.decode("utf-8") }')
            raise e

        LogHandler.info('Generated Nebula CA Root certificate and key')

    def generate_client_cert(self, name):
        # Get a new IP from the range
        new_ip = self.__get_new_ip()
        new_ip_cidr = str(new_ip) + '/' + str(self.nebula_subnet.prefixlen)

        # Create the command and run it
        generate_command = f'{ str(self.nebula_ca_binary) } sign -name { name.replace(" ", "") } -ip { new_ip_cidr }'
        
        LogHandler.info(f'Generating Nebula client certificate and key for {name} at { new_ip_cidr }')
        try:
            ShellHandler.run(generate_command, str(self.working_dir))
        except CalledProcessError as e:
            LogHandler.error('There was an error generating the Nebula Client Certificate and Key:')
            LogHandler.error(f'Nebula Error: { e.stderr.decode("utf-8") }')
            raise e

        LogHandler.info(f'Generated Nebula client certificate and key for {name} at { new_ip_cidr }')

        return new_ip.exploded