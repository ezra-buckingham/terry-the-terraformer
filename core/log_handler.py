import logging
import click


logger = logging.getLogger()
VERBOSE_LOGGING = True


class LogHandler:

    @classmethod
    def confirmation(self, message):
        """Prompts the user for confirmation

        Args:
            `message (str)`: Message / Question to ask user
        Returns:
            `result (bool)`: Result of the confirmation
        """

        result = click.confirm(f'[?] {message}')
        return result


    @classmethod
    def get_input(self, message):
        """Prompts the user for input

        Args:
            `message (str)`: Message / Prompt to ask user
        Returns:
            `result (str)`: Result from the user
        """

        result = click.prompt(f'[?] {message}')
        return result

    @classmethod
    def debug(self, message):
        """Logs an debug message to stdout and log file

        Args:
            `message (str)`: Message to log
        Returns:
            `None`
        """

        global VERBOSE_LOGGING

        logger.debug(message)
        if VERBOSE_LOGGING:
            click.secho(f'[*] {message}', fg='blue')

    @classmethod
    def info(self, message):
        """Logs an info message to stdout and log file

        Args:
            `message (str)`: Message to log
        Returns:
            `None`
        """

        logger.info(message)
        click.secho(f'[+] {message}', fg='green')


    @classmethod
    def warn(self, message):
        """Log a warn message to stdout and log file

        Args:
            `message (str)`: Message to log
        Returns:
            `None`
        """

        logger.warn(message)
        click.secho(f'[!] {message}', fg='yellow')


    @classmethod
    def error(self, message):
        """Log an error message to stdout and log file
        
        Args:
            `message (str)`: Message to log
            `is_fatal (bool)`: Is the error fatal enough to exit (Default is `True`)
        Returns:
            `None`
        """

        logger.error(message)
        click.secho(f'[x] {message}', fg='red')


    @classmethod
    def critical(self, message):
        """Log an error message to stdout and log file
        
        Args:
            `message (str)`: Message to log
            `is_fatal (bool)`: Is the error fatal enough to exit (Default is `True`)
        Returns:
            `None`
        """

        logger.critical(message)
        click.secho(f'[x] Fatal Error: {message}', fg='red', bold=True)
        exit(code=1)