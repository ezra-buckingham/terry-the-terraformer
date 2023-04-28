import jinja2
from os import getenv


class JinjaHandler:
    """
    A class to help with building out the jinja templates
    """

    def __init__(self, search_path):
        self.template_loader = jinja2.FileSystemLoader(searchpath=search_path)
        self.template_env = jinja2.Environment(loader=self.template_loader)
        
        self.template_env.filters.update({
            'is_list': self.__is_list,
            'env_lookup': self.__env_lookup,
            'split': self.__split
        })
        
    def __is_list(value):
        """Jinja filter to check if the variable is a list

        Args:
            value (any): Variable to check if an object

        Returns:
            bool: Is the variable a list
        """
        
        return isinstance(value, list)
    
    
    def __env_lookup(self, key):
        """Jinja filter to get an environment variable

        Args:
            key (str): Environment variable to get

        Returns:
            str | None: Value of environment variable (None if undefined)
        """
        return getenv(key, None)
    

    def __split(self, string: str, delimiter: str):
        """Split a string by a delimiter

        Args:
            string (str): The string to split
            delimiter (str): Delimiter to split by

        Returns:
            List: List containing the split string
        """
        
        return string.split(delimiter)
    

    def get_template(self, template_path):
        """Get the Jinja template

        Args:
            template_path (Path): The path to the jinja template

        Returns:
            Template: The jinja template
        """
        
        template_path = str(template_path)
        template = self.template_env.get_template(template_path)
        return template
    
    def render_template(self, template, data, **kwargs):
        """
        """

        if isinstance(template, jinja2.Template):
            return template.render(data, **kwargs)
        else:
            raise TypeError('Template provided not of type Template')
    
    def get_and_render_template(self, template_path, data, **kwargs):
        """
        """

        template = self.get_template(template_path)
        return self.render_template(template, data, **kwargs)

    def get_vars_from_template(self, template):
        """ Retrieve the list of variables in a Jinja template
        Takes in a template_path as a string or a template
        Returns a list of the varaibles
        """

        template_source = self.template_env.loader.get_source(self.template_env, template)
        parsed_content = self.template_env.parse(template_source)
        variables = jinja2.meta.find_undeclared_variables(parsed_content)
        return variables