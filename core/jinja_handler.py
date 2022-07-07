from jinja2 import meta, Template, FileSystemLoader, Environment

class JinjaHandler:
    """
    A class to help with building out the jinja templates
    """

    def __init__(self, search_path):
        self.template_loader = FileSystemLoader(searchpath=search_path)
        self.template_env = Environment(loader=self.template_loader)

    def get_template(self, template_path):
        """
        """
        template_path = str(template_path)
        template = self.template_env.get_template(template_path)
        return template
    
    def render_template(self, template, data, **kwargs):
        """
        """

        if isinstance(template, Template):
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
        variables = meta.find_undeclared_variables(parsed_content)
        return variables