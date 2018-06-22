from parse_config import config_to_dict
from acl_class import Acl
from ace_class import ace_factory
import acl as acl_import


class Cisco_Config(object):
    def __init__(self, config):
        configuration = config_to_dict(config)
        self.extended_acls = []
        for acl_name, acl_value in configuration['extended_acls'].items():
            self.extended_acls.append(Acl(acl_name, acl_value, parent=self))
        self.interfaces = configuration['interfaces']
        self.hostname = configuration['hostname']
        self.static_routes = configuration['static_routes']

    def search_acls(text_ace, match_on):
        pass


if __name__ == '__main__':
    pass
