from parse_config import config_to_dict
import re
from acl_class import Acl
from ace_class import ace_factory
import acl as acl_import


class Cisco_Config(object):
    def __init__(self, config):
        configuration = config_to_dict(config)
        self.extended_acls = []
        self.interfaces = configuration['interfaces']
        self.hostname = configuration['hostname']
        self.static_routes = configuration['static_routes']
        for acl_name, acl_value in configuration['extended_acls'].items():
            if re.search('-IN$', acl_name, flags=re.M):
                self.extended_acls.append(Acl(acl_name, acl_value, parent=self))

    def _find_ace_interfaces(self, acl_name):
        attached_interfaces = []
        for intface in self.interfaces:
            if re.search(acl_name, self.interfaces[intface], flags=re.M):
                attached_interfaces.append(intface)
        return attached_interfaces

    def _get_subnets(self, interface):
        ip_addresses = re.findall('ip address ((?:[\\d\\.]+) (?:[\\d\\.]+))', self.interfaces[interface])
        return ip_addresses

    def search_acls(self, text_ace, match_on):
        pass


if __name__ == '__main__':
    pass
