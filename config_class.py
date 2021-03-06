from parse_config import config_to_dict
import re
from acl_class import Acl
from ace_class import ace_factory


class Cisco_Config(object):
    def __init__(self, config):
        configuration = config_to_dict(config)
        self.inbound_extended_acls = {}
        self.interfaces = configuration['interfaces']
        self.hostname = configuration['hostname']
        self.static_routes = configuration['static_routes']
        self._raw_extended_acls = configuration['extended_acls']
        for acl_name, acl_value in configuration['extended_acls'].items():
            if self._inbound_acl(acl_name):
                self.inbound_extended_acls[acl_name] = Acl(acl_name, acl_value, parent=self)

    def _inbound_acl(self, acl_name):
        for intface in self.interfaces:
            if 'ip access-group ' + acl_name + ' in' in self.interfaces[intface]:
                return True
        return False

    def _find_ace_interfaces(self, acl_name):
        attached_interfaces = set()
        attached = f'ip access-group {acl_name} '
        for intface in self.interfaces:
            if attached in self.interfaces[intface]:
                attached_interfaces.add(intface)
        return attached_interfaces

    def _get_subnets(self, interface):
        ip_addresses = re.findall('ip address ((?:[\\d\\.]+) (?:[\\d\\.]+))', self.interfaces[interface])
        return ip_addresses

    def search_acls(self, text_ace, match_on):
        pass


if __name__ == '__main__':
    pass
