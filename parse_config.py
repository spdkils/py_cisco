# written by Allen Stevens
import re

# Not sure if I should just check None
# SRE_MATCH = type(re.match('', ''))

types = {'ip_or_mask': '^((?:\\d{1,3}\\.){3}\\d{1,3})$',
         'interface': '^(?:Serial|(?:Fast|Gigabit)Ethernet|Vlan).+$',
         'integer': '^\\d+$'}

data_structure = ['hostname', 'acls', 'interfaces', 'static_routes']


def _get_hostname(config) -> str:
    host_group = re.search('^hostname (.*)$', config, re.M)
    if host_group is not None:
        return host_group.group(1)


def _extract_acls(config) -> dict:
    acl_regex = r'^ip access-list (?:extended |standard )?(.*)\r?\n((?: .*\r?\n)+)'
    all_acls = re.findall(acl_regex, config, re.M)
    return dict(all_acls)


def _extract_interfaces(config) -> dict:
    interface_regex = r'^interface (.+)\r?\n((?: .+\r?\n)*)'
    all_interfaces = re.findall(interface_regex, config, re.M)
    return dict(all_interfaces)


def _extract_static_routes(config) -> dict:
    static_routes = '^ip route (.*)$'
    return re.findall(static_routes, config, re.M)


def config_to_dict(config) -> dict:
    results = {}
    results['acls'] = _extract_acls(config)
    results['hostname'] = _get_hostname(config)
    results['interfaces'] = _extract_interfaces(config)
    results['static_routes'] = _extract_static_routes(config)
