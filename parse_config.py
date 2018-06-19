# written by Allen Stevens
import re

data_structure = ['hostname', 'acls', 'interfaces', 'static_routes']

def _extract_acls(config) -> dict:
    acl_regex = r'^ip access-list (?:extended |standard )?(.*)\r?\n((?: .*\r?\n)+)'
    all_acls = re.findall(acl_regex, config, re.M)
    return dict(all_acls)

def _get_hostname(config) -> str:
    host_group = re.search('^hostname (.*)$', config, re.M)
    if isinstance(host_group, _sre.SRE_Match):
        return host_group.group(1)
    else:
        return None